################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the daemon-side per-client socket session.

'SocketSession' owns the per-client handle table backing the SOCKET_CALL
op: one real stack socket plus its data bridge per open handle. The
'socket' call creates a socketpair, builds the daemon-side socket, and
returns the client end as a passed file descriptor; subsequent
handle-keyed calls (bind / connect / setsockopt / getsockopt / shutdown /
close / getsockname / getpeername) drive the underlying socket.

A STREAM handle is a 'TcpSocket' over a SOCK_STREAM 'SocketBridge', its
bridge started once the connection is opened (the stack socket's 'recv'
has no session to read before then). A DGRAM handle is a 'UdpSocket' over
a SOCK_DGRAM 'DatagramBridge', started at creation (a datagram socket can
receive before any connect). When the client disconnects, 'close_all'
reaps every still-open socket — the daemon's analogue of a kernel closing
a process's fds on exit.

This module is daemon-side: it imports the real socket factory and the
bridges, so it stays pytcp-resident (see
docs/refactor/kernel_userspace_separation.md §2).

pytcp/ipc/ipc__socket_session.py

ver 3.0.8
"""

import socket
import threading
from typing import Any

from net_proto.lib.enums import EtherType, IpProto
from pytcp.ipc.ipc__dgram_bridge import DatagramBridge
from pytcp.ipc.ipc__enums import IpcMessageKind
from pytcp.ipc.ipc__message import IpcMessage
from pytcp.ipc.ipc__packet_bridge import PacketBridge
from pytcp.ipc.ipc__socket_bridge import SocketBridge
from pytcp.ipc.ipc__socket_rpc import (
    SocketRequest,
    decode_socket_request,
    encode_socket_error,
    encode_socket_ok,
)
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket import socket as pytcp_socket
from pytcp.runtime.socket.packet__socket import PacketSocket
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.runtime.socket.udp__socket import UdpSocket

# The socket methods a client may invoke over SOCKET_CALL.
_ALLOWED_METHODS: frozenset[str] = frozenset(
    {
        "socket",
        "bind",
        "connect",
        "listen",
        "accept",
        "setsockopt",
        "getsockopt",
        "shutdown",
        "close",
        "getsockname",
        "getpeername",
    },
)

# Poll interval for the blocking 'accept' loop so it can re-check the
# server stop event between waits for an inbound connection.
IPC__SESSION__ACCEPT_POLL__SEC: float = 0.2


class _DaemonSocket:
    """
    A daemon-side stack socket paired with its client data bridge.
    """

    def __init__(
        self,
        sock: TcpSocket | UdpSocket | RawSocket,
        bridge: SocketBridge | DatagramBridge,
        /,
    ) -> None:
        """
        Bind a daemon stack socket to its data bridge, leaving the bridge
        unstarted.
        """

        self._socket = sock
        self._bridge = bridge
        self._bridge_started = False

    @property
    def socket(self) -> TcpSocket | UdpSocket | RawSocket:
        """
        Get the underlying daemon-side stack socket.
        """

        return self._socket

    def start_bridge(self) -> None:
        """
        Start the data bridge once (idempotent). A STREAM bridge starts
        after connect (its RX pump needs a session to read from); a DGRAM
        bridge starts at creation.
        """

        if not self._bridge_started:
            self._bridge.start()
            self._bridge_started = True

    def close(self, *, abort: bool) -> None:
        """
        Stop the bridge and tear down the connection. A TCP connection
        closes abortively (RST) on a client-disconnect reap or gracefully
        (FIN) on an explicit close; a UDP socket just unregisters.
        """

        self._bridge.stop()
        if isinstance(self._socket, TcpSocket):
            if self._socket.tcp_session is not None:
                if abort:
                    self._socket.abort()
                else:
                    self._socket.close()
        else:
            self._socket.close()


class _DaemonPacketSocket:
    """
    A daemon-side AF_PACKET socket paired with its client packet bridge.
    """

    def __init__(self, packet_socket: PacketSocket, bridge: PacketBridge, /) -> None:
        """
        Bind a daemon AF_PACKET socket to its packet bridge, leaving the
        bridge unstarted.
        """

        self._socket = packet_socket
        self._bridge = bridge
        self._bridge_started = False

    @property
    def socket(self) -> PacketSocket:
        """
        Get the underlying daemon-side AF_PACKET socket.
        """

        return self._socket

    def start_bridge(self) -> None:
        """
        Start the packet bridge once (idempotent). An AF_PACKET socket
        captures from creation, so its bridge starts immediately.
        """

        if not self._bridge_started:
            self._bridge.start()
            self._bridge_started = True

    def close(self, *, abort: bool) -> None:
        """
        Stop the bridge and unregister the AF_PACKET socket's capture
        filter. 'abort' is accepted for a uniform reap interface and
        ignored — a link-layer socket has no connection to abort.
        """

        _ = abort
        self._bridge.stop()
        self._socket.close()


class SocketSession:
    """
    The per-client socket-handle table backing the SOCKET_CALL op.
    """

    def __init__(self, stop_event: threading.Event) -> None:
        """
        Start with an empty handle table. 'stop_event' lets the blocking
        'accept' loop bail out on server shutdown.
        """

        self._sockets: dict[int, _DaemonSocket | _DaemonPacketSocket] = {}
        self._next_handle = 0
        self._stop_event = stop_event

    def handle(self, request: IpcMessage, /) -> tuple[IpcMessage, socket.socket | None]:
        """
        Serve one SOCKET_CALL request, returning the response and — for
        the 'socket' call — the client-end socket to pass alongside it.

        Any failure is forwarded as a RESPONSE_ERROR carrying the
        exception's type name and message, which the client turns back
        into an 'IpcRemoteError' (the same boundary translation the
        control plane uses).
        """

        try:
            value, fd_socket = self._invoke(decode_socket_request(request.body))
        except Exception as error:
            return (
                IpcMessage(
                    kind=IpcMessageKind.RESPONSE_ERROR,
                    op=request.op,
                    req_id=request.req_id,
                    body=encode_socket_error(error_type=type(error).__name__, message=str(error)),
                ),
                None,
            )

        return (
            IpcMessage(
                kind=IpcMessageKind.RESPONSE_OK,
                op=request.op,
                req_id=request.req_id,
                body=encode_socket_ok(value),
            ),
            fd_socket,
        )

    def close_all(self) -> None:
        """
        Reap every still-open socket on client disconnect.
        """

        for daemon_socket in list(self._sockets.values()):
            try:
                daemon_socket.close(abort=True)
            except OSError:
                pass
        self._sockets.clear()

    def _invoke(self, request: SocketRequest, /) -> tuple[Any, socket.socket | None]:
        """
        Route an allowlisted socket method to the addressed handle.
        """

        if request.method not in _ALLOWED_METHODS:
            raise KeyError(f"Method {request.method!r} is not a permitted socket call.")

        if request.method == "socket":
            return self._open(
                family=request.args["family"],
                socket_type=request.args["type"],
                protocol=request.args.get("protocol"),
            )

        daemon_socket = self._sockets.get(request.handle) if request.handle is not None else None
        if daemon_socket is None:
            raise KeyError(f"Unknown socket handle {request.handle!r}.")

        if isinstance(daemon_socket, _DaemonPacketSocket):
            return self._invoke_packet(daemon_socket, request)

        sock = daemon_socket.socket

        match request.method:
            case "bind":
                sock.bind(request.args["address"])
                return None, None
            case "connect":
                sock.connect(request.args["address"])
                daemon_socket.start_bridge()
                return None, None
            case "listen":
                if not isinstance(sock, TcpSocket):
                    raise OSError("listen() is supported only on a stream socket.")
                sock.listen(backlog=request.args["backlog"])
                return None, None
            case "accept":
                if not isinstance(sock, TcpSocket):
                    raise OSError("accept() is supported only on a stream socket.")
                return self._accept(sock)
            case "setsockopt":
                sock.setsockopt(request.args["level"], request.args["optname"], request.args["value"])
                return None, None
            case "getsockopt":
                return sock.getsockopt(request.args["level"], request.args["optname"]), None
            case "shutdown":
                if not isinstance(sock, TcpSocket):
                    raise OSError("shutdown() is not supported on a datagram socket.")
                sock.shutdown(request.args["how"])
                return None, None
            case "getsockname":
                return sock.getsockname(), None
            case "getpeername":
                return sock.getpeername(), None
            case "close":
                self._sockets.pop(request.handle)  # type: ignore[arg-type]
                daemon_socket.close(abort=False)
                return None, None

        raise KeyError(f"Method {request.method!r} is not a permitted socket call.")

    def _invoke_packet(
        self,
        daemon_socket: _DaemonPacketSocket,
        request: SocketRequest,
        /,
    ) -> tuple[Any, socket.socket | None]:
        """
        Route an AF_PACKET socket's call. A link-layer socket addresses
        with a 'sockaddr_ll' and supports only 'bind' / 'close' as control
        methods; sendto / recvfrom ride the packet bridge.
        """

        match request.method:
            case "bind":
                daemon_socket.socket.bind(request.args["address"])
                return None, None
            case "close":
                self._sockets.pop(request.handle)  # type: ignore[arg-type]
                daemon_socket.close(abort=False)
                return None, None

        raise KeyError(f"Method {request.method!r} is not permitted on an AF_PACKET socket.")

    def _accept(self, listening: TcpSocket, /) -> tuple[dict[str, Any], socket.socket]:
        """
        Block (polling, so server shutdown interrupts) until an inbound
        connection completes its handshake, then build a data channel for
        the accepted child and return its handle and peer address with the
        client end to pass.
        """

        while not self._stop_event.is_set():
            try:
                child, peer = listening.accept(timeout=IPC__SESSION__ACCEPT_POLL__SEC)
            except TimeoutError:
                continue

            assert isinstance(child, TcpSocket)
            data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            child_socket = _DaemonSocket(child, SocketBridge(child, data_end))
            child_socket.start_bridge()

            handle = self._next_handle
            self._next_handle += 1
            self._sockets[handle] = child_socket
            return {"handle": handle, "peer": peer}, client_end

        raise OSError("accept() interrupted by daemon shutdown.")

    def _open(
        self,
        *,
        family: AddressFamily,
        socket_type: SocketType,
        protocol: IpProto | EtherType | int | None,
    ) -> tuple[dict[str, int], socket.socket]:
        """
        Create a daemon-side socket of the requested type plus its data
        socketpair, assign a handle, and return the handle with the
        client end to pass.
        """

        match socket_type:
            case SocketType.STREAM:
                return self._open_stream(family=family)
            case SocketType.DGRAM:
                return self._open_dgram(family=family)
            case SocketType.RAW:
                if family is AddressFamily.PACKET:
                    if isinstance(protocol, IpProto):
                        raise ValueError("An AF_PACKET socket takes an ethertype, not an IpProto.")
                    return self._open_packet(protocol=protocol)
                if not isinstance(protocol, IpProto):
                    raise ValueError("A raw IP socket requires an IpProto next-header protocol.")
                return self._open_raw(family=family, protocol=protocol)

        raise ValueError(f"Unsupported socket type {socket_type!r}.")

    def _open_stream(self, *, family: AddressFamily) -> tuple[dict[str, int], socket.socket]:
        """
        Create a daemon TCP socket over a SOCK_STREAM data bridge (started
        later, at connect).
        """

        tcp_socket = pytcp_socket(family=family, type=SocketType.STREAM)
        assert isinstance(tcp_socket, TcpSocket)

        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        return self._register(_DaemonSocket(tcp_socket, SocketBridge(tcp_socket, data_end)), client_end)

    def _open_dgram(self, *, family: AddressFamily) -> tuple[dict[str, int], socket.socket]:
        """
        Create a daemon UDP socket over a SOCK_DGRAM data bridge, started
        immediately (a datagram socket can receive before any connect).
        """

        udp_socket = pytcp_socket(family=family, type=SocketType.DGRAM)
        assert isinstance(udp_socket, UdpSocket)

        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        daemon_socket = _DaemonSocket(udp_socket, DatagramBridge(udp_socket, data_end))
        daemon_socket.start_bridge()
        return self._register(daemon_socket, client_end)

    def _open_raw(self, *, family: AddressFamily, protocol: IpProto) -> tuple[dict[str, int], socket.socket]:
        """
        Create a daemon raw IP socket (over a SOCK_DGRAM data bridge,
        started immediately) for the given IANA next-header protocol.
        """

        raw_socket = pytcp_socket(family=family, type=SocketType.RAW, protocol=protocol)
        assert isinstance(raw_socket, RawSocket)

        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        daemon_socket = _DaemonSocket(raw_socket, DatagramBridge(raw_socket, data_end))
        daemon_socket.start_bridge()
        return self._register(daemon_socket, client_end)

    def _open_packet(self, *, protocol: EtherType | int | None) -> tuple[dict[str, int], socket.socket]:
        """
        Create a daemon AF_PACKET socket over a SOCK_DGRAM packet bridge,
        started immediately (a link-layer socket captures from creation).
        The 'protocol' is the ethertype capture filter (None = capture
        all).
        """

        packet_socket = pytcp_socket(family=AddressFamily.PACKET, type=SocketType.RAW, protocol=protocol)
        assert isinstance(packet_socket, PacketSocket)

        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        daemon_socket = _DaemonPacketSocket(packet_socket, PacketBridge(packet_socket, data_end))
        daemon_socket.start_bridge()
        return self._register(daemon_socket, client_end)

    def _register(
        self,
        daemon_socket: _DaemonSocket | _DaemonPacketSocket,
        client_end: socket.socket,
        /,
    ) -> tuple[dict[str, int], socket.socket]:
        """
        Assign the next handle to a daemon socket and return the handle
        with the client end to pass.
        """

        handle = self._next_handle
        self._next_handle += 1
        self._sockets[handle] = daemon_socket
        return {"handle": handle}, client_end
