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

ver 3.0.9
"""

import errno
import os
import socket
import threading
from typing import Any

from net_proto.lib.enums import EtherType, IpProto
from pytcp.ipc.ipc__dgram_bridge import DatagramBridge
from pytcp.ipc.ipc__enums import IpcMessageKind
from pytcp.ipc.ipc__message import IpcMessage
from pytcp.ipc.ipc__packet_bridge import PacketBridge
from pytcp.ipc.ipc__socket_bridge import (
    IPC__BRIDGE__JOIN_TIMEOUT__SEC,
    SocketBridge,
)
from pytcp.ipc.ipc__socket_rpc import (
    SocketRequest,
    decode_socket_request,
    encode_exception,
    encode_socket_ok,
)
from pytcp.runtime.socket import (
    SO_ERROR,
    SOL_SOCKET,
    AddressFamily,
    SocketType,
)
from pytcp.runtime.socket import socket as pytcp_socket
from pytcp.runtime.socket.packet__socket import PacketSocket
from pytcp.runtime.socket.ping__socket import PingSocket
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.runtime.socket.udp__socket import UdpSocket

# The socket methods a client may invoke over SOCKET_CALL.
_ALLOWED_METHODS: frozenset[str] = frozenset(
    {
        "socket",
        "bind",
        "connect",
        "connect_start",
        "listen",
        "accept",
        "accept_take",
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
        sock: TcpSocket | UdpSocket | RawSocket | PingSocket,
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
        # Non-blocking connect (A3.3): the pending read-and-clear SO_ERROR
        # the worker publishes once the async handshake resolves, plus the
        # worker thread itself.
        self._so_error: int | None = None
        self._connect_thread: threading.Thread | None = None

    @property
    def socket(self) -> TcpSocket | UdpSocket | RawSocket | PingSocket:
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

    def start_connect_async(self, address: tuple[str, int], filler_len: int, /) -> None:
        """
        Run a non-blocking connect on a background worker so the dispatch
        thread returns at once (A3.3). The worker drives the blocking
        handshake, publishes the resulting SO_ERROR, and — on success —
        starts the data bridge.
        """

        self._connect_thread = threading.Thread(
            target=self._run_connect,
            args=(address, filler_len),
            name="IPC-Connect",
            daemon=True,
        )
        self._connect_thread.start()

    def _run_connect(self, address: tuple[str, int], filler_len: int, /) -> None:
        """
        Worker body: drive the blocking handshake, capture its errno
        (0 on success), drain the client's priming filler so its fd flips
        writable on both success and failure, then start the bridge when
        the connection established.
        """

        # The non-blocking connect path is stream-only (the session gates
        # 'connect_start' to a TcpSocket), so the bridge is always a
        # SocketBridge with the priming-drain affordance.
        assert isinstance(self._bridge, SocketBridge)

        try:
            self._socket.connect(address)
            so_error = 0
        except OSError as error:
            so_error = error.errno if error.errno is not None else errno.ECONNREFUSED

        # Publish the result before flipping the client fd writable so a
        # select-writable-then-read sequence observes the final SO_ERROR.
        self._so_error = so_error
        self._bridge.prime_drain(filler_len)
        if so_error == 0:
            self.start_bridge()

    def take_so_error(self) -> int:
        """
        Return and clear the pending non-blocking-connect SO_ERROR,
        defaulting to 0 (no error) — the BSD read-once SO_ERROR semantics.
        """

        so_error, self._so_error = self._so_error, None
        return so_error if so_error is not None else 0

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

        # Reap a non-blocking connect worker — aborting / closing the stack
        # socket above cancels any in-flight handshake, so the worker
        # unblocks and exits promptly.
        if self._connect_thread is not None:
            self._connect_thread.join(timeout=IPC__BRIDGE__JOIN_TIMEOUT__SEC)


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

    def handle(self, request: IpcMessage, /) -> tuple[IpcMessage, socket.socket | int | None]:
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
        # Socket-RPC boundary: translate ANY handler failure into a
        # structured RESPONSE_ERROR for the client (faithful error
        # forwarding, not silent swallowing).
        except Exception as error:  # pylint: disable=broad-exception-caught
            return (
                IpcMessage(
                    kind=IpcMessageKind.RESPONSE_ERROR,
                    op=request.op,
                    req_id=request.req_id,
                    body=encode_exception(error),
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

    def _invoke(self, request: SocketRequest, /) -> tuple[Any, socket.socket | int | None]:
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
            # An unknown handle is the daemon-side analogue of operating on
            # a closed descriptor; surface it as the stdlib's EBADF so the
            # reconstructed client error is OSError(EBADF), not KeyError.
            raise OSError(errno.EBADF, "Bad file descriptor")

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
            case "connect_start":
                if not isinstance(sock, TcpSocket):
                    raise OSError("connect_start() is supported only on a stream socket.")
                daemon_socket.start_connect_async(request.args["address"], request.args["filler_len"])
                return None, None
            case "listen":
                if not isinstance(sock, TcpSocket):
                    raise OSError("listen() is supported only on a stream socket.")
                sock.listen(backlog=request.args["backlog"])
                # Pass the listener's accept-readiness eventfd (A3.4) so the
                # client can select for a queued child. A dup'd eventfd
                # shares the kernel counter, so the daemon's accept-side
                # drain reflects on the client's fd with no watcher thread.
                return None, os.dup(sock.fileno())
            case "accept":
                if not isinstance(sock, TcpSocket):
                    raise OSError("accept() is supported only on a stream socket.")
                return self._accept(sock)
            case "accept_take":
                if not isinstance(sock, TcpSocket):
                    raise OSError("accept_take() is supported only on a stream socket.")
                return self._accept_take(sock)
            case "setsockopt":
                sock.setsockopt(request.args["level"], request.args["optname"], request.args["value"])
                return None, None
            case "getsockopt":
                level = request.args["level"]
                optname = request.args["optname"]
                # The non-blocking-connect SO_ERROR edge is owned by the
                # daemon socket, not the stack socket: return-and-clear the
                # worker-published handshake result (0 when none pending).
                if level == SOL_SOCKET and optname == SO_ERROR:
                    return daemon_socket.take_so_error(), None
                return sock.getsockopt(level, optname), None
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
    ) -> tuple[Any, socket.socket | int | None]:
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
            return self._build_accepted_child(child, peer)

        raise OSError("accept() interrupted by daemon shutdown.")

    def _accept_take(self, listening: TcpSocket, /) -> tuple[dict[str, Any], socket.socket]:
        """
        Non-blocking accept (A3.4): take one queued child without blocking
        the dispatch thread, or raise 'BlockingIOError(EAGAIN)' when the
        accept queue is empty. The client gates this on the listener's
        select-readable accept-readiness fd; the take itself drains that
        eventfd when it removes the last queued child.
        """

        try:
            child, peer = listening.accept(timeout=0)
        except TimeoutError as error:
            raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN)) from error
        return self._build_accepted_child(child, peer)

    def _build_accepted_child(
        self,
        child: pytcp_socket,
        peer: tuple[str, int],
        /,
    ) -> tuple[dict[str, Any], socket.socket]:
        """
        Wrap an accepted child stack socket in a started data bridge,
        register its handle, and return the handle and peer address with
        the client end to pass.
        """

        assert isinstance(child, TcpSocket)
        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        child_socket = _DaemonSocket(child, SocketBridge(child, data_end))
        child_socket.start_bridge()

        handle = self._next_handle
        self._next_handle += 1
        self._sockets[handle] = child_socket
        return {"handle": handle, "peer": peer}, client_end

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
                if protocol in (IpProto.ICMP4, IpProto.ICMP6):
                    assert isinstance(protocol, IpProto)
                    return self._open_ping(family=family, protocol=protocol)
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

    def _open_ping(self, *, family: AddressFamily, protocol: IpProto) -> tuple[dict[str, int], socket.socket]:
        """
        Create a daemon ICMP Echo ('ping') datagram socket (over a
        SOCK_DGRAM data bridge, started immediately) — Linux 'SOCK_DGRAM'
        + 'IPPROTO_ICMP' / 'IPPROTO_ICMPV6'.
        """

        ping_socket = PingSocket(family, SocketType.DGRAM, protocol)

        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        daemon_socket = _DaemonSocket(ping_socket, DatagramBridge(ping_socket, data_end))
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
