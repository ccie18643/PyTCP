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
This module contains the client-side TCP socket shim.

'ClientTcpSocket' mirrors the BSD-style 'TcpSocket' surface across the
process boundary. Its data path is a real kernel descriptor — the
client end of the daemon's socketpair, passed at open time — so 'send' /
'recv' are ordinary socket I/O and 'fileno()' is selectable with
select / poll / epoll. Its control methods (bind / connect / setsockopt /
getsockopt / shutdown / getsockname / getpeername / close) marshal over
the SOCKET_CALL op keyed by the daemon-assigned handle.

pytcp/client/client__tcp_socket.py

ver 3.0.10
"""

import errno
import os
from typing import Self

from net_proto.lib.enums import IpProto
from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__socket_rpc import (
    accept_socket,
    accept_take_socket,
    listen_socket,
    open_socket,
    socket_call,
)
from pytcp.ipc.ipc__stdlib_socket import stdlib_socket
from pytcp.runtime.socket import SO_RCVBUF, SOL_SOCKET, AddressFamily, SocketType

# Default accept-queue depth when 'listen' is called without an explicit
# backlog (mirrors the daemon-side 'TCP__DEFAULT_BACKLOG').
IPC__CLIENT_TCP__DEFAULT_BACKLOG: int = 16

# Non-blocking connect priming (A3.3): shrink the data channel's send
# buffer and fill it so the client fd reads not-writable until the daemon
# drains the filler on handshake resolution — the manufactured backpressure
# behind the BSD writable-on-connect edge.
IPC__CLIENT_CONNECT__PRIME_SNDBUF: int = 4096
IPC__CLIENT_CONNECT__PRIME_CHUNK: bytes = bytes(4096)


class ClientTcpSocket:
    """
    A client-side TCP socket backed by a daemon socket over IPC.
    """

    def __init__(self, client: IpcClient, /, *, family: AddressFamily = AddressFamily.INET4) -> None:
        """
        Open a daemon-side TCP socket and adopt its passed data-channel
        descriptor as this socket's real, selectable fd.
        """

        self._client = client
        handle, data_fd = open_socket(client, family=family, type_=SocketType.STREAM)
        self._handle = handle
        self._data_socket = stdlib_socket.socket(stdlib_socket.AF_UNIX, stdlib_socket.SOCK_STREAM, fileno=data_fd)
        # Accept-readiness fd (A3.4): the listener's eventfd, received at
        # listen(); None until then. select / poll / epoll on a listener
        # poll this for a queued child, not the (data-less) data channel.
        self._accept_fd: int | None = None

    def fileno(self) -> int:
        """
        Return the descriptor selectable with select / poll / epoll: the
        accept-readiness eventfd for a listener, otherwise the data
        channel.
        """

        return self._accept_fd if self._accept_fd is not None else self._data_socket.fileno()

    def settimeout(self, timeout: float | None, /) -> None:
        """
        Set the data-channel timeout (seconds, or None for blocking).
        Acts on the local descriptor only — no daemon round trip.
        """

        self._data_socket.settimeout(timeout)

    def setblocking(self, flag: bool, /) -> None:
        """
        Set the data channel blocking or non-blocking. Acts on the local
        descriptor only — no daemon round trip.
        """

        self._data_socket.setblocking(flag)

    def send(self, data: bytes) -> int:
        """
        Send 'data' to the connected peer over the data channel.
        """

        return self._data_socket.send(data)

    def recv(self, bufsize: int) -> bytes:
        """
        Receive up to 'bufsize' bytes from the connected peer over the
        data channel (b"" once the peer has closed and the stream drains).
        """

        return self._data_socket.recv(bufsize)

    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the daemon socket to a local address.
        """

        socket_call(self._client, method="bind", handle=self._handle, args={"address": address})

    def connect(self, address: tuple[str, int]) -> None:
        """
        Connect the daemon socket to a remote address.
        """

        socket_call(self._client, method="connect", handle=self._handle, args={"address": address})

    def connect_start(self, address: tuple[str, int]) -> None:
        """
        Begin a non-blocking connect: prime the send buffer to manufacture
        not-writable backpressure, then kick off the daemon-side async
        handshake, which drains exactly the primed bytes on resolution to
        flip this fd writable.
        """

        filler_len = self._prime_send_buffer()
        socket_call(
            self._client,
            method="connect_start",
            handle=self._handle,
            args={"address": address, "filler_len": filler_len},
        )

    def _prime_send_buffer(self) -> int:
        """
        Shrink the data channel's send buffer and fill it to EAGAIN so the
        client fd reads not-writable, returning the exact filler byte count
        the daemon worker must drain to release the writable edge.
        """

        self._data_socket.setsockopt(
            stdlib_socket.SOL_SOCKET,
            stdlib_socket.SO_SNDBUF,
            IPC__CLIENT_CONNECT__PRIME_SNDBUF,
        )
        prior_timeout = self._data_socket.gettimeout()
        self._data_socket.setblocking(False)
        written = 0
        try:
            while True:
                written += self._data_socket.send(IPC__CLIENT_CONNECT__PRIME_CHUNK)
        except BlockingIOError:
            pass
        finally:
            self._data_socket.settimeout(prior_timeout)
        return written

    def listen(self, *, backlog: int = IPC__CLIENT_TCP__DEFAULT_BACKLOG) -> None:
        """
        Mark the daemon socket as a passive listener with an accept queue
        bounded by 'backlog', adopting the accept-readiness eventfd the
        daemon passes back so select / poll can wait for a queued child.
        """

        self._accept_fd = listen_socket(self._client, handle=self._handle, backlog=backlog)

    def accept_nonblocking(self) -> tuple[Self, tuple[str, int]]:
        """
        Take one queued child without blocking, returning a new
        'ClientTcpSocket' and the peer's '(host, port)' address, or raise
        'BlockingIOError(EAGAIN)' when the accept queue is empty (A3.4).
        """

        self._require_listening()
        child_handle, peer, data_fd = accept_take_socket(self._client, handle=self._handle)
        return self._adopt(self._client, child_handle, data_fd), peer

    def accept(self) -> tuple[Self, tuple[str, int]]:
        """
        Block until an inbound connection completes, returning a new
        'ClientTcpSocket' for the accepted connection (its data path is
        the passed descriptor) and the peer's '(host, port)' address.
        """

        self._require_listening()
        child_handle, peer, data_fd = accept_socket(self._client, handle=self._handle)
        return self._adopt(self._client, child_handle, data_fd), peer

    def _require_listening(self) -> None:
        """
        Raise 'OSError(EINVAL)' when 'accept()' is called on a socket that
        was never placed into the LISTEN state (no 'listen()' call, so no
        accept-readiness fd) — matching the stdlib / BSD 'accept(2)'
        contract, which rejects a non-listening socket rather than
        blocking or returning a spurious child.
        """

        if self._accept_fd is None:
            raise OSError(errno.EINVAL, os.strerror(errno.EINVAL))

    @classmethod
    def _adopt(cls, client: IpcClient, handle: int, data_fd: int, /) -> Self:
        """
        Build a shim around an already-opened daemon socket handle and its
        passed data-channel descriptor (an accepted child connection),
        bypassing the open-a-new-socket constructor.
        """

        instance = cls.__new__(cls)
        instance._client = client
        instance._handle = handle
        instance._data_socket = stdlib_socket.socket(stdlib_socket.AF_UNIX, stdlib_socket.SOCK_STREAM, fileno=data_fd)
        instance._accept_fd = None
        return instance

    def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        Set a socket option on the daemon stdlib_socket.
        """

        if isinstance(level, int) and level == SOL_SOCKET and optname == SO_RCVBUF and isinstance(value, int):
            # SO_RCVBUF is honoured on the real receive buffer — the
            # client's socketpair end is the effective client-side stream
            # buffer — rather than only stored on the daemon. The
            # socketpair is a real kernel socket, so the kernel doubling /
            # clamps match stdlib exactly.
            self._data_socket.setsockopt(stdlib_socket.SOL_SOCKET, stdlib_socket.SO_RCVBUF, value)
            return

        socket_call(
            self._client,
            method="setsockopt",
            handle=self._handle,
            args={"level": level, "optname": optname, "value": value},
        )

    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        Get a socket option from the daemon stdlib_socket.
        """

        if isinstance(level, int) and level == SOL_SOCKET and optname == SO_RCVBUF:
            # Report the real socketpair buffer size (kernel-adjusted),
            # matching what 'setsockopt(SO_RCVBUF)' applied above.
            return self._data_socket.getsockopt(stdlib_socket.SOL_SOCKET, stdlib_socket.SO_RCVBUF)

        result: int | bytes = socket_call(
            self._client,
            method="getsockopt",
            handle=self._handle,
            args={"level": level, "optname": optname},
        )
        return result

    def shutdown(self, how: int, /) -> None:
        """
        Shut down one or both halves of the daemon connection.
        """

        socket_call(self._client, method="shutdown", handle=self._handle, args={"how": how})

    def getsockname(self) -> tuple[str, int]:
        """
        Get the daemon socket's local address and port.
        """

        result: tuple[str, int] = socket_call(self._client, method="getsockname", handle=self._handle, args={})
        return result

    def getpeername(self) -> tuple[str, int]:
        """
        Get the daemon socket's remote address and port.
        """

        result: tuple[str, int] = socket_call(self._client, method="getpeername", handle=self._handle, args={})
        return result

    def detach(self) -> int:
        """
        Detach and return the data-channel descriptor.

        The caller takes ownership of the descriptor; the shim's data
        socket no longer holds it. The daemon handle is left in place (to
        be reaped when the client disconnects), so the descriptor stays
        connected to the daemon-side stdlib_socket.
        """

        return self._data_socket.detach()

    def close(self) -> None:
        """
        Close the daemon socket and the local data-channel descriptor.
        """

        try:
            socket_call(self._client, method="close", handle=self._handle, args={})
        finally:
            self._data_socket.close()
            if self._accept_fd is not None:
                try:
                    os.close(self._accept_fd)
                except OSError:
                    pass
                self._accept_fd = None
