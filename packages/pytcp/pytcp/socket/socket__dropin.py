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
This module contains the daemon-backed stdlib-socket drop-in.

'socket()' is a stdlib-shaped factory: it opens a socket on the running
PyTCP daemon (a process-wide lazy 'ClientStack' connection resolved from
'$PYTCP_DAEMON_SOCKET') and returns a 'Socket' wrapper whose data path is
a real, selectable descriptor. 'Socket' presents the Berkeley-sockets
method surface, delegating data/control calls to the underlying client
shim and adding the stdlib conveniences the shims do not carry
('sendall', 'recv_into', 'gettimeout', 'getblocking', the context-manager
protocol, the 'family'/'type'/'proto' properties). It backs the
'pytcp.socket' package, which re-exports it together with the stdlib
constant / error / helper surface so 'import pytcp.socket as socket' is a
one-line stand-in for stdlib 'socket'. This increment covers SOCK_STREAM
and SOCK_DGRAM; non-blocking-readiness, RAW/AF_PACKET, and 'makefile' /
'dup' land in later increments.

'pytcp.client' is imported lazily (and under TYPE_CHECKING for
annotations) because 'pytcp.socket' is re-exported from the top-level
'pytcp' package: an eager client import would pull the ipc -> neighbor ->
stack chain at 'import pytcp' time and hit a genuine circular import
(see docs/refactor/daemon_socket_library_and_cli.md). The client is only
needed once a socket is actually opened, by which point the stack is
fully initialised.

pytcp/socket/socket__dropin.py

ver 3.0.8
"""

import builtins
import errno
import os
import threading
from types import TracebackType
from typing import TYPE_CHECKING, Self, cast, override

from net_proto.lib.enums import IpProto
from pytcp.runtime.socket import AddressFamily, SocketType

if TYPE_CHECKING:
    from pytcp.client import ClientStack, ClientTcpSocket, ClientUdpSocket

# stdlib-socket exception aliases.
error = OSError
timeout = TimeoutError
has_ipv6: bool = True

_default_stack_lock: threading.Lock = threading.Lock()
_default_stack: ClientStack | None = None


def _get_default_stack() -> ClientStack:
    """
    Return the process-wide daemon connection, opening it on first use.

    The daemon socket path comes from '$PYTCP_DAEMON_SOCKET', falling back
    to the daemon's default path.
    """

    global _default_stack

    with _default_stack_lock:
        if _default_stack is None:
            # Lazy import to avoid the import-pytcp-time circular import
            # described in the module docstring.
            from pytcp.client import connect
            from pytcp.daemon.daemon import default_socket_path

            socket_path = os.environ.get("PYTCP_DAEMON_SOCKET") or default_socket_path()
            _default_stack = connect(socket_path=socket_path)
        return _default_stack


def _reset_default_stack() -> None:
    """
    Close and drop the process-wide daemon connection (test affordance).
    """

    global _default_stack

    with _default_stack_lock:
        if _default_stack is not None:
            _default_stack.close()
            _default_stack = None


class Socket:
    """
    A stdlib-shaped socket backed by a PyTCP daemon socket handle.
    """

    def __init__(
        self,
        underlying: ClientTcpSocket | ClientUdpSocket,
        /,
        *,
        family: AddressFamily,
        type: SocketType,
        proto: int,
    ) -> None:
        """
        Wrap a daemon-backed client socket shim.
        """

        self._sock = underlying
        self._family = family
        self._type = type
        self._proto = proto
        self._timeout: float | None = None

    @property
    def family(self) -> AddressFamily:
        """
        Get the socket's address family.
        """

        return self._family

    @property
    def type(self) -> SocketType:
        """
        Get the socket's type.
        """

        return self._type

    @property
    def proto(self) -> int:
        """
        Get the socket's protocol number.
        """

        return self._proto

    def fileno(self) -> int:
        """
        Get the underlying data-channel file descriptor.
        """

        return self._sock.fileno()

    def settimeout(self, value: float | None, /) -> None:
        """
        Set the socket timeout (None blocking, 0 non-blocking, >0 timed).
        """

        self._timeout = value
        self._sock.settimeout(value)

    def gettimeout(self) -> float | None:
        """
        Get the socket timeout.
        """

        return self._timeout

    def setblocking(self, flag: bool, /) -> None:
        """
        Set blocking mode (equivalent to settimeout(None / 0.0)).
        """

        self._timeout = None if flag else 0.0
        self._sock.setblocking(flag)

    def getblocking(self) -> bool:
        """
        Get whether the socket is in blocking mode.
        """

        return self._timeout != 0.0

    def bind(self, address: tuple[str, int], /) -> None:
        """
        Bind the socket to a local address.
        """

        self._sock.bind(address)

    def connect(self, address: tuple[str, int], /) -> None:
        """
        Connect the socket to a remote address.
        """

        self._sock.connect(address)

    def listen(self, backlog: int = 128, /) -> None:
        """
        Mark a stream socket as accepting connections.
        """

        if self._type is not SocketType.STREAM:
            raise OSError(errno.EOPNOTSUPP, "listen() is only supported on a stream socket.")
        cast("ClientTcpSocket", self._sock).listen(backlog=backlog)

    def accept(self) -> tuple["Socket", tuple[str, int]]:
        """
        Accept a connection, returning a new Socket and the peer address.
        """

        if self._type is not SocketType.STREAM:
            raise OSError(errno.EOPNOTSUPP, "accept() is only supported on a stream socket.")
        child, peer = cast("ClientTcpSocket", self._sock).accept()
        return Socket(child, family=self._family, type=self._type, proto=self._proto), peer

    def send(self, data: bytes, /) -> int:
        """
        Send some of 'data', returning the number of bytes sent.
        """

        return self._sock.send(data)

    def sendall(self, data: bytes, /) -> None:
        """
        Send all of 'data', looping until every byte is accepted.
        """

        view = memoryview(data)
        while view:
            view = view[self._sock.send(bytes(view)) :]

    def sendto(self, data: bytes, address: tuple[str, int], /) -> int:
        """
        Send a datagram to 'address', returning the number of bytes sent.
        """

        if self._type is not SocketType.DGRAM:
            raise OSError(errno.EOPNOTSUPP, "sendto() is only supported on a datagram socket.")
        return cast("ClientUdpSocket", self._sock).sendto(data, address)

    def recv(self, bufsize: int, /) -> bytes:
        """
        Receive up to 'bufsize' bytes.
        """

        return self._sock.recv(bufsize)

    def recv_into(self, buffer: bytearray | memoryview, nbytes: int = 0, /) -> int:
        """
        Receive bytes into a writable buffer, returning the count.
        """

        want = nbytes if nbytes else len(buffer)
        data = self._sock.recv(want)
        count = len(data)
        with memoryview(buffer) as view:
            view[:count] = data
        return count

    def recvfrom(self, bufsize: int, /) -> tuple[bytes, tuple[str, int]]:
        """
        Receive a datagram, returning the data and the sender address.
        """

        if self._type is not SocketType.DGRAM:
            raise OSError(errno.EOPNOTSUPP, "recvfrom() is only supported on a datagram socket.")
        return cast("ClientUdpSocket", self._sock).recvfrom(bufsize)

    def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        Set a socket option on the daemon socket.
        """

        self._sock.setsockopt(level, optname, value)

    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        Get a socket option from the daemon socket.
        """

        return self._sock.getsockopt(level, optname)

    def shutdown(self, how: int, /) -> None:
        """
        Shut down one or both halves of the connection.
        """

        if self._type is not SocketType.STREAM:
            raise OSError(errno.EOPNOTSUPP, "shutdown() is only supported on a stream socket.")
        cast("ClientTcpSocket", self._sock).shutdown(how)

    def getsockname(self) -> tuple[str, int]:
        """
        Get the socket's local address.
        """

        return self._sock.getsockname()

    def getpeername(self) -> tuple[str, int]:
        """
        Get the socket's remote address.
        """

        return self._sock.getpeername()

    def close(self) -> None:
        """
        Close the socket and release the daemon handle.
        """

        self._sock.close()

    def __enter__(self) -> Self:
        """
        Enter the socket context, returning the socket.
        """

        return self

    def __exit__(
        self,
        exc_type: builtins.type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """
        Close the socket on context exit.
        """

        self.close()

    @override
    def __repr__(self) -> str:
        """
        Get the constructor-style representation of the socket.
        """

        return f"{type(self).__name__}(family={self._family!r}, type={self._type!r}, proto={self._proto!r})"


def socket(
    family: int | AddressFamily = AddressFamily.INET4,
    type: int | SocketType = SocketType.STREAM,
    proto: int = 0,
    fileno: int | None = None,
) -> Socket:
    """
    Open a daemon-backed socket, mirroring the stdlib 'socket()' factory.
    """

    if fileno is not None:
        raise NotImplementedError(
            "pytcp.socket.socket(fileno=...) wrapping an existing descriptor is "
            "not supported by the daemon-backed drop-in.",
        )

    address_family = AddressFamily(family)
    socket_type = SocketType(type)

    if socket_type not in (SocketType.STREAM, SocketType.DGRAM):
        raise NotImplementedError(
            f"The daemon-backed drop-in currently supports SOCK_STREAM and SOCK_DGRAM; got {socket_type!r}.",
        )

    underlying = _get_default_stack().socket(address_family, socket_type)

    return Socket(
        cast("ClientTcpSocket | ClientUdpSocket", underlying),
        family=address_family,
        type=socket_type,
        proto=proto,
    )
