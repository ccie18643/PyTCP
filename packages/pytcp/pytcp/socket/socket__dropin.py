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
('sendall', 'recv_into', 'gettimeout', 'getblocking', 'makefile', the
context-manager protocol, the 'family'/'type'/'proto' properties). It
backs the 'pytcp.socket' package, which re-exports it together with the
stdlib constant / error / helper surface so 'import pytcp.socket as
socket' is a one-line stand-in for stdlib 'socket'. This increment covers
SOCK_STREAM and SOCK_DGRAM; non-blocking-readiness, RAW/AF_PACKET, and
'dup' / 'detach' land in later increments.

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
import io
import os
import threading
from types import TracebackType
from typing import TYPE_CHECKING, Self, cast, override

from net_proto.lib.enums import IpProto
from pytcp.runtime.socket import AddressFamily, SocketType

if TYPE_CHECKING:
    from io import _WrappedBuffer

    from _typeshed import ReadableBuffer, WriteableBuffer

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


class _SocketIO(io.RawIOBase):
    """
    A raw byte stream over a daemon-backed 'Socket' (makefile backing).
    """

    def __init__(self, sock: Socket, mode: str, /) -> None:
        """
        Wrap a 'Socket' as a raw I/O stream in the given makefile mode.
        """

        super().__init__()
        self._sock: Socket | None = sock
        self._reading = "r" in mode
        self._writing = "w" in mode
        self._timeout_occurred: bool = False

    def _require_sock(self) -> Socket:
        """
        Return the wrapped socket, or raise if the stream is closed.
        """

        if self._sock is None:
            raise ValueError("I/O operation on closed socket.")
        return self._sock

    @override
    def readable(self) -> bool:
        """
        Get whether the stream is open for reading.
        """

        return self._reading

    @override
    def writable(self) -> bool:
        """
        Get whether the stream is open for writing.
        """

        return self._writing

    @override
    def fileno(self) -> int:
        """
        Get the underlying data-channel file descriptor.
        """

        return self._require_sock().fileno()

    @override
    def readinto(self, buffer: WriteableBuffer, /) -> int | None:
        """
        Read available bytes into 'buffer', returning the count (None when
        a non-blocking read would block, 0 at end of stream).
        """

        if not self._reading:
            raise OSError(errno.EBADF, "the stream is not open for reading.")
        sock = self._require_sock()
        try:
            return sock.recv_into(memoryview(buffer))
        except TimeoutError:
            self._timeout_occurred = True
            raise
        except OSError as receive_error:
            if receive_error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return None
            raise

    @override
    def write(self, buffer: ReadableBuffer, /) -> int | None:
        """
        Write 'buffer' to the stream, returning the count accepted (None
        when a non-blocking write would block).
        """

        if not self._writing:
            raise OSError(errno.EBADF, "the stream is not open for writing.")
        sock = self._require_sock()
        try:
            return sock.send(bytes(buffer))
        except OSError as send_error:
            if send_error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return None
            raise

    @override
    def close(self) -> None:
        """
        Close the stream and drop its reference on the wrapped socket.
        """

        if self.closed:
            return
        super().close()
        sock = self._sock
        self._sock = None
        if sock is not None:
            sock._decref_socketio()


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
        self._io_refs: int = 0
        self._closed: bool = False
        self._real_closed: bool = False

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

    def makefile(
        self,
        mode: str = "r",
        buffering: int | None = None,
        *,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> io.BufferedReader | io.BufferedWriter | io.BufferedRWPair | io.TextIOWrapper | _SocketIO:
        """
        Return a file object over the socket, mirroring stdlib makefile.

        The returned stream shares the socket's data channel; the daemon
        handle is held open until both the socket and every stream made
        from it are closed (the stdlib shared-fd ownership contract).
        """

        if not set(mode) <= {"r", "w", "b"}:
            raise ValueError(f"invalid mode {mode!r} (only r, w, b allowed)")

        writing = "w" in mode
        reading = "r" in mode or not writing
        binary = "b" in mode
        raw_mode = ("r" if reading else "") + ("w" if writing else "")

        raw = _SocketIO(self, raw_mode)
        self._io_refs += 1

        effective_buffering = io.DEFAULT_BUFFER_SIZE if buffering is None or buffering < 0 else buffering
        if effective_buffering == 0:
            if not binary:
                raise ValueError("unbuffered streams must be binary")
            return raw

        buffer: io.BufferedReader | io.BufferedWriter | io.BufferedRWPair
        if reading and writing:
            buffer = io.BufferedRWPair(raw, raw, effective_buffering)
        elif reading:
            buffer = io.BufferedReader(raw, effective_buffering)
        else:
            buffer = io.BufferedWriter(raw, effective_buffering)

        if binary:
            return buffer
        # 'buffer' is a read-only / write-only / read-write buffered stream;
        # 'TextIOWrapper' only exercises the half matching the text mode, so
        # the wrap is sound even though the static '_WrappedBuffer' protocol
        # demands both 'read' and 'write'.
        return io.TextIOWrapper(cast("_WrappedBuffer", buffer), encoding, errors, newline)

    def close(self) -> None:
        """
        Close the socket and release the daemon handle.

        If outstanding 'makefile' streams still reference the data
        channel, the underlying handle is held open until the last of them
        closes — mirroring the stdlib socket / makefile shared-fd
        ownership.
        """

        self._closed = True
        if self._io_refs <= 0:
            self._real_close()

    def _real_close(self) -> None:
        """
        Release the daemon handle and data channel exactly once.
        """

        if self._real_closed:
            return
        self._real_closed = True
        self._sock.close()

    def _decref_socketio(self) -> None:
        """
        Drop one 'makefile' stream's reference, closing once none remain.
        """

        if self._io_refs > 0:
            self._io_refs -= 1
        if self._closed and self._io_refs <= 0:
            self._real_close()

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
