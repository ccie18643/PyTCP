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
('sendall', 'recv_into', 'gettimeout', 'getblocking', 'makefile', 'dup',
'detach', the context-manager protocol, the 'family'/'type'/'proto'
properties). It backs the 'pytcp.socket' package, which re-exports it
together with the stdlib constant / error / helper surface so 'import
pytcp.socket as socket' is a one-line stand-in for stdlib 'socket'. This
increment covers SOCK_STREAM and SOCK_DGRAM; non-blocking-readiness and
RAW/AF_PACKET land in later increments.

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
from pytcp.ipc.ipc__stdlib_socket import stdlib_socket as _stdlib_socket
from pytcp.runtime.socket import AddressFamily, SocketType

if TYPE_CHECKING:
    from io import _WrappedBuffer

    from _typeshed import ReadableBuffer, WriteableBuffer

    from pytcp.client import (
        ClientPingSocket,
        ClientRawSocket,
        ClientStack,
        ClientTcpSocket,
        ClientUdpSocket,
    )

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
            # The drop-in mirrors stdlib 'socket.socket._decref_socketio'
            # by name for 1:1 SocketIO-refcount parity; keep the private
            # spelling and suppress both protected-access checkers on the
            # one line (see source_files.md §5.2 per-line corner case).
            sock._decref_socketio()  # pylint: disable=protected-access  # pyright: ignore[reportPrivateUsage]


class _DupDataChannel:
    """
    A data-only endpoint over a duplicated data-channel descriptor.

    Wrapped in a 'Socket' and returned by 'Socket.dup()': a 'dup(2)' of
    the socketpair end reaches the same daemon-side socket, so the byte
    stream is shared, but the duplicate carries no daemon control handle —
    its control operations are unavailable.
    """

    def __init__(self, data_socket: _stdlib_socket.socket, /) -> None:
        """
        Adopt an already-duplicated data-channel descriptor.
        """

        self._data_socket = data_socket

    def fileno(self) -> int:
        """
        Get the duplicated data-channel file descriptor.
        """

        return self._data_socket.fileno()

    def settimeout(self, timeout: float | None, /) -> None:
        """
        Set the data-channel timeout (seconds, or None for blocking).
        """

        self._data_socket.settimeout(timeout)

    def setblocking(self, flag: bool, /) -> None:
        """
        Set the data channel blocking or non-blocking.
        """

        self._data_socket.setblocking(flag)

    def send(self, data: bytes) -> int:
        """
        Send 'data' over the shared data channel.
        """

        return self._data_socket.send(data)

    def recv(self, bufsize: int) -> bytes:
        """
        Receive up to 'bufsize' bytes from the shared data channel.
        """

        return self._data_socket.recv(bufsize)

    def detach(self) -> int:
        """
        Detach and return the duplicated data-channel descriptor.
        """

        return self._data_socket.detach()

    def close(self) -> None:
        """
        Close the duplicated data-channel descriptor only.
        """

        self._data_socket.close()


class Socket:
    """
    A stdlib-shaped socket backed by a PyTCP daemon socket handle.
    """

    def __init__(
        self,
        underlying: ClientTcpSocket | ClientUdpSocket | ClientRawSocket | ClientPingSocket | _DupDataChannel,
        /,
        *,
        family: AddressFamily,
        type: SocketType,
        proto: int | IpProto,
    ) -> None:
        """
        Wrap a daemon-backed client socket shim (or, for a duplicate, a
        data-only channel with no daemon control handle).
        """

        self._sock = underlying
        self._family = family
        self._type = type
        self._proto = int(proto)
        self._timeout: float | None = None
        self._io_refs: int = 0
        self._closed: bool = False
        self._real_closed: bool = False
        self._data_only = isinstance(underlying, _DupDataChannel)

    def _control_sock(self) -> ClientTcpSocket | ClientUdpSocket | ClientRawSocket | ClientPingSocket:
        """
        Return the underlying control-capable client shim, or raise if the
        socket is a data-only duplicate.
        """

        if self._data_only:
            raise OSError(errno.EOPNOTSUPP, "control operations are not available on a duplicated socket.")
        return cast("ClientTcpSocket | ClientUdpSocket | ClientRawSocket | ClientPingSocket", self._sock)

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

        self._control_sock().bind(address)

    def connect(self, address: tuple[str, int], /) -> None:
        """
        Connect the socket to a remote address.
        """

        self._control_sock().connect(address)

    def connect_ex(self, address: tuple[str, int], /) -> int:
        """
        Connect like 'connect', but return the error number instead of
        raising (0 on success), mirroring stdlib 'connect_ex'.
        """

        try:
            self.connect(address)
        except OSError as error:
            return error.errno if error.errno is not None else errno.EINVAL
        return 0

    def listen(self, backlog: int = 128, /) -> None:
        """
        Mark a stream socket as accepting connections.
        """

        if self._type is not SocketType.STREAM:
            raise OSError(errno.EOPNOTSUPP, "listen() is only supported on a stream socket.")
        cast("ClientTcpSocket", self._control_sock()).listen(backlog=backlog)

    def accept(self) -> tuple["Socket", tuple[str, int]]:
        """
        Accept a connection, returning a new Socket and the peer address.
        """

        if self._type is not SocketType.STREAM:
            raise OSError(errno.EOPNOTSUPP, "accept() is only supported on a stream socket.")
        child, peer = cast("ClientTcpSocket", self._control_sock()).accept()
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

        if self._type not in (SocketType.DGRAM, SocketType.RAW):
            raise OSError(errno.EOPNOTSUPP, "sendto() is only supported on a datagram or raw socket.")
        return cast("ClientUdpSocket | ClientRawSocket | ClientPingSocket", self._control_sock()).sendto(data, address)

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

        if self._type not in (SocketType.DGRAM, SocketType.RAW):
            raise OSError(errno.EOPNOTSUPP, "recvfrom() is only supported on a datagram or raw socket.")
        return cast("ClientUdpSocket | ClientRawSocket | ClientPingSocket", self._control_sock()).recvfrom(bufsize)

    def recvmsg(
        self,
        bufsize: int,
        ancbufsize: int = 0,
        flags: int = 0,
        /,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Receive a datagram with its ancillary control messages, mirroring
        stdlib 'socket.recvmsg'.
        """

        if self._type not in (SocketType.DGRAM, SocketType.RAW):
            raise OSError(errno.EOPNOTSUPP, "recvmsg() is only supported on a datagram or raw socket.")
        _ = flags
        return cast(
            "ClientUdpSocket | ClientRawSocket | ClientPingSocket",
            self._control_sock(),
        ).recvmsg(bufsize, ancbufsize)

    def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        Set a socket option on the daemon socket.
        """

        self._control_sock().setsockopt(level, optname, value)

    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        Get a socket option from the daemon socket.
        """

        return self._control_sock().getsockopt(level, optname)

    def shutdown(self, how: int, /) -> None:
        """
        Shut down one or both halves of the connection.
        """

        if self._type is not SocketType.STREAM:
            raise OSError(errno.EOPNOTSUPP, "shutdown() is only supported on a stream socket.")
        cast("ClientTcpSocket", self._control_sock()).shutdown(how)

    def getsockname(self) -> tuple[str, int]:
        """
        Get the socket's local address.
        """

        return self._control_sock().getsockname()

    def getpeername(self) -> tuple[str, int]:
        """
        Get the socket's remote address.
        """

        return self._control_sock().getpeername()

    def dup(self) -> Socket:
        """
        Duplicate the socket's data channel into an independent socket.

        Mirrors stdlib 'dup': a 'dup(2)' of the data-channel descriptor
        reaches the same daemon-side connection, so the byte stream is
        shared, but the duplicate carries no daemon control handle of its
        own — its control operations are unavailable. Closing either
        socket leaves the other's data channel intact. Supported on stream
        sockets.
        """

        if self._type is not SocketType.STREAM:
            raise OSError(errno.EOPNOTSUPP, "dup() is only supported on a stream socket.")
        data_socket = _stdlib_socket.socket(
            _stdlib_socket.AF_UNIX,
            _stdlib_socket.SOCK_STREAM,
            fileno=os.dup(self.fileno()),
        )
        return Socket(_DupDataChannel(data_socket), family=self._family, type=self._type, proto=self._proto)

    def detach(self) -> int:
        """
        Detach and return the live data-channel descriptor.

        Mirrors stdlib 'detach': the caller takes ownership of the
        descriptor and the wrapper becomes inert — a later 'close'
        releases nothing and 'fileno' reports -1. The daemon handle is
        left to be reaped when the connection to the daemon is closed.
        """

        descriptor = self._sock.detach()
        self._closed = True
        self._real_closed = True
        return descriptor

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
    proto: int | IpProto = 0,
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

    if socket_type not in (SocketType.STREAM, SocketType.DGRAM, SocketType.RAW):
        raise NotImplementedError(
            f"The daemon-backed drop-in supports SOCK_STREAM, SOCK_DGRAM and SOCK_RAW; got {socket_type!r}.",
        )

    # SOCK_RAW carries an IANA next-header in 'proto' (e.g. IPPROTO_ICMP);
    # a SOCK_DGRAM + IPPROTO_ICMP / IPPROTO_ICMPV6 is an unprivileged ICMP
    # Echo ('ping') socket that also keys on 'proto'; SOCK_STREAM and a
    # plain SOCK_DGRAM ignore it.
    protocol: int | IpProto | None
    if socket_type is SocketType.RAW:
        protocol = proto
    elif socket_type is SocketType.DGRAM and proto in (IpProto.ICMP4, IpProto.ICMP6):
        protocol = proto
    else:
        protocol = None
    underlying = _get_default_stack().socket(address_family, socket_type, protocol)

    return Socket(
        cast("ClientTcpSocket | ClientUdpSocket | ClientRawSocket | ClientPingSocket", underlying),
        family=address_family,
        type=socket_type,
        proto=proto,
    )


type _SockAddr = tuple[str, int] | tuple[str, int, int, int]
type _AddrInfo = tuple[AddressFamily, SocketType, int, str, _SockAddr]


class _GlobalDefaultTimeout:
    """
    Sentinel for the stdlib 'create_connection' default-timeout argument.
    """


# Mirrors 'socket._GLOBAL_DEFAULT_TIMEOUT' — the value 'create_connection'
# treats as "leave the socket's own timeout untouched". Re-exported so a
# consumer that reads 'socket._GLOBAL_DEFAULT_TIMEOUT' (e.g. http.client)
# sees the same sentinel.
_GLOBAL_DEFAULT_TIMEOUT: _GlobalDefaultTimeout = _GlobalDefaultTimeout()


def gethostbyname(hostname: str, /) -> str:
    """
    Resolve 'hostname' to an IPv4 address string through the daemon
    resolver, mirroring stdlib 'socket.gethostbyname'.
    """

    return _get_default_stack().resolver.gethostbyname(hostname)


def getaddrinfo(
    host: str,
    port: int | None = None,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> list[_AddrInfo]:
    """
    Resolve 'host' / 'port' into stdlib-shaped address-info 5-tuples
    through the daemon resolver, mirroring stdlib 'socket.getaddrinfo'.
    """

    return _get_default_stack().resolver.getaddrinfo(host, port, family, type, proto, flags)


def create_connection(
    address: tuple[str, int],
    timeout: float | None | _GlobalDefaultTimeout = _GLOBAL_DEFAULT_TIMEOUT,
    source_address: tuple[str, int] | None = None,
) -> Socket:
    """
    Open a TCP connection to 'address', mirroring stdlib
    'socket.create_connection' (resolve via the daemon, then try each
    candidate address until one connects).
    """

    host, port = address
    errors: list[OSError] = []

    for family, socket_type, candidate_proto, _canonname, sockaddr in getaddrinfo(
        host, port, 0, int(SocketType.STREAM)
    ):
        sock: Socket | None = None
        try:
            sock = socket(family, socket_type, candidate_proto)
            if not isinstance(timeout, _GlobalDefaultTimeout) and timeout is not None:
                sock.settimeout(timeout)
            if source_address is not None:
                sock.bind(source_address)
            sock.connect((sockaddr[0], sockaddr[1]))
            return sock
        except OSError as error:
            errors.append(error)
            if sock is not None:
                sock.close()

    if errors:
        raise errors[-1]
    raise OSError("getaddrinfo returned an empty list")
