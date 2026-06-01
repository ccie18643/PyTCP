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

ver 3.0.8
"""

import socket
from typing import Self

from net_proto.lib.enums import IpProto
from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__socket_rpc import accept_socket, open_socket, socket_call
from pytcp.runtime.socket import AddressFamily, SocketType

# Default accept-queue depth when 'listen' is called without an explicit
# backlog (mirrors the daemon-side 'TCP__DEFAULT_BACKLOG').
IPC__CLIENT_TCP__DEFAULT_BACKLOG: int = 16


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
        self._data_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=data_fd)

    def fileno(self) -> int:
        """
        Return the data-channel descriptor, selectable with select / poll
        / epoll.
        """

        return self._data_socket.fileno()

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

    def listen(self, *, backlog: int = IPC__CLIENT_TCP__DEFAULT_BACKLOG) -> None:
        """
        Mark the daemon socket as a passive listener with an accept queue
        bounded by 'backlog'.
        """

        socket_call(self._client, method="listen", handle=self._handle, args={"backlog": backlog})

    def accept(self) -> tuple[Self, tuple[str, int]]:
        """
        Block until an inbound connection completes, returning a new
        'ClientTcpSocket' for the accepted connection (its data path is
        the passed descriptor) and the peer's '(host, port)' address.
        """

        child_handle, peer, data_fd = accept_socket(self._client, handle=self._handle)
        return self._adopt(self._client, child_handle, data_fd), peer

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
        instance._data_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=data_fd)
        return instance

    def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        Set a socket option on the daemon socket.
        """

        socket_call(
            self._client,
            method="setsockopt",
            handle=self._handle,
            args={"level": level, "optname": optname, "value": value},
        )

    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        Get a socket option from the daemon socket.
        """

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

    def close(self) -> None:
        """
        Close the daemon socket and the local data-channel descriptor.
        """

        try:
            socket_call(self._client, method="close", handle=self._handle, args={})
        finally:
            self._data_socket.close()
