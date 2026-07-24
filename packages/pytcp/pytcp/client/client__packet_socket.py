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
This module contains the client-side AF_PACKET socket shim.

'ClientPacketSocket' mirrors the BSD-style 'PacketSocket' surface across
the process boundary. Its data path is the client end of the daemon's
SOCK_DGRAM socketpair; each link-layer frame is prefixed with its
'sockaddr_ll' (see 'ipc__packet_frame') so 'recvfrom' (how the frame
arrived) and 'sendto' (which interface to egress) carry the link-layer
address across. 'bind' (a 'SockAddrLl') and 'close' marshal over the
SOCKET_CALL op keyed by the daemon-assigned handle.

pytcp/client/client__packet_socket.py

ver 3.0.9
"""

from net_proto.lib.enums import EtherType
from pytcp.ipc.ipc__client import IpcClient
from pytcp.ipc.ipc__packet_bridge import IPC__PACKET_BRIDGE__CHUNK_SIZE
from pytcp.ipc.ipc__packet_frame import decode_packet, encode_packet
from pytcp.ipc.ipc__socket_rpc import open_socket, socket_call
from pytcp.ipc.ipc__stdlib_socket import stdlib_socket
from pytcp.runtime.socket import ETH_P_ALL, AddressFamily, SocketType
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl


class ClientPacketSocket:
    """
    A client-side AF_PACKET socket backed by a daemon socket over IPC.
    """

    def __init__(self, client: IpcClient, /, *, protocol: EtherType | int = ETH_P_ALL) -> None:
        """
        Open a daemon-side AF_PACKET socket for the given ethertype filter
        and adopt its passed SOCK_DGRAM data-channel descriptor.
        """

        self._client = client
        handle, data_fd = open_socket(
            client,
            family=AddressFamily.PACKET,
            type_=SocketType.RAW,
            protocol=protocol,
        )
        self._handle = handle
        self._data_socket = stdlib_socket.socket(stdlib_socket.AF_UNIX, stdlib_socket.SOCK_DGRAM, fileno=data_fd)

    def fileno(self) -> int:
        """
        Return the data-channel descriptor, selectable with select / poll
        / epoll.
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

    def sendto(self, data: bytes, address: SockAddrLl, /) -> int:
        """
        Send the link-layer frame 'data' out the interface named by
        'address'.
        """

        self._data_socket.send(encode_packet(address, data))
        return len(data)

    def send(self, data: bytes) -> int:
        """
        Send the link-layer frame 'data' out the sole interface (an
        unbound egress).
        """

        self._data_socket.send(encode_packet(SockAddrLl(), data))
        return len(data)

    def recvfrom(self, bufsize: int | None = None) -> tuple[bytes, SockAddrLl]:
        """
        Receive one link-layer frame with the 'sockaddr_ll' describing how
        it arrived, truncating the frame to 'bufsize'.
        """

        sockaddr_ll, frame = decode_packet(self._data_socket.recv(IPC__PACKET_BRIDGE__CHUNK_SIZE))
        return (frame if bufsize is None else frame[:bufsize]), sockaddr_ll

    def recv(self, bufsize: int | None = None) -> bytes:
        """
        Receive one link-layer frame, truncated to 'bufsize'.
        """

        return self.recvfrom(bufsize)[0]

    def bind(self, address: SockAddrLl) -> None:
        """
        Scope the daemon socket to '(address.ifindex, address.ethertype)'.
        """

        socket_call(self._client, method="bind", handle=self._handle, args={"address": address})

    def close(self) -> None:
        """
        Close the daemon socket and the local data-channel descriptor.
        """

        try:
            socket_call(self._client, method="close", handle=self._handle, args={})
        finally:
            self._data_socket.close()
