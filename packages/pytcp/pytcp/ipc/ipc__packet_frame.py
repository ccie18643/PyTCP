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
This module contains the IPC AF_PACKET data-channel frame codec.

An AF_PACKET socket's data channel is a SOCK_DGRAM socketpair (boundary-
preserving — one captured/sent link-layer frame per AF_UNIX datagram).
Each frame is prefixed with a fixed 13-byte 'sockaddr_ll' so 'recvfrom'
(daemon -> client: how the frame arrived) and 'sendto' (client -> daemon:
which interface to egress) survive the boundary:

    ifindex(4) ethertype(2) pkttype(1) mac(6) frame

The ethertype is read back through 'EtherType.from_int' and the MAC from
its 6 wire bytes, so the link-layer address survives as typed values.

pytcp/ipc/ipc__packet_frame.py

ver 3.0.8
"""

from net_addr import Buffer, MacAddress
from net_proto.lib.enums import EtherType
from pytcp.ipc.ipc__errors import IpcFrameError
from pytcp.runtime.socket import PacketType
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl

IPC__PACKET__IFINDEX_LEN: int = 4
IPC__PACKET__ETHERTYPE_LEN: int = 2
IPC__PACKET__PKTTYPE_LEN: int = 1
IPC__PACKET__MAC_LEN: int = 6
IPC__PACKET__HEADER_LEN: int = (
    IPC__PACKET__IFINDEX_LEN + IPC__PACKET__ETHERTYPE_LEN + IPC__PACKET__PKTTYPE_LEN + IPC__PACKET__MAC_LEN
)


def encode_packet(sockaddr_ll: SockAddrLl, frame: Buffer, /) -> bytes:
    """
    Encode a link-layer frame into a framed blob carrying its
    'sockaddr_ll' ahead of the frame.
    """

    return (
        sockaddr_ll.ifindex.to_bytes(IPC__PACKET__IFINDEX_LEN, "big")
        + int(sockaddr_ll.ethertype).to_bytes(IPC__PACKET__ETHERTYPE_LEN, "big")
        + int(sockaddr_ll.pkttype).to_bytes(IPC__PACKET__PKTTYPE_LEN, "big")
        + bytes(sockaddr_ll.mac)
        + bytes(frame)
    )


def decode_packet(blob: Buffer, /) -> tuple[SockAddrLl, bytes]:
    """
    Decode a framed link-layer blob into its 'sockaddr_ll' and frame.
    """

    data = bytes(blob)

    if len(data) < IPC__PACKET__HEADER_LEN:
        raise IpcFrameError("AF_PACKET frame is truncated before the end of its sockaddr_ll.")

    ethertype_start = IPC__PACKET__IFINDEX_LEN
    pkttype_start = ethertype_start + IPC__PACKET__ETHERTYPE_LEN
    mac_start = pkttype_start + IPC__PACKET__PKTTYPE_LEN

    sockaddr_ll = SockAddrLl(
        ifindex=int.from_bytes(data[:ethertype_start], "big"),
        ethertype=EtherType.from_int(int.from_bytes(data[ethertype_start:pkttype_start], "big")),
        pkttype=PacketType(data[pkttype_start]),
        mac=MacAddress(data[mac_start:IPC__PACKET__HEADER_LEN]),
    )

    return sockaddr_ll, data[IPC__PACKET__HEADER_LEN:]
