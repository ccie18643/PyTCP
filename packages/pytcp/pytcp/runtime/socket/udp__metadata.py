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
This module contains the interface class for the UDP Parser -> UDP Socket communication.

pytcp/runtime/socket/udp__metadata.py

ver 3.0.10
"""

from dataclasses import dataclass

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto.lib.tracker import Tracker
from net_proto.protocols.ip4.options.ip4__options import Ip4Options
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.socket_id import SocketId


@dataclass(frozen=True, kw_only=True, slots=True)
class UdpMetadata:
    """
    The UDP socket metadata taken from the received packet.
    """

    ip__ver: IpVersion
    ip__local_address: Ip6Address | Ip4Address
    ip__remote_address: Ip6Address | Ip4Address

    udp__local_port: int
    udp__remote_port: int
    udp__data: memoryview = memoryview(bytes())

    # IPv4 options block carried by the inbound datagram, parsed
    # into an 'Ip4Options' object. 'None' for IPv6 datagrams and
    # for IPv4 datagrams with no options. Surfaced to applications
    # via 'recvmsg' as an 'IP_OPTIONS' cmsg per RFC 1122 §4.1.3.2
    # when 'IP_RECVOPTS' is set on the receiving socket.
    ip4__options: Ip4Options | None = None

    # Combined TOS (IPv4) / Traffic Class (IPv6) byte computed
    # from the inbound datagram's DSCP and ECN bits as
    # '(dscp << 2) | ecn'. Surfaced to applications via
    # 'recvmsg' as an 'IP_TOS' cmsg (IPv4, 1 byte) or
    # 'IPV6_TCLASS' cmsg (IPv6, 4-byte int) per RFC 1122 §4.1.4
    # / RFC 3542 §6.5 when 'IP_RECVTOS' / 'IPV6_RECVTCLASS' is
    # set on the receiving socket.
    ip__tos: int = 0

    tracker: Tracker | None = None

    @property
    def socket_ids(self) -> list[SocketId]:
        """
        Get list of the listening socket IDs that match the metadata.
        """

        match self.ip__ver, self.udp__local_port, self.udp__remote_port:
            case IpVersion.IP4, 68, 67:
                # DHCPv4 client sockets keep their local at 0.0.0.0
                # for the whole RFC 2131 §4.4 lifecycle (see
                # 'UdpSocket._get_ip_addresses'). The 'connect()'
                # target varies by FSM phase:
                #   - INIT / REBINDING: 255.255.255.255 (broadcast).
                #   - RENEWING: server unicast (the leasing server).
                # Both phases have to be findable by RX, so we
                # enumerate one ID per connect-target shape.
                return [
                    SocketId(
                        address_family=AddressFamily.INET4,
                        socket_type=SocketType.DGRAM,
                        local_address=Ip4Address(),
                        local_port=68,
                        remote_address=self.ip__remote_address,
                        remote_port=67,
                    ),  # RENEWING: unicast reply from the leasing server.
                    SocketId(
                        address_family=AddressFamily.INET4,
                        socket_type=SocketType.DGRAM,
                        local_address=Ip4Address(),
                        local_port=68,
                        remote_address=Ip4Address("255.255.255.255"),
                        remote_port=67,
                    ),  # INIT / REBINDING: broadcast reply.
                ]
            case IpVersion.IP6, 546, 547:
                return [
                    SocketId(
                        address_family=AddressFamily.INET6,
                        socket_type=SocketType.DGRAM,
                        local_address=Ip6Address(),
                        local_port=546,
                        remote_address=Ip6Address("ff02::1:2"),
                        remote_port=547,
                    ),  # ID for the DHCPv6 client operation.
                    SocketId(
                        address_family=AddressFamily.INET6,
                        socket_type=SocketType.DGRAM,
                        local_address=Ip6Address(),
                        local_port=546,
                        remote_address=Ip6Address("ff02::1:3"),
                        remote_port=547,
                    ),  # ID for the DHCPv6 client operation.
                ]
            case _:
                return [
                    SocketId(
                        address_family=AddressFamily.from_ver(self.ip__ver),
                        socket_type=SocketType.DGRAM,
                        local_address=self.ip__local_address,
                        local_port=self.udp__local_port,
                        remote_address=self.ip__remote_address,
                        remote_port=self.udp__remote_port,
                    ),
                    SocketId(
                        address_family=AddressFamily.from_ver(self.ip__ver),
                        socket_type=SocketType.DGRAM,
                        local_address=self.ip__local_address,
                        local_port=self.udp__local_port,
                        remote_address=self.ip__remote_address.unspecified,
                        remote_port=0,
                    ),
                    SocketId(
                        address_family=AddressFamily.from_ver(self.ip__ver),
                        socket_type=SocketType.DGRAM,
                        local_address=self.ip__local_address.unspecified,
                        local_port=self.udp__local_port,
                        remote_address=self.ip__remote_address.unspecified,
                        remote_port=0,
                    ),
                ]
