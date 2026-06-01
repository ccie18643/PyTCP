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
This module contains the AF_PACKET link-layer socket address value
type ('SockAddrLl') — the PyTCP equivalent of Linux
'struct sockaddr_ll' (<linux/if_packet.h>). It is the address form
exchanged by 'PacketSocket.bind' / '.sendto' / '.recvfrom' the way the
'(ip, port)' tuple is for IP sockets.

pytcp/socket/sockaddr_ll.py

ver 3.0.8
"""

from dataclasses import dataclass, field

from net_addr import MacAddress
from net_proto.lib.enums import EtherType
from pytcp.socket import ETH_P_ALL, PacketType


@dataclass(frozen=True, kw_only=True, slots=True)
class SockAddrLl:
    """
    The AF_PACKET link-layer socket address — Linux 'struct
    sockaddr_ll'. 'ifindex' scopes the address to one interface (0 =
    every interface / unbound); 'ethertype' is the protocol filter
    (ETH_P_ALL = capture-all); 'pkttype' classifies how an inbound
    frame was addressed; 'mac' is the link-layer address (the unicast
    source on egress, the matched address on ingress).
    """

    ifindex: int = 0
    ethertype: EtherType | int = ETH_P_ALL
    pkttype: PacketType = PacketType.PACKET_HOST
    mac: MacAddress = field(default_factory=MacAddress)
