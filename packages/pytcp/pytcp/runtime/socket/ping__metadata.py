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
This module contains the inbound ICMP Echo Reply metadata for ping sockets.

A 'PingMetadata' carries one inbound ICMP Echo Reply from the ICMP RX
handler to the owning 'PingSocket': the serialized ICMP message bytes the
application receives (no IP header, mirroring a Linux ICMP datagram
socket), the sender's address, and the received IP TTL / IPv6 Hop Limit
that 'recvmsg' surfaces as an 'IP_TTL' / 'IPV6_HOPLIMIT' cmsg when
'IP_RECVTTL' / 'IPV6_RECVHOPLIMIT' is enabled.

pytcp/runtime/socket/ping__metadata.py

ver 3.0.9
"""

from dataclasses import dataclass

from net_addr import Ip4Address, Ip6Address
from net_addr.ip_version import IpVersion


@dataclass(frozen=True, kw_only=True, slots=True)
class PingMetadata:
    """
    The inbound ICMP Echo Reply metadata delivered to a ping socket.
    """

    ip__ver: IpVersion
    ip__remote_address: Ip6Address | Ip4Address
    ip__ttl: int
    icmp__data: bytes
