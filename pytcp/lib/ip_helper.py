#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
Module contains helper functions for IP related operations.

pycp/misc/ip_helper.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp.lib import stack
from pytcp.lib.ip4_address import Ip4Address, Ip4AddressFormatError
from pytcp.lib.ip6_address import Ip6Address, Ip6AddressFormatError

if TYPE_CHECKING:
    from pytcp.lib.ip_address import IpAddress


def inet_cksum(data: memoryview, init: int = 0) -> int:
    """
    Compute Internet Checksum used by IPv4/ICMPv4/ICMPv6/UDP/TCP protocols.
    """
    if (dlen := len(data)) == 20:
        cksum = init + int(sum(struct.unpack("!5L", data)))
    else:
        cksum = init + int(sum(struct.unpack_from(f"!{dlen >> 3}Q", data)))
        if remainder := dlen & 7:
            cksum += int().from_bytes(data[-remainder:], byteorder="big") << (
                (8 - remainder) << 3
            )
        cksum = (cksum >> 64) + (cksum & 0xFFFFFFFFFFFFFFFF)
    cksum = (cksum >> 32) + (cksum & 0xFFFFFFFF)
    cksum = (cksum >> 16) + (cksum & 0xFFFF)
    return ~(cksum + (cksum >> 16)) & 0xFFFF


def ip_version(ip_address: str) -> int | None:
    """
    Return version of IP address string.
    """
    try:
        return Ip6Address(ip_address).version
    except Ip6AddressFormatError:
        try:
            return Ip4Address(ip_address).version
        except Ip4AddressFormatError:
            return None


def str_to_ip(ip_address: str) -> Ip6Address | Ip4Address | None:
    """
    Convert string to appropriate version IP address.
    """
    try:
        return Ip6Address(ip_address)
    except Ip6AddressFormatError:
        try:
            return Ip4Address(ip_address)
        except Ip4AddressFormatError:
            return None


def pick_local_ip_address(
    remote_ip_address: IpAddress,
) -> Ip6Address | Ip4Address:
    """
    Pick appropriate source IP address based on provided
    destination IP address.
    """
    assert isinstance(remote_ip_address, (Ip6Address, Ip4Address))
    if isinstance(remote_ip_address, Ip6Address):
        return pick_local_ip6_address(remote_ip_address)
    return pick_local_ip4_address(remote_ip_address)


def pick_local_ip6_address(remote_ip6_address: Ip6Address) -> Ip6Address:
    """
    Pick appropriate source IPv6 address based on provided
    destination IPv6 address.
    """
    # If destination belongs to any of local networks
    # pick source address from that network
    for ip6_host in stack.packet_handler.ip6_host:
        if remote_ip6_address in ip6_host.network:
            return ip6_host.address
    # If destination is external pick source from first
    # network that has default gateway set
    for ip6_host in stack.packet_handler.ip6_host:
        if ip6_host.gateway:
            return ip6_host.address
    # In case everything else fails return unspecified
    return Ip6Address(0)


def pick_local_ip4_address(remote_ip4_address: Ip4Address) -> Ip4Address:
    """
    Pick appropriate source IPv4 address based on provided
    destination IPv4 address.
    """
    # If destination belongs to any of local networks
    # pick source address from that network
    for ip4_host in stack.packet_handler.ip4_host:
        if remote_ip4_address in ip4_host.network:
            return ip4_host.address
    # If destination is external pick source from first
    # network that has default gateway set
    for ip4_host in stack.packet_handler.ip4_host:
        if ip4_host.gateway:
            return ip4_host.address
    # In case everything else fails return unspecified
    return Ip4Address(0)
