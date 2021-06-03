#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# misc/ip_helper.py - module contains helper functions
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import Union

from lib.ip4_address import Ip4Address
from lib.ip6_address import Ip6Address, Ip6AddressFormatError


def inet_cksum(data: bytes, dptr: int, dlen: int, init: int = 0) -> int:
    """Compute Internet Checksum used by IPv4/ICMPv4/ICMPv6/UDP/TCP protocols"""

    if dlen == 20:
        cksum = init + sum(struct.unpack_from("!5L", data, dptr))

    else:
        cksum = init + sum(struct.unpack_from(f"!{dlen >> 3}Q", data, dptr))
        if remainder := dlen & 7:
            cksum += struct.unpack("!Q", data[dptr + dlen - remainder : dptr + dlen] + b"\0" * (8 - remainder))[0]
        cksum = (cksum >> 64) + (cksum & 0xFFFFFFFFFFFFFFFF)

    cksum = (cksum >> 32) + (cksum & 0xFFFFFFFF)
    cksum = (cksum >> 16) + (cksum & 0xFFFF)
    return ~(cksum + (cksum >> 16)) & 0xFFFF


def ip_pick_version(ip_address: str) -> Union[Ip6Address, Ip4Address]:
    """Return correct Ip6Address or Ip4Address object based on address string provided"""

    try:
        return Ip6Address(ip_address)
    except Ip6AddressFormatError:
        return Ip4Address(ip_address)
