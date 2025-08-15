#!/usr/bin/env python3

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
Module contains function used to compute the Internet Checksum used used by
the IPv4/ICMPv4/ICMPv6/UDP/TCP protocols.

pytcp/lib/inet_cksum.py

ver 3.0.3
"""


import struct


def inet_cksum(
    *,
    data: bytes | bytearray | memoryview,
    init: int = 0,
) -> int:
    """
    Compute the Internet Checksum used by IPv4/ICMPv4/ICMPv6/UDP/TCP protocols.
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
    cksum = ~(cksum + (cksum >> 16)) & 0xFFFF

    return cksum
