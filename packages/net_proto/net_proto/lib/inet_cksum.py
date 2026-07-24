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
This module contains the function used to compute the Internet Checksum for
the IPv4/ICMPv4/ICMPv6/UDP/TCP protocols.

The algorithm is defined in RFC 1071 (Computing the Internet Checksum):
treat the input as a sequence of 16-bit words, fold the one's-complement
sum into 16 bits, then take the one's-complement of the result. RFC 1141
and RFC 1624 describe incremental-update variants used elsewhere in the
stack; this module implements only the from-scratch RFC 1071 path.

net_proto/lib/inet_cksum.py

ver 3.0.9
"""

import struct

from net_addr import Buffer


def inet_cksum(*buffers: Buffer, init: int = 0) -> int:
    """
    Calculate the Internet Checksum of the provided buffers.

    Reference: RFC 1071 (Computing the Internet Checksum).
    """

    cksum = init
    carry = 0

    for buffer in buffers:
        buffer_len = len(buffer)
        offset = 0

        if carry:
            if buffer_len:
                cksum += (carry << 8) | buffer[0]
                offset = 1
                carry = 0
            else:
                continue

        if (remainder := buffer_len - offset) >= 8:
            q_count = remainder >> 3
            cksum += sum(struct.unpack_from(f"!{q_count}Q", buffer, offset))
            offset += q_count << 3

        if even := (buffer_len - offset) & ~1:
            h_count = even >> 1
            cksum += sum(struct.unpack_from(f"!{h_count}H", buffer, offset))
            offset += even

        if buffer_len - offset == 1:
            carry = buffer[offset]

    cksum += carry << 8
    cksum = (cksum & 0xFFFF_FFFF_FFFF_FFFF) + (cksum >> 64)
    cksum = (cksum & 0xFFFF_FFFF) + (cksum >> 32)
    cksum = (cksum & 0xFFFF) + (cksum >> 16)
    cksum = (cksum & 0xFFFF) + (cksum >> 16)

    return (~cksum) & 0xFFFF
