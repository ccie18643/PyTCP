#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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
# ip6/ps.py - protocol support for IPv6 protocol
#


from misc.ipv6_address import IPv6Address


# IPv6 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version| Traffic Class |           Flow Label                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Payload Length        |  Next Header  |   Hop Limit   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                         Source Address                        +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                      Destination Address                      +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


HEADER_LEN = 40

NEXT_HEADER_TCP = 6
NEXT_HEADER_UDP = 17
NEXT_HEADER_EXT_FRAG = 44
NEXT_HEADER_ICMP6 = 58

NEXT_HEADER_TABLE = {NEXT_HEADER_TCP: "TCP", NEXT_HEADER_UDP: "UDP", NEXT_HEADER_EXT_FRAG: "FRAG", NEXT_HEADER_ICMP6: "ICMPv6"}


class Base:
    """ IPv6 packet parser class """

    def __init__(self) -> None:
        """ Class constructor """

        self.src = IPv6Address(0)
        self.dst = IPv6Address(0)
        self.next = -1
        self.flow = -1
        self.dlen = -1
        self.hop = -1

    def __str__(self) -> str:
        """ Packet log string """

        return (
            f"IPv6 {self.src} > {self.dst}, next {self.next} ({NEXT_HEADER_TABLE.get(self.next, '???')}), flow {self.flow}"
            + f", dlen {self.dlen}, hop {self.hop}"
        )
