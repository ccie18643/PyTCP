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
# ip6_ext_frag/ps.py - protocol support for IPv6 fragmentation extension header
#


# IPv6 protocol fragmentation extension header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next header   |   Reserved    |         Offset          |R|R|M|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                               Id                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP6_EXT_FRAG_HEADER_LEN = 8

IP6_EXT_FRAG_NEXT_HEADER_TCP = 6
IP6_EXT_FRAG_NEXT_HEADER_UDP = 17
IP6_EXT_FRAG_NEXT_HEADER_ICMP6 = 58

IP6_EXT_FRAG_NEXT_HEADER_TABLE = {IP6_EXT_FRAG_NEXT_HEADER_TCP: "TCP", IP6_EXT_FRAG_NEXT_HEADER_UDP: "UDP", IP6_EXT_FRAG_NEXT_HEADER_ICMP6: "ICMPv6"}


def __str__(self) -> str:
    """Packet log string"""

    return (
        f"IPv6_FRAG id {self.id}{', MF' if self.flag_mf else ''}, offset {self.offset}"
        + f", next {self.next} ({IP6_EXT_FRAG_NEXT_HEADER_TABLE.get(self.next, '???')})"
    )
