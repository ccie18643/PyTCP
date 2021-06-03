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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# fpa_ip6_ext_frag.py - Fast Packet Assembler support class for IPv6 fragment extension header
#


import struct

from tracker import Tracker

# IPv6 protocol fragmentation extension header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next header   |   Reserved    |         Offset          |R|R|M|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                               Id                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP6_EXT_FRAG_LEN = 8

IP6_NEXT_HEADER_TCP = 6
IP6_NEXT_HEADER_UDP = 17
IP6_NEXT_HEADER_ICMP6 = 58

IP6_NEXT_HEADER_TABLE = {IP6_NEXT_HEADER_TCP: "TCP", IP6_NEXT_HEADER_UDP: "UDP", IP6_NEXT_HEADER_ICMP6: "ICMPv6"}


class Ip6ExtFrag:
    """IPv6 fragment extension header support class"""

    protocol = "IP6_EXT_FRAG"

    def __init__(
        self,
        next,
        offset,
        flag_mf,
        id,
        data,
    ):
        """Class constructor"""

        self.tracker = Tracker("TX")

        self.next = next
        self.offset = offset
        self.flag_mf = flag_mf
        self.id = id
        self.data = data

        self.dlen = len(data)
        self.plen = len(self)

    def __str__(self):
        """Packet log string"""

        return (
            f"IPv6_FRAG id {self.id}{', MF' if self.flag_mf else ''}, offset {self.offset}"
            + f", next {self.next} ({IP6_NEXT_HEADER_TABLE.get(self.next, '???')})"
        )

    def __len__(self):
        """Length of the packet"""

        return IP6_EXT_FRAG_LEN + len(self.data)

    def assemble_packet(self, frame, hptr, _):
        """Assemble packet into the raw form"""

        struct.pack_into(
            f"! BBH L {self.dlen}s",
            frame,
            hptr,
            self.next,
            0,
            self.offset | self.flag_mf,
            self.id,
            self.data,
        )
