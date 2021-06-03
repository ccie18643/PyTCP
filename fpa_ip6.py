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
# fpa_ip6.py - Fast Packet Assembler support class for IPv6 protocol
#


import struct

import config
from ipv6_address import IPv6Address

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


IP6_HEADER_LEN = 40

IP6_NEXT_HEADER_TCP = 6
IP6_NEXT_HEADER_UDP = 17
IP6_NEXT_HEADER_EXT_FRAG = 44
IP6_NEXT_HEADER_ICMP6 = 58

IP6_NEXT_HEADER_TABLE = {IP6_NEXT_HEADER_TCP: "TCP", IP6_NEXT_HEADER_UDP: "UDP", IP6_NEXT_HEADER_ICMP6: "ICMPv6", IP6_NEXT_HEADER_EXT_FRAG: "IPv6_FRAG"}


class Ip6Packet:
    """IPv6 packet support class"""

    protocol = "IP6"

    def __init__(
        self,
        child_packet,
        src,
        dst,
        hop=config.ip6_default_hop,
        dscp=0,
        ecn=0,
        flow=0,
    ):
        """Class constructor"""

        assert child_packet.protocol in {"ICMP6", "UDP", "TCP", "IP6_EXT_FRAG"}, f"Not supported protocol: {child_packet.protocol}"
        self._child_packet = child_packet

        self.tracker = self._child_packet.tracker

        self.ver = 6
        self.dscp = dscp
        self.ecn = ecn
        self.flow = flow
        self.hop = hop
        self.src = IPv6Address(src)
        self.dst = IPv6Address(dst)

        if self._child_packet.protocol == "ICMP6":
            self.next = IP6_NEXT_HEADER_ICMP6

        elif self._child_packet.protocol == "UDP":
            self.next = IP6_NEXT_HEADER_UDP

        elif self._child_packet.protocol == "TCP":
            self.next = IP6_NEXT_HEADER_TCP

        elif self._child_packet.protocol == "IP6_EXT_FRAG":
            self.next = IP6_NEXT_HEADER_EXT_FRAG

        self.dlen = len(child_packet)

    def __str__(self):
        """Packet log string"""

        return (
            f"IPv6 {self.src} > {self.dst}, next {self.next} ({IP6_NEXT_HEADER_TABLE.get(self.next, '???')}), flow {self.flow}"
            + f", dlen {self.dlen}, hop {self.hop}"
        )

    def __len__(self):
        """Length of the packet"""

        return IP6_HEADER_LEN + len(self._child_packet)

    @property
    def pshdr_sum(self):
        """Returns IPv6 pseudo header that is used by TCP, UDP and ICMPv6 to compute their checksums"""

        pseudo_header = struct.pack("! 16s 16s L BBBB", self.src.packed, self.dst.packed, self.dlen, 0, 0, 0, self.next)
        return sum(struct.unpack("! 5Q", pseudo_header))

    def assemble_packet(self, frame, hptr):
        """Assemble packet into the raw form"""

        struct.pack_into(
            "! BBBB HBB 16s 16s",
            frame,
            hptr,
            self.ver << 4 | self.dscp >> 4,
            self.dscp << 6 | self.ecn << 4 | ((self.flow & 0b000011110000000000000000) >> 16),
            (self.flow & 0b000000001111111100000000) >> 8,
            self.flow & 0b000000000000000011111111,
            self.dlen,
            self.next,
            self.hop,
            self.src.packed,
            self.dst.packed,
        )

        self._child_packet.assemble_packet(frame, hptr + IP6_HEADER_LEN, self.pshdr_sum)
