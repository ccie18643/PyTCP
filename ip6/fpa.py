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
# ip6/fpa.py - Fast Packet Assembler support class for IPv6 protocol
#


import struct
from typing import Union

import config
import ether.ps
import icmp6.fpa
import ip6.ps
import ip6_ext_frag.fpa
import tcp.fpa
import udp.fpa
from misc.ipv6_address import IPv6Address


class Assembler:
    """IPv6 packet assembler support class"""

    ether_type = ether.ps.TYPE_IP6

    def __init__(
        self,
        carried_packet: Union[ip6_ext_frag.fpa.Assembler, icmp6.fpa.Assembler, tcp.fpa.Assembler, udp.fpa.Assembler],
        src: IPv6Address,
        dst: IPv6Address,
        hop: int = config.ip6_default_hop,
        dscp: int = 0,
        ecn: int = 0,
        flow: int = 0,
    ) -> None:
        """Class constructor"""

        assert carried_packet.ip6_next in {ip6.ps.NEXT_HEADER_ICMP6, ip6.ps.NEXT_HEADER_UDP, ip6.ps.NEXT_HEADER_TCP, ip6.ps.NEXT_HEADER_EXT_FRAG}

        self._carried_packet = carried_packet
        self.tracker = self._carried_packet.tracker
        self.ver = 6
        self.dscp = dscp
        self.ecn = ecn
        self.flow = flow
        self.hop = hop
        self.src = IPv6Address(src)
        self.dst = IPv6Address(dst)
        self.next = self._carried_packet.ip6_next
        self.dlen = len(carried_packet)

    def __len__(self) -> int:
        """Length of the packet"""

        return ip6.ps.HEADER_LEN + len(self._carried_packet)

    from ip6.ps import __str__

    @property
    def pshdr_sum(self) -> int:
        """Returns IPv6 pseudo header that is used by TCP, UDP and ICMPv6 to compute their checksums"""

        pseudo_header = struct.pack("! 16s 16s L BBBB", self.src.packed, self.dst.packed, self.dlen, 0, 0, 0, self.next)
        return sum(struct.unpack("! 5Q", pseudo_header))

    def assemble(self, frame: bytearray, hptr: int) -> None:
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

        self._carried_packet.assemble(frame, hptr + ip6.ps.HEADER_LEN, self.pshdr_sum)
