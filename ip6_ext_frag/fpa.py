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
# ip6_ext_frag/fpa.py - Fast Packet Assembler support class for IPv6 fragment extension header
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct

import ip6.ps
import ip6_ext_frag.ps
from misc.tracker import Tracker


class Ip6ExtFragAssembler:
    """IPv6 fragment extension header assembler support class"""

    ip6_next = ip6.ps.IP6_NEXT_HEADER_EXT_FRAG

    def __init__(
        self,
        next: int,
        offset: int,
        flag_mf: bool,
        id: int,
        data: bytes,
    ):
        """Class constructor"""

        assert next in {ip6.ps.IP6_NEXT_HEADER_ICMP6, ip6.ps.IP6_NEXT_HEADER_UDP, ip6.ps.IP6_NEXT_HEADER_TCP}

        self.tracker = Tracker("TX")
        self.next = next
        self.offset = offset
        self.flag_mf = flag_mf
        self.id = id
        self.data = data
        self.dlen = len(data)
        self.plen = len(self)

    def __len__(self) -> int:
        """Length of the packet"""

        return ip6_ext_frag.ps.IP6_EXT_FRAG_HEADER_LEN + len(self.data)

    from ip6_ext_frag.ps import __str__

    def assemble(self, frame: bytearray, hptr: int, _: int):
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
