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
# ether/fpa.py - Fast Packet Assembler support class for Ethernet protocol
#


import struct
from typing import Union

import arp.fpa
import ether.ps
import ip4.fpa
import ip6.fpa


class Assembler:
    """Ethernet packet assembler support class"""

    def __init__(
        self, carried_packet: Union[arp.fpa.Assembler, ip4.fpa.Assembler, ip6.fpa.Assembler], src: str = "00:00:00:00:00:00", dst: str = "00:00:00:00:00:00"
    ) -> None:
        """Class constructor"""

        assert carried_packet.ether_type in {ether.ps.TYPE_ARP, ether.ps.TYPE_IP4, ether.ps.TYPE_IP6}

        self._carried_packet = carried_packet
        self.tracker = self._carried_packet.tracker
        self.dst = dst
        self.src = src
        self.type = self._carried_packet.ether_type

    def __len__(self) -> int:
        """Length of the packet"""

        return ether.ps.HEADER_LEN + len(self._carried_packet)

    from ether.ps import __str__

    def assemble(self, frame: bytearray, hptr: int) -> None:
        """Assemble packet into the raw form"""

        struct.pack_into("! 6s 6s H", frame, hptr, bytes.fromhex(self.dst.replace(":", "")), bytes.fromhex(self.src.replace(":", "")), self.type)

        self._carried_packet.assemble(frame, hptr + ether.ps.HEADER_LEN)
