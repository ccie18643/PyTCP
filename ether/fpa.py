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


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING, Union

import ether.ps
from lib.mac_address import MacAddress

if TYPE_CHECKING:
    from arp.fpa import ArpAssembler
    from ip4.fpa import Ip4Assembler
    from ip6.fpa import Ip6Assembler


class EtherAssembler:
    """Ethernet packet assembler support class"""

    def __init__(
        self,
        carried_packet: Union[ArpAssembler, Ip4Assembler, Ip6Assembler],
        src: MacAddress = MacAddress("00:00:00:00:00:00"),
        dst: MacAddress = MacAddress("00:00:00:00:00:00"),
    ) -> None:
        """Class constructor"""

        assert carried_packet.ether_type in {ether.ps.ETHER_TYPE_ARP, ether.ps.ETHER_TYPE_IP4, ether.ps.ETHER_TYPE_IP6}

        self._carried_packet = carried_packet
        self.tracker = self._carried_packet.tracker
        self.dst = dst
        self.src = src
        self.type = self._carried_packet.ether_type

    def __len__(self) -> int:
        """Length of the packet"""

        return ether.ps.ETHER_HEADER_LEN + len(self._carried_packet)

    from ether.ps import __str__

    def assemble(self, frame: bytearray, hptr: int) -> None:
        """Assemble packet into the raw form"""

        struct.pack_into("! 6s 6s H", frame, hptr, bytes(self.dst), bytes(self.src), self.type)

        self._carried_packet.assemble(frame, hptr + ether.ps.ETHER_HEADER_LEN)
