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
# protocols/ether/fpa.py - Fast Packet Assembler support class for Ethernet protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING, Union

from lib.mac_address import MacAddress
from protocols.ether.ps import (
    ETHER_HEADER_LEN,
    ETHER_TYPE_ARP,
    ETHER_TYPE_IP4,
    ETHER_TYPE_IP6,
    ETHER_TYPE_TABLE,
)

if TYPE_CHECKING:
    from lib.tracker import Tracker
    from protocols.arp.fpa import ArpAssembler
    from protocols.ip4.fpa import Ip4Assembler
    from protocols.ip6.fpa import Ip6Assembler


class EtherAssembler:
    """Ethernet packet assembler support class"""

    def __init__(
        self,
        carried_packet: Union[ArpAssembler, Ip4Assembler, Ip6Assembler],
        src: MacAddress = MacAddress(0),
        dst: MacAddress = MacAddress(0),
    ) -> None:
        """Class constructor"""

        assert carried_packet.ether_type in {ETHER_TYPE_ARP, ETHER_TYPE_IP4, ETHER_TYPE_IP6}

        self._carried_packet: Union[ArpAssembler, Ip4Assembler, Ip6Assembler] = carried_packet
        self._tracker: Tracker = self._carried_packet.tracker
        self._dst: MacAddress = dst
        self._src: MacAddress = src
        self._type: int = self._carried_packet.ether_type

    def __len__(self) -> int:
        """Length of the packet"""

        return ETHER_HEADER_LEN + len(self._carried_packet)

    def __str__(self) -> str:
        """Packet log string"""

        return f"ETHER {self._src} > {self._dst}, 0x{self._type:0>4x} ({ETHER_TYPE_TABLE.get(self._type, '???')})"

    @property
    def tracker(self) -> Tracker:
        """Getter for _tracker"""

        return self._tracker

    @property
    def dst(self) -> MacAddress:
        """Getter for _dst"""

        return self._dst

    @dst.setter
    def dst(self, mac_address: MacAddress):
        """Setter for _dst"""

        self._dst = mac_address

    @property
    def src(self) -> MacAddress:
        """Getter for _src"""

        return self._src

    @src.setter
    def src(self, mac_address: MacAddress):
        """Setter for _src"""

        self._src = mac_address

    def assemble(self, frame: memoryview) -> None:
        """Assemble packet into the raw form"""

        struct.pack_into("! 6s 6s H", frame, 0, bytes(self._dst), bytes(self._src), self._type)

        self._carried_packet.assemble(frame[ETHER_HEADER_LEN:])