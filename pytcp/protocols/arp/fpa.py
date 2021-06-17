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
# protocols/arp/fpa.py - Fast Packet Assembler support class for ARP protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import Optional

from lib.ip4_address import Ip4Address
from lib.mac_address import MacAddress
from lib.tracker import Tracker
from protocols.arp.ps import ARP_HEADER_LEN, ARP_OP_REPLY, ARP_OP_REQUEST
from protocols.ether.ps import ETHER_TYPE_ARP


class ArpAssembler:
    """ARP packet assembler support class"""

    ether_type = ETHER_TYPE_ARP

    def __init__(
        self,
        sha: MacAddress,
        spa: Ip4Address,
        tpa: Ip4Address,
        tha: MacAddress = MacAddress(0),
        oper: int = ARP_OP_REQUEST,
        echo_tracker: Optional[Tracker] = None,
    ) -> None:
        """Class constructor"""

        self._tracker = Tracker("TX", echo_tracker)

        self._hrtype: int = 1
        self._prtype: int = 0x0800
        self._hrlen: int = 6
        self._prlen: int = 4
        self._oper: int = oper
        self._sha: MacAddress = sha
        self._spa: Ip4Address = spa
        self._tha: MacAddress = tha
        self._tpa: Ip4Address = tpa

    def __len__(self) -> int:
        """Length of the packet"""

        return ARP_HEADER_LEN

    def __str__(self) -> str:
        """Packet log string"""

        if self._oper == ARP_OP_REQUEST:
            return f"ARP request {self._spa} / {self._sha} > {self._tpa} / {self._tha}"
        if self._oper == ARP_OP_REPLY:
            return f"ARP reply {self._spa} / {self._sha} > {self._tpa} / {self._tha}"

        return f"ARP request unknown operation {self._oper}"

    @property
    def tracker(self) -> Tracker:
        """Getter for _tracker"""

        return self._tracker

    def assemble(self, frame: memoryview) -> None:
        """Assemble packet into the raw form"""

        struct.pack_into(
            "!HH BBH 6s 4s 6s 4s",
            frame,
            0,
            self._hrtype,
            self._prtype,
            self._hrlen,
            self._prlen,
            self._oper,
            bytes(self._sha),
            bytes(self._spa),
            bytes(self._tha),
            bytes(self._tpa),
        )
