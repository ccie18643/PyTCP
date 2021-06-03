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
# arp/fpa.py - Fast Packet Assembler support class for ARP protocol
#


import struct
from typing import Optional

import arp.ps
import ether.ps
from misc.ipv4_address import IPv4Address
from misc.tracker import Tracker


class Assembler:
    """ARP packet assembler support class"""

    ether_type = ether.ps.TYPE_ARP

    def __init__(
        self,
        sha: str,
        spa: IPv4Address,
        tpa: IPv4Address,
        tha: str = "00:00:00:00:00:00",
        oper: int = arp.ps.OP_REQUEST,
        echo_tracker: Optional[Tracker] = None,
    ) -> None:
        """Class constructor"""

        self.tracker = Tracker("TX", echo_tracker)

        self.hrtype = 1
        self.prtype = 0x0800
        self.hrlen = 6
        self.prlen = 4
        self.oper = oper
        self.sha = sha
        self.spa = IPv4Address(spa)
        self.tha = tha
        self.tpa = IPv4Address(tpa)

    def __len__(self) -> int:
        """Length of the packet"""

        return arp.ps.HEADER_LEN

    from arp.ps import __str__

    def assemble(self, frame: bytearray, hptr: int):
        """Assemble packet into the raw form"""

        return struct.pack_into(
            "!HH BBH 6s 4s 6s 4s",
            frame,
            hptr,
            self.hrtype,
            self.prtype,
            self.hrlen,
            self.prlen,
            self.oper,
            bytes.fromhex(self.sha.replace(":", "")),
            IPv4Address(self.spa).packed,
            bytes.fromhex(self.tha.replace(":", "")),
            IPv4Address(self.tpa).packed,
        )
