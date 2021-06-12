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
# udp/fpa.py - Fast Packet Assembler support class for UDP protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import Optional

import ip4.ps
import ip6.ps
import udp.ps
from lib.tracker import Tracker
from misc.ip_helper import inet_cksum


class UdpAssembler:
    """UDP packet assembler support class"""

    ip4_proto = ip4.ps.IP4_PROTO_UDP
    ip6_next = ip6.ps.IP6_NEXT_HEADER_UDP

    def __init__(self, sport: int, dport: int, data: Optional[bytes] = None, echo_tracker: Optional[Tracker] = None) -> None:
        """Class constructor"""

        self._tracker: Tracker = Tracker("TX", echo_tracker)
        self._sport: int = sport
        self._dport: int = dport
        self._data: bytes = b"" if data is None else data
        self._plen: int = udp.ps.UDP_HEADER_LEN + len(self._data)

    def __len__(self) -> int:
        """Length of the packet"""

        return self._plen

    def __str__(self) -> str:
        """Packet log string"""

        return f"UDP {self._sport} > {self._dport}, len {self._plen}"

    @property
    def tracker(self) -> Tracker:
        """Getter for _tracker"""

        return self._tracker

    def assemble(self, frame: memoryview, pshdr_sum: int) -> None:
        """Assemble packet into the raw form"""

        # memoryview: bytes conversion requir
        struct.pack_into(f"! HH HH {len(self._data)}s", frame, 0, self._sport, self._dport, self._plen, 0, bytes(self._data))
        struct.pack_into("! H", frame, 6, inet_cksum(frame, pshdr_sum))
