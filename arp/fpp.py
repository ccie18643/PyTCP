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
# arp/fpp.py - Fast Packet Parser support class for ARP protocol
#


import struct

import arp.ps
import config
from misc.ipv4_address import IPv4Address
from misc.packet import PacketRx


class Parser:
    """ARP packet parser class"""

    def __init__(self, packet_rx: PacketRx) -> None:
        """Class constructor"""

        packet_rx.arp = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

    def __len__(self) -> int:
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    from arp.ps import __str__

    @property
    def hrtype(self) -> int:
        """Read 'Hardware address type' field"""

        if "_cache__hrtype" not in self.__dict__:
            self._cache__hrtype = struct.unpack_from("!H", self._frame, self._hptr + 0)[0]
        return self._cache__hrtype

    @property
    def prtype(self) -> int:
        """Read 'Protocol address type' field"""

        if "_cache__prtype" not in self.__dict__:
            self._cache__prtype = struct.unpack_from("!H", self._frame, self._hptr + 2)[0]
        return self._cache__prtype

    @property
    def hrlen(self) -> int:
        """Read 'Hardware address length' field"""

        return self._frame[self._hptr + 4]

    @property
    def prlen(self) -> int:
        """Read 'Protocol address length' field"""

        return self._frame[self._hptr + 5]

    @property
    def oper(self) -> int:
        """Read 'Operation' field"""

        if "_cache__oper" not in self.__dict__:
            self._cache__oper = struct.unpack_from("!H", self._frame, self._hptr + 6)[0]
        return self._cache__oper

    @property
    def sha(self) -> str:
        """Read 'Sender hardware address' field"""

        if "_cache__sha" not in self.__dict__:
            self._cache__sha = ":".join([f"{_:0>2x}" for _ in self._frame[self._hptr + 8 : self._hptr + 14]])
        return self._cache__sha

    @property
    def spa(self) -> IPv4Address:
        """Read 'Sender protocol address' field"""

        if "_cache__spa" not in self.__dict__:
            self._cache__spa = IPv4Address(self._frame[self._hptr + 14 : self._hptr + 18])
        return self._cache__spa

    @property
    def tha(self) -> str:
        """Read 'Target hardware address' field"""

        if "_cache__tha" not in self.__dict__:
            self._cache__tha = ":".join([f"{_:0>2x}" for _ in self._frame[self._hptr + 18 : self._hptr + 24]])
        return self._cache__tha

    @property
    def tpa(self) -> IPv4Address:
        """Read 'Target protocol address' field"""

        if "_cache__tpa" not in self.__dict__:
            self._cache__tpa = IPv4Address(self._frame[self._hptr + 24 : self._hptr + 28])
        return self._cache__tpa

    @property
    def packet_copy(self) -> bytes:
        """Read the whole packet"""

        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = self._frame[self._hptr : self._hptr + arp.ps.HEADER_LEN]
        return self._cache__packet_copy

    def _packet_integrity_check(self) -> str:
        """Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return ""

        if len(self) < arp.ps.HEADER_LEN:
            return "ARP integrity - wrong packet length (I)"

        return ""

    def _packet_sanity_check(self) -> str:
        """Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values"""

        if not config.packet_sanity_check:
            return ""

        if self.hrtype != 1:
            return "ARP sanity - 'arp_hrtype' must be 1"

        if self.prtype != 0x0800:
            return "ARP sanity - 'arp_prtype' must be 0x0800"

        if self.hrlen != 6:
            return "ARP sanity - 'arp_hrlen' must be 6"

        if self.prlen != 4:
            return "ARP sanity - 'arp_prlen' must be 4"

        if self.oper not in {1, 2}:
            return "ARP sanity - 'oper' must be [1-2]"

        return ""
