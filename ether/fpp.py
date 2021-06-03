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
# ether/fpp.py - Fast Packet Parser support class for Ethernet protocol
#


import struct

import config
import ether.ps
from misc.packet import PacketRx


class Parser:
    """Ethernet packet parser class"""

    def __init__(self, packet_rx: PacketRx) -> None:
        """Class constructor"""

        packet_rx.ether = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

        if not packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + ether.ps.HEADER_LEN

    def __len__(self) -> int:
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    from ether.ps import __str__

    @property
    def dst(self) -> str:
        """Read 'Destination MAC address' field"""

        if "_cache__dst" not in self.__dict__:
            self._cache__dst = ":".join([f"{_:0>2x}" for _ in self._frame[self._hptr + 0 : self._hptr + 6]])
        return self._cache__dst

    @property
    def src(self) -> str:
        """Read 'Source MAC address' field"""

        if "_cache__src" not in self.__dict__:
            self._cache__src = ":".join([f"{_:0>2x}" for _ in self._frame[self._hptr + 6 : self._hptr + 12]])
        return self._cache__src

    @property
    def type(self) -> int:
        """Read 'EtherType' field"""

        if "_cache__type" not in self.__dict__:
            self._cache__type = struct.unpack_from("!H", self._frame, self._hptr + 12)[0]
        return self._cache__type

    @property
    def header_copy(self) -> bytes:
        """Return copy of packet header"""

        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = self._frame[self._hptr : self._hptr + ether.ps.HEADER_LEN]
        return self._cache__header_copy

    @property
    def data_copy(self) -> bytes:
        """Return copy of packet data"""

        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = self._frame[self._hptr + ether.ps.HEADER_LEN :]
        return self._cache__data_copy

    @property
    def packet_copy(self) -> bytes:
        """Return copy of whole packet"""

        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = self._frame[self._hptr :]
        return self._cache__packet_copy

    @property
    def plen(self) -> int:
        """Calculate packet length"""

        if "_cache__plen" not in self.__dict__:
            self._cache__plen = len(self)
        return self._cache__plen

    def _packet_integrity_check(self) -> str:
        """Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return ""

        if len(self) < ether.ps.HEADER_LEN:
            return "ETHER integrity - wrong packet length (I)"

        return ""

    def _packet_sanity_check(self) -> str:
        """Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values"""

        if not config.packet_sanity_check:
            return ""

        if self.type < ether.ps.TYPE_MIN:
            return "ETHER sanity - 'ether_type' must be greater than 0x0600"

        return ""
