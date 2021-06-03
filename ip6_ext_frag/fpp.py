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
# ip6_ext_frag/fpp.py - Fast Packet Parser for  IPv6 fragmentation extension header
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING

import config
import ip6_ext_frag.ps

if TYPE_CHECKING:
    from misc.packet import PacketRx


class Ip6ExtFragParser:
    """IPv6 fragmentation extension header parser class"""

    def __init__(self, packet_rx: PacketRx) -> None:
        """Class constructor"""

        assert packet_rx.ip6 is not None

        packet_rx.ip6_ext_frag = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr
        self._plen = packet_rx.ip6.dlen

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

        if not packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + ip6_ext_frag.ps.IP6_EXT_FRAG_HEADER_LEN

    def __len__(self):
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    from ip6_ext_frag.ps import __str__

    @property
    def next(self) -> int:
        """Read 'Next' field"""

        return self._frame[self._hptr + 0]

    @property
    def offset(self) -> int:
        """Read 'Fragment offset' field"""

        if "_cache__offset" not in self.__dict__:
            self._cache__offset = struct.unpack_from("!H", self._frame, self._hptr + 2)[0] & 0b1111111111111000
        return self._cache__offset

    @property
    def flag_mf(self) -> bool:
        """Read 'MF flag' field"""

        return bool(self._frame[self._hptr + 3] & 0b00000001)

    @property
    def id(self) -> int:
        """Read 'Identification' field"""

        if "_cache__id" not in self.__dict__:
            self._cache__id = struct.unpack_from("!L", self._frame, self._hptr + 4)[0]
        return self._cache__id

    @property
    def hlen(self) -> int:
        """Calculate header length"""

        return ip6_ext_frag.ps.IP6_EXT_FRAG_HEADER_LEN

    @property
    def dlen(self) -> int:
        """Calculate data length"""

        return self._plen - ip6_ext_frag.ps.IP6_EXT_FRAG_HEADER_LEN

    @property
    def plen(self) -> int:
        """Calculate packet length"""

        return self._plen

    @property
    def header_copy(self) -> bytes:
        """Return copy of packet header"""

        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = self._frame[self._hptr : self._hptr + ip6_ext_frag.ps.IP6_EXT_FRAG_HEADER_LEN]
        return self._cache__header_copy

    @property
    def data_copy(self) -> bytes:
        """Return copy of packet data"""

        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = self._frame[self._hptr + ip6_ext_frag.ps.IP6_EXT_FRAG_HEADER_LEN : self._hptr + self.plen]
        return self._cache__data_copy

    @property
    def packet_copy(self) -> bytes:
        """Return copy of whole packet"""

        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self._cache__packet_copy

    def _packet_integrity_check(self) -> str:
        """Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return ""

        if len(self) < ip6_ext_frag.ps.IP6_EXT_FRAG_HEADER_LEN:
            return "IPv4 integrity - wrong packet length (I)"

        return ""

    def _packet_sanity_check(self) -> str:
        """Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values"""

        if not config.packet_sanity_check:
            return ""

        return ""
