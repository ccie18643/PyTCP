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
# udp/fpp.py - Fast Packet Parser support class for UDP protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING

import config
import udp.ps
from misc.ip_helper import inet_cksum

if TYPE_CHECKING:
    from misc.packet import PacketRx


class UdpParser:
    """UDP packet parser class"""

    def __init__(self, packet_rx: PacketRx) -> None:
        """Class constructor"""

        assert packet_rx.ip is not None

        packet_rx.udp = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr
        self._plen = packet_rx.ip.dlen

        packet_rx.parse_failed = self._packet_integrity_check(packet_rx.ip.pshdr_sum) or self._packet_sanity_check()

        if not packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + udp.ps.UDP_HEADER_LEN

    def __len__(self) -> int:
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    from udp.ps import __str__

    @property
    def sport(self) -> int:
        """Read 'Source port' field"""

        if "_cache__sport" not in self.__dict__:
            self._cache__sport = struct.unpack_from("!H", self._frame, self._hptr + 0)[0]
        return self._cache__sport

    @property
    def dport(self) -> int:
        """Read 'Destianation port' field"""

        if "_cache__dport" not in self.__dict__:
            self._cache__dport = struct.unpack_from("!H", self._frame, self._hptr + 2)[0]
        return self._cache__dport

    @property
    def plen(self) -> int:
        """Read 'Packet length' field"""

        if "_cache__plen" not in self.__dict__:
            self._cache__plen = struct.unpack_from("!H", self._frame, self._hptr + 4)[0]
        return self._cache__plen

    @property
    def cksum(self) -> int:
        """Read 'Checksum' field"""

        if "_cache__cksum" not in self.__dict__:
            self._cache__cksum = struct.unpack_from("!H", self._frame, self._hptr + 6)[0]
        return self._cache__cksum

    @property
    def data(self) -> bytes:
        """Read the data packet carries"""

        if "_cache__data" not in self.__dict__:
            self._cache__data = self._frame[self._hptr + udp.ps.UDP_HEADER_LEN : self._hptr + self.plen]
        return self._cache__data

    @property
    def dlen(self) -> int:
        """Calculate data length"""

        return self.plen - udp.ps.UDP_HEADER_LEN

    @property
    def packet(self) -> bytes:
        """Read the whole packet"""

        if "_cache__packet" not in self.__dict__:
            self._cache__packet = self._frame[self._hptr :]
        return self._cache__packet

    def _packet_integrity_check(self, pshdr_sum: int) -> str:
        """Packet integrity check to be run on raw frame prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return ""

        if inet_cksum(self._frame, self._hptr, self._plen, pshdr_sum):
            return "UDP integrity - wrong packet checksum"

        if not udp.ps.UDP_HEADER_LEN <= self._plen <= len(self):
            return "UDP integrity - wrong packet length (I)"

        plen = struct.unpack_from("!H", self._frame, self._hptr + 4)[0]
        if not udp.ps.UDP_HEADER_LEN <= plen == self._plen <= len(self):
            return "UDP integrity - wrong packet length (II)"

        return ""

    def _packet_sanity_check(self):
        """Packet sanity check to be run on parsed packet to make sure frame's fields contain sane values"""

        if not config.packet_sanity_check:
            return ""

        if self.sport == 0:
            return "UDP sanity - 'udp_sport' must be greater than 0"

        if self.dport == 0:
            return "UDP sanity - 'udp_dport' must be greater then 0"

        return ""
