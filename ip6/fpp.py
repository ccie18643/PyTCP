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
# ip6.py/fpp - Fast Packet Parser support class for IPv6 protocol
#


import struct

import config
import ip6.ps
from misc.ipv6_address import IPv6Address
from misc.packet import PacketRx


class Parser:
    """IPv6 packet parser class"""

    def __init__(self, packet_rx: PacketRx) -> None:
        """Class constructor"""

        packet_rx.ip6 = self
        packet_rx.ip = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

        if not packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + ip6.ps.HEADER_LEN

    def __len__(self) -> int:
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    from ip6.ps import __str__

    @property
    def ver(self) -> int:
        """Read 'Version' field"""

        if "_cache__ver" not in self.__dict__:
            self._cache__ver = self._frame[self._hptr + 0] >> 4
        return self._cache__ver

    @property
    def dscp(self) -> int:
        """Read 'DSCP' field"""

        if "_cache__dscp" not in self.__dict__:
            self._cache__dscp = ((self._frame[self._hptr + 0] & 0b00001111) << 2) | ((self._frame[self._hptr + 1] & 0b11000000) >> 6)
        return self._cache__dscp

    @property
    def ecn(self) -> int:
        """Read 'ECN' field"""

        if "_cache__ecn" not in self.__dict__:
            self._cache__ecn = (self._frame[self._hptr + 1] & 0b00110000) >> 4
        return self._cache__ecn

    @property
    def flow(self) -> int:
        """Read 'Flow' field"""

        if "_cache__flow" not in self.__dict__:
            self._cache__flow = ((self._frame[self._hptr + 1] & 0b00001111) << 16) | (self._frame[self._hptr + 2] << 8) | self._frame[self._hptr + 3]
        return self._cache__flow

    @property
    def dlen(self) -> int:
        """Read 'Data length' field"""

        if "_cache__dlen" not in self.__dict__:
            self._cache__dlen = struct.unpack_from("!H", self._frame, self._hptr + 4)[0]
        return self._cache__dlen

    @property
    def next(self) -> int:
        """Read 'Next' field"""

        return self._frame[self._hptr + 6]

    @property
    def hop(self) -> int:
        """Read 'Hop' field"""

        return self._frame[self._hptr + 7]

    @property
    def src(self) -> IPv6Address:
        """Read 'Source address' field"""

        if "_cache__src" not in self.__dict__:
            self._cache__src = IPv6Address(self._frame[self._hptr + 8 : self._hptr + 24])
        return self._cache__src

    @property
    def dst(self) -> IPv6Address:
        """Read 'Destination address' field"""

        if "_cache__dst" not in self.__dict__:
            self._cache__dst = IPv6Address(self._frame[self._hptr + 24 : self._hptr + 40])
        return self._cache__dst

    @property
    def hlen(self) -> int:
        """Calculate header length"""

        return ip6.ps.HEADER_LEN

    @property
    def plen(self) -> int:
        """Calculate packet length"""

        return ip6.ps.HEADER_LEN + self.dlen

    @property
    def header_copy(self) -> bytes:
        """Return copy of packet header"""

        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = self._frame[self._hptr : self._hptr + ip6.ps.HEADER_LEN]
        return self._cache__header_copy

    @property
    def data_copy(self) -> bytes:
        """Return copy of packet data"""

        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = self._frame[self._hptr + ip6.ps.HEADER_LEN : self._hptr + self.plen]
        return self._cache__data_copy

    @property
    def packet_copy(self) -> bytes:
        """Return copy of whole packet"""

        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self._cache__packet_copy

    @property
    def pshdr_sum(self) -> int:
        """Returns IPv6 pseudo header that is used by TCP, UDP and ICMPv6 to compute their checksums"""

        if "_cache__pshdr_sum" not in self.__dict__:
            pseudo_header = struct.pack("! 16s 16s L BBBB", self.src.packed, self.dst.packed, self.dlen, 0, 0, 0, self.next)
            self._cache__pshdr_sum = sum(struct.unpack("! 5Q", pseudo_header))
        return self._cache__pshdr_sum

    def _packet_integrity_check(self) -> str:
        """Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return ""

        if len(self) < ip6.ps.HEADER_LEN:
            return "IPv6 integrity - wrong packet length (I)"

        if struct.unpack_from("!H", self._frame, self._hptr + 4)[0] != len(self) - ip6.ps.HEADER_LEN:
            return "IPv6 integrity - wrong packet length (II)"

        return ""

    def _packet_sanity_check(self) -> str:
        """Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values"""

        if not config.packet_sanity_check:
            return ""

        if self.ver != 6:
            return "IPv6 sanity - 'ver' must be 6"

        if self.hop == 0:
            return "IPv6 sanity - 'hop' must not be 0"

        if self.src.is_multicast:
            return "IPv6 sanity - 'src' must not be multicast"

        return ""
