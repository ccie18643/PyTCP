#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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


class Parser:
    """ IPv6 packet parser class """

    def __init__(self, packet_rx):
        """ Class constructor """

        packet_rx.ip6 = self
        packet_rx.ip = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr

        self.__ver = NotImplemented
        self.__dscp = NotImplemented
        self.__ecn = NotImplemented
        self.__flow = NotImplemented
        self.__dlen = NotImplemented
        self.__src = NotImplemented
        self.__dst = NotImplemented
        self.__data = NotImplemented
        self.__header_copy = NotImplemented
        self.__data_copy = NotImplemented
        self.__packet_copy = NotImplemented
        self.__pshdr_sum = NotImplemented

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

        if not packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + ip6.ps.HEADER_LEN

    def __len__(self):
        """ Number of bytes remaining in the frame """

        return len(self._frame) - self._hptr

    from ip6.ps import __str__

    @property
    def ver(self):
        """ Read 'Version' field """

        if self.__ver is NotImplemented:
            self.__ver = self._frame[self._hptr + 0] >> 4
        return self.__ver

    @property
    def dscp(self):
        """ Read 'DSCP' field """

        if self.__dscp is NotImplemented:
            self.__dscp = ((self._frame[self._hptr + 0] & 0b00001111) << 2) | ((self._frame[self._hptr + 1] & 0b11000000) >> 6)
        return self.__dscp

    @property
    def ecn(self):
        """ Read 'ECN' field """

        if self.__ecn is NotImplemented:
            self.__ecn = (self._frame[self._hptr + 1] & 0b00110000) >> 4
        return self.__ecn

    @property
    def flow(self):
        """ Read 'Flow' field """

        if self.__flow is NotImplemented:
            self.__flow = ((self._frame[self._hptr + 1] & 0b00001111) << 16) | (self._frame[self._hptr + 2] << 8) | self._frame[self._hptr + 3]
        return self.__flow

    @property
    def dlen(self):
        """ Read 'Data length' field """

        if self.__dlen is NotImplemented:
            self.__dlen = struct.unpack_from("!H", self._frame, self._hptr + 4)[0]
        return self.__dlen

    @property
    def next(self):
        """ Read 'Next' field """

        return self._frame[self._hptr + 6]

    @property
    def hop(self):
        """ Read 'Hop' field """

        return self._frame[self._hptr + 7]

    @property
    def src(self):
        """ Read 'Source address' field """

        if self.__src is NotImplemented:
            self.__src = IPv6Address(self._frame[self._hptr + 8 : self._hptr + 24])
        return self.__src

    @property
    def dst(self):
        """ Read 'Destination address' field """

        if self.__dst is NotImplemented:
            self.__dst = IPv6Address(self._frame[self._hptr + 24 : self._hptr + 40])
        return self.__dst

    @property
    def hlen(self):
        """ Calculate header length """

        return ip6.ps.HEADER_LEN

    @property
    def plen(self):
        """ Calculate packet length """

        return ip6.ps.HEADER_LEN + self.dlen

    @property
    def header_copy(self):
        """ Return copy of packet header """

        if self.__header_copy is NotImplemented:
            self.__header_copy = self._frame[self._hptr : self._hptr + ip6.ps.HEADER_LEN]
        return self.__header_copy

    @property
    def data_copy(self):
        """ Return copy of packet data """

        if self.__data_copy is NotImplemented:
            self.__data_copy = self._frame[self._hptr + ip6.ps.HEADER_LEN : self._hptr + self.plen]
        return self.__data_copy

    @property
    def packet_copy(self):
        """ Return copy of whole packet """

        if self.__packet_copy is NotImplemented:
            self.__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self.__packet_copy

    @property
    def pshdr_sum(self):
        """ Returns IPv6 pseudo header that is used by TCP, UDP and ICMPv6 to compute their checksums """

        if self.__pshdr_sum is NotImplemented:
            pseudo_header = struct.pack("! 16s 16s L BBBB", self.src.packed, self.dst.packed, self.dlen, 0, 0, 0, self.next)
            self.__pshdr_sum = sum(struct.unpack("! 5Q", pseudo_header))
        return self.__pshdr_sum

    def _packet_integrity_check(self):
        """ Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe """

        if not config.packet_integrity_check:
            return False

        if len(self) < ip6.ps.HEADER_LEN:
            return "IPv6 integrity - wrong packet length (I)"

        if struct.unpack_from("!H", self._frame, self._hptr + 4)[0] != len(self) - ip6.ps.HEADER_LEN:
            return "IPv6 integrity - wrong packet length (II)"

        return False

    def _packet_sanity_check(self):
        """ Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values """

        if not config.packet_sanity_check:
            return False

        if self.ver != 6:
            return "IPv6 sanity - 'ver' must be 6"

        if self.hop == 0:
            return "IPv6 sanity - 'hop' must not be 0"

        if self.src.is_multicast:
            return "IPv6 sanity - 'src' must not be multicast"

        return False
