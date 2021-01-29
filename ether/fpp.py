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
# ether/fpp.py - Fast Packet Parser support class for Ethernet protocol
#


import struct

import config
import ether.ps
from misc.packet import PacketRx


class Parser:
    """ Ethernet packet parser class """

    def __init__(self, packet_rx: PacketRx):
        """ Class constructor """

        packet_rx.ether = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr

        self.__dst = NotImplemented
        self.__src = NotImplemented
        self.__type = NotImplemented
        self.__header_copy = NotImplemented
        self.__data_copy = NotImplemented
        self.__packet_copy = NotImplemented
        self.__plen = NotImplemented

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

        if not packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + ether.ps.HEADER_LEN

    def __len__(self):
        """ Number of bytes remaining in the frame """

        return len(self._frame) - self._hptr

    from ether.ps import __str__

    @property
    def dst(self):
        """ Read 'Destination MAC address' field """

        if self.__dst is NotImplemented:
            self.__dst = ":".join([f"{_:0>2x}" for _ in self._frame[self._hptr + 0 : self._hptr + 6]])
        return self.__dst

    @property
    def src(self):
        """ Read 'Source MAC address' field """

        if self.__src is NotImplemented:
            self.__src = ":".join([f"{_:0>2x}" for _ in self._frame[self._hptr + 6 : self._hptr + 12]])
        return self.__src

    @property
    def type(self):
        """ Read 'EtherType' field """

        if self.__type is NotImplemented:
            self.__type = struct.unpack_from("!H", self._frame, self._hptr + 12)[0]
        return self.__type

    @property
    def header_copy(self):
        """ Return copy of packet header """

        if self.__header_copy is NotImplemented:
            self.__header_copy = self._frame[self._hptr : self._hptr + ether.ps.HEADER_LEN]
        return self.__header_copy

    @property
    def data_copy(self):
        """ Return copy of packet data """

        if self.__data_copy is NotImplemented:
            self.__data_copy = self._frame[self._hptr + ether.ps.HEADER_LEN :]
        return self.__data_copy

    @property
    def packet_copy(self):
        """ Return copy of whole packet """

        if self.__packet_copy is NotImplemented:
            self.__packet_copy = self._frame[self._hptr :]
        return self.__packet_copy

    @property
    def plen(self):
        """ Calculate packet length """

        if self.__plen is NotImplemented:
            self.__plen = len(self)
        return self.__plen

    def _packet_integrity_check(self):
        """ Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe """

        if not config.packet_integrity_check:
            return False

        if len(self) < ether.ps.HEADER_LEN:
            return "ETHER integrity - wrong packet length (I)"

        return False

    def _packet_sanity_check(self):
        """ Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values """

        if not config.packet_sanity_check:
            return False

        if self.type < ether.ps.TYPE_MIN:
            return "ETHER sanity - 'ether_type' must be greater than 0x0600"

        return False
