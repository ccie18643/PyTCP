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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# fpp_ip6_ext_frag.py - packet parser IPv6 protocol fragmentation extension header
#


import struct

import config

# IPv6 protocol fragmentation extension header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next header   |   Reserved    |         Offset          |R|R|M|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                               Id                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP6_EXT_FRAG_LEN = 8

IP6_NEXT_HEADER_TCP = 6
IP6_NEXT_HEADER_UDP = 17
IP6_NEXT_HEADER_ICMP6 = 58

IP6_NEXT_HEADER_TABLE = {IP6_NEXT_HEADER_TCP: "TCP", IP6_NEXT_HEADER_UDP: "UDP", IP6_NEXT_HEADER_ICMP6: "ICMPv6"}


class Ip6ExtFrag:
    """IPv6 fragmentation extension headr support class"""

    class __not_cached:
        pass

    def __init__(self, packet_rx):
        """Class constructor"""

        packet_rx.ip6_ext_frag = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr
        self._plen = packet_rx.ip6.dlen

        self.__next = self.__not_cached
        self.__offset = self.__not_cached
        self.__id = self.__not_cached
        self.__header_copy = self.__not_cached
        self.__data_copy = self.__not_cached
        self.__packet_copy = self.__not_cached

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

        if not packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + IP6_EXT_FRAG_LEN

    def __str__(self):
        """Packet log string"""

        return (
            f"IPv6_FRAG id {self.id}{', MF' if self.flag_mf else ''}, offset {self.offset}"
            + f", next {self.next} ({IP6_NEXT_HEADER_TABLE.get(self.next, '???')})"
        )

    def __len__(self):
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    @property
    def next(self):
        """Read 'Next' field"""

        return self._frame[self._hptr + 0]

    @property
    def offset(self):
        """Read 'Fragment offset' field"""

        if self.__offset is self.__not_cached:
            self.__offset = struct.unpack_from("!H", self._frame, self._hptr + 2)[0] & 0b1111111111111000
        return self.__offset

    @property
    def flag_mf(self):
        """Read 'MF flag' field"""

        return self._frame[self._hptr + 3] & 0b00000001

    @property
    def id(self):
        """Read 'Identification' field"""

        if self.__id is self.__not_cached:
            self.__id = struct.unpack_from("!L", self._frame, self._hptr + 4)[0]
        return self.__id

    @property
    def hlen(self):
        """Calculate header length"""

        return IP6_EXT_FRAG_LEN

    @property
    def dlen(self):
        """Calculate data length"""

        return self._plen - IP6_EXT_FRAG_LEN

    @property
    def plen(self):
        """Calculate packet length"""

        return self._plen

    @property
    def header_copy(self):
        """Return copy of packet header"""

        if self.__header_copy is self.__not_cached:
            self.__header_copy = self._frame[self._hptr : self._hptr + IP6_EXT_FRAG_LEN]
        return self.__header_copy

    @property
    def data_copy(self):
        """Return copy of packet data"""

        if self.__data_copy is self.__not_cached:
            self.__data_copy = self._frame[self._hptr + IP6_EXT_FRAG_LEN : self._hptr + self.plen]
        return self.__data_copy

    @property
    def packet_copy(self):
        """Return copy of whole packet"""

        if self.__packet_copy is self.__not_cached:
            self.__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self.__packet_copy

    def _packet_integrity_check(self):
        """Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return False

        return False

    def _packet_sanity_check(self):
        """Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values"""

        if not config.packet_sanity_check:
            return False

        return False
