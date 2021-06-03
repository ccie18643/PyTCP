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
# fpp_icmp4.py - Fast Packet Parser support class for ICMPv4 protocol
#


import struct

import config
from ip_helper import inet_cksum

# Echo reply message (0/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/[0-3, 5-15])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/4)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |          Link MTU / 0         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Echo Request message (8/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP4_HEADER_LEN = 4

ICMP4_ECHO_REPLY = 0
ICMP4_UNREACHABLE = 3
ICMP4_UNREACHABLE__NET = 0
ICMP4_UNREACHABLE__HOST = 1
ICMP4_UNREACHABLE__PROTOCOL = 2
ICMP4_UNREACHABLE__PORT = 3
ICMP4_UNREACHABLE__FAGMENTATION = 4
ICMP4_UNREACHABLE__SOURCE_ROUTE_FAILED = 5
ICMP4_ECHO_REQUEST = 8


class Icmp4Packet:
    """ICMPv4 packet support class"""

    class __not_cached:
        pass

    def __init__(self, packet_rx):
        """Class constructor"""

        packet_rx.icmp4 = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr
        self._plen = packet_rx.ip.dlen

        self.__cksum = self.__not_cached
        self.__ec_id = self.__not_cached
        self.__ec_seq = self.__not_cached
        self.__ec_data = self.__not_cached
        self.__un_data = self.__not_cached
        self.__plen = self.__not_cached
        self.__packet_copy = self.__not_cached

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

    def __str__(self):
        """Packet log string"""

        log = f"ICMPv4 type {self.type}, code {self.code}"

        if self.type == ICMP4_ECHO_REPLY:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        elif self.type == ICMP4_UNREACHABLE and self.code == ICMP4_UNREACHABLE__PORT:
            pass

        elif self.type == ICMP4_ECHO_REQUEST:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        return log

    def __len__(self):
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    @property
    def type(self):
        """Read 'Type' field"""

        return self._frame[self._hptr + 0]

    @property
    def code(self):
        """Read 'Code' field"""

        return self._frame[self._hptr + 1]

    @property
    def cksum(self):
        """Read 'Checksum' field"""

        if self.__cksum is self.__not_cached:
            self.__cksum = struct.unpack_from("!H", self._frame, self._hptr + 2)[0]
        return self.__cksum

    @property
    def ec_id(self):
        """Read Echo 'Id' field"""

        if self.__ec_id is self.__not_cached:
            assert self.type in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}
            self.__ec_id = struct.unpack_from("!H", self._frame, self._hptr + 4)[0]
        return self.__ec_id

    @property
    def ec_seq(self):
        """Read Echo 'Seq' field"""

        if self.__ec_seq is self.__not_cached:
            assert self.type in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}
            self.__ec_seq = struct.unpack_from("!H", self._frame, self._hptr + 6)[0]
        return self.__ec_seq

    @property
    def ec_data(self):
        """Read data carried by Echo message"""

        if self.__ec_data is self.__not_cached:
            assert self.type in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}
            self.__ec_data = self._frame[self._hptr + 8 : self._hptr + self.plen]
        return self.__ec_data

    @property
    def un_data(self):
        """Read data carried by Uneachable message"""

        if self.__un_data is self.__not_cached:
            assert self.type == ICMP4_UNREACHABLE
            self.__un_data = self._frame[self._hptr + 8 : self._hptr + self.plen]
        return self.__un_data

    @property
    def plen(self):
        """Calculate packet length"""

        return self._plen

    @property
    def packet_copy(self):
        """Read the whole packet"""

        if self.__packet_copy is self.__not_cached:
            self.__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self.__packet_copy

    def _packet_integrity_check(self):
        """Packet integrity check to be run on raw frame prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return False

        if inet_cksum(self._frame, self._hptr, self._plen):
            return "ICMPv4 integrity - wrong packet checksum"

        if not ICMP4_HEADER_LEN <= self._plen <= len(self):
            return "ICMPv4 integrity - wrong packet length (I)"

        if self._frame[self._hptr + 0] in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}:
            if not 8 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"

        elif self._frame[self._hptr + 0] == ICMP4_UNREACHABLE:
            if not 12 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"

        return False

    def _packet_sanity_check(self):
        """Packet sanity check to be run on parsed packet to make sure frame's fields contain sane values"""

        if not config.packet_sanity_check:
            return False

        if self.type in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}:
            if not self.code == 0:
                return "ICMPv4 sanity - 'code' should be set to 0 (RFC 792)"

        if self.type == ICMP4_UNREACHABLE:
            if self.code not in {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}:
                return "ICMPv4 sanity - 'code' must be set to [0-15] (RFC 792)"

        return False
