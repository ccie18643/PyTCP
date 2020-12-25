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
# fpp_ether.py - Fast Packet Parser support class for Ethernet protocol
#


import struct

import config

# Ethernet packet header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +    Destination MAC Address    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      Source MAC Address       +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           EtherType           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ETHER_HEADER_LEN = 14

ETHER_TYPE_MIN = 0x0600
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IP4 = 0x0800
ETHER_TYPE_IP6 = 0x86DD


ETHER_TYPE_TABLE = {ETHER_TYPE_ARP: "ARP", ETHER_TYPE_IP4: "IPv4", ETHER_TYPE_IP6: "IPv6"}


class EtherPacket:
    """ Ethernet packet support class """

    def __init__(self, frame, hptr=0):
        """ Class constructor """

        self._frame = frame
        self._hptr = hptr

        self.packet_parse_failed = self._packet_integrity_check() or self._packet_sanity_check()
        if self.packet_parse_failed:
            return

        self.dptr = self._hptr + ETHER_HEADER_LEN

    def __str__(self):
        """ Packet log string """

        return f"ETHER {self.src} > {self.dst}, 0x{self.type:0>4x} ({ETHER_TYPE_TABLE.get(self.type, '???')})"

    def __len__(self):
        """ Packet length """

        return len(self._frame) - self._hptr

    @property
    def dst(self):
        """ Read 'Destination MAC address' field """

        if not hasattr(self, "_dst"):
            self._dst = ":".join([f"{_:0>2x}" for _ in self._frame[self._hptr + 0 : self._hptr + 6]])
        return self._dst

    @property
    def src(self):
        """ Read 'Source MAC address' field """

        if not hasattr(self, "_src"):
            self._src = ":".join([f"{_:0>2x}" for _ in self._frame[self._hptr + 6 : self._hptr + 12]])
        return self._src

    @property
    def type(self):
        """ Read 'EtherType' field """

        if not hasattr(self, "_type"):
            self._type = struct.unpack_from("!H", self._frame, self._hptr + 12)[0]
        return self._type

    @property
    def data(self):
        """ Read the data packet carries """

        if not hasattr(self, "_data"):
            self._data = self._frame[self._hptr + ETHER_HEADER_LEN :]
        return self._data

    @property
    def packet(self):
        """ Read the whole packet """

        if not hasattr(self, "_packet"):
            self._packet = self._frame[self._hptr :]
        return self._packet

    @property
    def plen(self):
        """ Calculate packet length """

        if not hasattr(self, "_plen"):
            self._plen = len(self)
        return self._plen

    def _packet_integrity_check(self):
        """ Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe """

        if not config.packet_integrity_check:
            return False

        if len(self) < ETHER_HEADER_LEN:
            return "ETHER integrity - wrong packet length (I)"

        return False

    def _packet_sanity_check(self):
        """ Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values """

        if not config.packet_sanity_check:
            return False

        if self.type < ETHER_TYPE_MIN:
            return "ETHER sanity - 'ether_type' must be greater than 0x0600"

        return False
