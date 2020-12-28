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
# fpp_ip6.py - packet parser IPv6 protocol
#


import struct

import config
from ipv6_address import IPv6Address

# IPv6 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version| Traffic Class |           Flow Label                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Payload Length        |  Next Header  |   Hop Limit   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                         Source Address                        +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                      Destination Address                      +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP6_HEADER_LEN = 40

IP6_NEXT_HEADER_TCP = 6
IP6_NEXT_HEADER_UDP = 17
IP6_NEXT_HEADER_ICMP6 = 58

IP6_NEXT_HEADER_TABLE = {IP6_NEXT_HEADER_TCP: "TCP", IP6_NEXT_HEADER_UDP: "UDP", IP6_NEXT_HEADER_ICMP6: "ICMPv6"}


class Ip6Packet:
    """ IPv6 packet support class """

    class __not_cached:
        pass

    def __init__(self, frame, hptr):
        """ Class constructor """

        self._frame = frame
        self._hptr = hptr

        self.__ver = self.__not_cached
        self.__dscp = self.__not_cached
        self.__ecn = self.__not_cached
        self.__flow = self.__not_cached
        self.__dlen = self.__not_cached
        self.__src = self.__not_cached
        self.__dst = self.__not_cached
        self.__data = self.__not_cached
        self.__plen = self.__not_cached
        self.__packet = self.__not_cached
        self.__pshdr_sum = self.__not_cached

        self.packet_parse_failed = self._packet_integrity_check() or self._packet_sanity_check()
        if self.packet_parse_failed:
            return

        self.dptr = self._hptr + IP6_HEADER_LEN

    def __str__(self):
        """ Packet log string """

        return (
            f"IPv6 {self.src} > {self.dst}, next {self.next} ({IP6_NEXT_HEADER_TABLE.get(self.next, '???')}), flow {self.flow}"
            + f", dlen {self.dlen}, hop {self.hop}"
        )

    def __len__(self):
        """ Number of bytes remaining in the frame """

        return len(self._frame) - self._hptr

    @property
    def ver(self):
        """ Read 'Version' field """

        if self.__ver is self.__not_cached:
            self.__ver = self._frame[self._hptr + 0] >> 4
        return self.__ver

    @property
    def dscp(self):
        """ Read 'DSCP' field """

        if self.__dscp is self.__not_cached:
            self.__dscp = ((self._frame[self._hptr + 0] & 0b00001111) << 2) | ((self._frame[self._hptr + 1] & 0b11000000) >> 6)
        return self.__dscp

    @property
    def ecn(self):
        """ Read 'ECN' field """

        if self.__ecn is self.__not_cached:
            self.__ecn = (self._frame[self._hptr + 1] & 0b00110000) >> 4
        return self.__ecn

    @property
    def flow(self):
        """ Read 'Flow' field """

        if self.__flow is self.__not_cached:
            self.__flow = ((self._frame[self._hptr + 1] & 0b00001111) << 16) | (self._frame[self._hptr + 2] << 8) | self._frame[self._hptr + 3]
        return self.__flow

    @property
    def dlen(self):
        """ Read 'Data length' field """

        if self.__dlen is self.__not_cached:
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

        if self.__src is self.__not_cached:
            self.__src = IPv6Address(self._frame[self._hptr + 8 : self._hptr + 24])
        return self.__src

    @property
    def dst(self):
        """ Read 'Destination address' field """

        if self.__dst is self.__not_cached:
            self.__dst = IPv6Address(self._frame[self._hptr + 24 : self._hptr + 40])
        return self.__dst

    @property
    def data(self):
        """ Read the data packet carries """

        if self.__data is self.__not_cached:
            self.__data = self.__frame[self._hptr + IP6_HEADER_LEN :]
        return self.__data

    @property
    def plen(self):
        """ Calculate packet length """

        if self.__plen is self.__not_cached:
            self.__plen = len(self)
        return self.__plen

    @property
    def packet(self):
        """ Read the whole packet """

        if self.__packet is self.__not_cached:
            self.__packet = self.__frame[self._hptr : self._hptr + IP6_HEADER_LEN + self.dlen]
        return self.__packet

    @property
    def pshdr_sum(self):
        """ Returns IPv6 pseudo header that is used by TCP, UDP and ICMPv6 to compute their checksums """

        if self.__pshdr_sum is self.__not_cached:
            pseudo_header = struct.pack("! 16s 16s L BBBB", self.src.packed, self.dst.packed, self.dlen, 0, 0, 0, self.next)
            self.__pshdr_sum = sum(struct.unpack("! 5Q", pseudo_header))
        return self.__pshdr_sum

    def _packet_integrity_check(self):
        """ Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe """

        if not config.packet_integrity_check:
            return False

        if len(self) < IP6_HEADER_LEN:
            return "IPv6 integrity - wrong packet length (I)"

        if struct.unpack_from("!H", self._frame, self._hptr + 4)[0] != len(self) - IP6_HEADER_LEN:
            return "IPv6 integrity - wrong packet length (II)"

        return False

    def _packet_sanity_check(self):
        """ Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values """

        if not config.packet_sanity_check:
            return False

        if not self.ver == 6:
            return "IPv6 sanity - 'ver' must be 6"

        if self.hop == 0:
            return "IPv6 sanity - 'hop' must not be 0"

        if self.src.is_multicast:
            return "IPv6 sanity - 'src' must not be multicast"

        return False
