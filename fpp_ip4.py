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
# fpp_ip4.py - Fast Packet Parser support class for IPv4 protocol
#


import struct

import config
from ip_helper import inet_cksum
from ipv4_address import IPv4Address

# IPv4 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |   DSCP    |ECN|          Packet length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to live |    Protocol   |         Header checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP4_HEADER_LEN = 20

IP4_PROTO_ICMP4 = 1
IP4_PROTO_TCP = 6
IP4_PROTO_UDP = 17


IP4_PROTO_TABLE = {IP4_PROTO_ICMP4: "ICMPv4", IP4_PROTO_TCP: "TCP", IP4_PROTO_UDP: "UDP"}


class Ip4Packet:
    """IPv4 packet support class"""

    class __not_cached:
        pass

    def __init__(self, packet_rx):
        """Class constructor"""

        packet_rx.ip4 = self
        packet_rx.ip = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr

        self.__ver = self.__not_cached
        self.__hlen = self.__not_cached
        self.__dscp = self.__not_cached
        self.__ecn = self.__not_cached
        self.__plen = self.__not_cached
        self.__id = self.__not_cached
        self.__offset = self.__not_cached
        self.__cksum = self.__not_cached
        self.__src = self.__not_cached
        self.__dst = self.__not_cached
        self.__options = self.__not_cached
        self.__header_copy = self.__not_cached
        self.__options_copy = self.__not_cached
        self.__data_copy = self.__not_cached
        self.__packet_copy = self.__not_cached
        self.__olen = self.__not_cached
        self.__dlen = self.__not_cached
        self.__packet = self.__not_cached
        self.__pshdr_sum = self.__not_cached

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

        if not packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + self.hlen

    def __str__(self):
        """Packet log string"""

        return (
            f"IPv4 {self.src} > {self.dst}, proto {self.proto} ({IP4_PROTO_TABLE.get(self.proto, '???')}), id {self.id}"
            + f"{', DF' if self.flag_df else ''}{', MF' if self.flag_mf else ''}, offset {self.offset}, plen {self.plen}"
            + f", ttl {self.ttl}"
        )

    def __len__(self):
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    @property
    def ver(self):
        """Read 'Version' field"""

        if self.__ver is self.__not_cached:
            self.__ver = self._frame[self._hptr + 0] >> 4
        return self.__ver

    @property
    def hlen(self):
        """Read 'Header length' field"""

        if self.__hlen is self.__not_cached:
            self.__hlen = (self._frame[self._hptr + 0] & 0b00001111) << 2
        return self.__hlen

    @property
    def dscp(self):
        """Read 'DSCP' field"""

        if self.__dscp is self.__not_cached:
            self.__dscp = (self._frame[self._hptr + 1] & 0b11111100) >> 2
        return self.__dscp

    @property
    def ecn(self):
        """Read 'ECN' field"""

        if self.__ecn is self.__not_cached:
            self.__ecn = self._frame[self._hptr + 1] & 0b00000011
        return self.__ecn

    @property
    def plen(self):
        """Read 'Packet length' field"""

        if self.__plen is self.__not_cached:
            self.__plen = struct.unpack_from("!H", self._frame, self._hptr + 2)[0]
        return self.__plen

    @property
    def id(self):
        """Read 'Identification' field"""

        if self.__id is self.__not_cached:
            self.__id = struct.unpack_from("!H", self._frame, self._hptr + 4)[0]
        return self.__id

    @property
    def flag_df(self):
        """Read 'DF flag' field"""

        return self._frame[self._hptr + 6] & 0b01000000

    @property
    def flag_mf(self):
        """Read 'MF flag' field"""

        return self._frame[self._hptr + 6] & 0b00100000

    @property
    def offset(self):
        """Read 'Fragment offset' field"""

        if self.__offset is self.__not_cached:
            self.__offset = (struct.unpack_from("!H", self._frame, self._hptr + 6)[0] & 0b0001111111111111) << 3
        return self.__offset

    @property
    def ttl(self):
        """Read 'TTL' field"""

        return self._frame[self._hptr + 8]

    @property
    def proto(self):
        """Read 'Protocol' field"""

        return self._frame[self._hptr + 9]

    @property
    def cksum(self):
        """Read 'Checksum' field"""

        if self.__cksum is self.__not_cached:
            self.__cksum = struct.unpack_from("!H", self._frame, self._hptr + 10)[0]
        return self.__cksum

    @property
    def src(self):
        """Read 'Source address' field"""

        if self.__src is self.__not_cached:
            self.__src = IPv4Address(self._frame[self._hptr + 12 : self._hptr + 16])
        return self.__src

    @property
    def dst(self):
        """Read 'Destination address' field"""

        if self.__dst is self.__not_cached:
            self.__dst = IPv4Address(self._frame[self._hptr + 16 : self._hptr + 20])
        return self.__dst

    @property
    def options(self):
        """Read list of options"""

        if self.__options is self.__not_cached:
            self.__options = []
            optr = self._hptr + IP4_HEADER_LEN

            while optr < self._hptr + self.hlen:
                if self._frame[optr] == IP4_OPT_EOL:
                    self.__options.append(Ip4OptEol())
                    break
                if self._frame[optr] == IP4_OPT_NOP:
                    self.__options.append(Ip4OptNop())
                    optr += IP4_OPT_NOP_LEN
                    continue
                self.__options.append({}.get(self._frame[optr], Ip4OptUnk)(self._frame, optr))
                optr += self._frame[optr + 1]

        return self.__options

    @property
    def olen(self):
        """Calculate options length"""

        if self.__olen is self.__not_cached:
            self.__olen = self.hlen - IP4_HEADER_LEN
        return self.__olen

    @property
    def dlen(self):
        """Calculate data length"""

        if self.__dlen is self.__not_cached:
            self.__dlen = self.plen - self.hlen
        return self.__dlen

    @property
    def header_copy(self):
        """Return copy of packet header"""

        if self.__header_copy is self.__not_cached:
            self.__header_copy = self._frame[self._hptr : self._hptr + IP4_HEADER_LEN]
        return self.__header_copy

    @property
    def options_copy(self):
        """Return copy of packet header"""

        if self.__options_copy is self.__not_cached:
            self.__options_copy = self._frame[self._hptr + IP4_HEADER_LEN : self._hptr + self.hlen]
        return self.__options_copy

    @property
    def data_copy(self):
        """Return copy of packet data"""

        if self.__data_copy is self.__not_cached:
            self.__data_copy = self._frame[self._hptr + self.hlen : self._hptr + self.plen]
        return self.__data_copy

    @property
    def packet_copy(self):
        """Return copy of whole packet"""

        if self.__packet_copy is self.__not_cached:
            self.__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self.__packet_copy

    @property
    def pshdr_sum(self):
        """Create IPv4 pseudo header used by TCP and UDP to compute their checksums"""

        if self.__pshdr_sum is self.__not_cached:
            pseudo_header = struct.pack("! 4s 4s BBH", self.src.packed, self.dst.packed, 0, self.proto, self.plen - self.hlen)
            self.__pshdr_sum = sum(struct.unpack("! 3L", pseudo_header))
        return self.__pshdr_sum

    def _packet_integrity_check(self):
        """Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return False

        if len(self) < IP4_HEADER_LEN:
            return "IPv4 integrity - wrong packet length (I)"

        hlen = (self._frame[self._hptr + 0] & 0b00001111) << 2
        plen = struct.unpack_from("!H", self._frame, self._hptr + 2)[0]
        if not IP4_HEADER_LEN <= hlen <= plen <= len(self):
            return "IPv4 integrity - wrong packet length (II)"

        # Cannot compute checksum earlier because it depends on sanity of hlen field
        if inet_cksum(self._frame, self._hptr, hlen):
            return "IPv4 integriy - wrong packet checksum"

        optr = self._hptr + IP4_HEADER_LEN
        while optr < self._hptr + hlen:
            if self._frame[optr] == IP4_OPT_EOL:
                break
            if self._frame[optr] == IP4_OPT_NOP:
                optr += 1
                if optr > self._hptr + hlen:
                    return "IPv4 integrity - wrong option length (I)"
                continue
            if optr + 1 > self._hptr + hlen:
                return "IPv4 integrity - wrong option length (II)"
            if self._frame[optr + 1] == 0:
                return "IPv4 integrity - wrong option length (III)"
            optr += self._frame[optr + 1]
            if optr > self._hptr + hlen:
                return "IPv4 integrity - wrong option length (IV)"

        return False

    def _packet_sanity_check(self):
        """Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values"""

        if not config.packet_sanity_check:
            return False

        if self.ver != 4:
            return "IP sanityi - 'ver' must be 4"

        if self.ver == 0:
            return "IP sanity - 'ttl' must be greater than 0"

        if self.src.is_multicast:
            return "IP sanity - 'src' must not be multicast"

        if self.src.is_reserved:
            return "IP sanity - 'src' must not be reserved"

        if self.src.is_limited_broadcast:
            return "IP sanity - 'src' must not be limited broadcast"

        if self.flag_df and self.flag_mf:
            return "IP sanity - 'flag_df' and 'flag_mf' must not be set simultaneously"

        if self.offset and self.flag_df:
            return "IP sanity - 'offset' must be 0 when 'df_flag' is set"

        if self.options and config.ip4_option_packet_drop:
            return "IP sanity - packet must not contain options"

        return False


#
#   IPv4 options
#


# IPv4 option - End of Option Linst

IP4_OPT_EOL = 0
IP4_OPT_EOL_LEN = 1


class Ip4OptEol:
    """IP option - End of Option List"""

    def __init__(self):
        self.kind = IP4_OPT_EOL

    def __str__(self):
        return "eol"


# IPv4 option - No Operation (1)

IP4_OPT_NOP = 1
IP4_OPT_NOP_LEN = 1


class Ip4OptNop:
    """IP option - No Operation"""

    def __init__(self):
        self.kind = IP4_OPT_NOP

    def __str__(self):
        return "nop"


# IPv4 option not supported by this stack


class Ip4OptUnk:
    """IP option not supported by this stack"""

    def __init__(self, frame, optr):
        self.kind = frame[optr + 0]
        self.len = frame[optr + 1]
        self.data = frame[optr + 2 : optr + self.len]

    def __str__(self):
        return f"unk-{self.kind}-{self.len}"
