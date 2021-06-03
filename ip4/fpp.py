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
# ip4/fpp.py - Fast Packet Parser support class for IPv4 protocol
#


import struct

import config
import ip4.ps
from misc.ip_helper import inet_cksum
from misc.ipv4_address import IPv4Address
from misc.packet import PacketRx


class Parser:
    """IPv4 packet parser class"""

    def __init__(self, packet_rx: PacketRx) -> None:
        """Class constructor"""

        packet_rx.ip4 = self
        packet_rx.ip = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr

        packet_rx.parse_failed = self._packet_integrity_check() or self._packet_sanity_check()

        if not packet_rx.parse_failed:
            packet_rx.hptr = self._hptr + self.hlen

    def __len__(self) -> int:
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    from ip4.ps import __str__

    @property
    def ver(self) -> int:
        """Read 'Version' field"""

        if "_cache__ver" not in self.__dict__:
            self._cache__ver = self._frame[self._hptr + 0] >> 4
        return self._cache__ver

    @property
    def hlen(self) -> int:
        """Read 'Header length' field"""

        if "_cache__hlen" not in self.__dict__:
            self._cache__hlen = (self._frame[self._hptr + 0] & 0b00001111) << 2
        return self._cache__hlen

    @property
    def dscp(self) -> int:
        """Read 'DSCP' field"""

        if "_cache__dscp" not in self.__dict__:
            self._cache__dscp = (self._frame[self._hptr + 1] & 0b11111100) >> 2
        return self._cache__dscp

    @property
    def ecn(self) -> int:
        """Read 'ECN' field"""

        if "_cache__ecn" not in self.__dict__:
            self._cache__ecn = self._frame[self._hptr + 1] & 0b00000011
        return self._cache__ecn

    @property
    def plen(self) -> int:
        """Read 'Packet length' field"""

        if "_cache__plen" not in self.__dict__:
            self._cache__plen = struct.unpack_from("!H", self._frame, self._hptr + 2)[0]
        return self._cache__plen

    @property
    def id(self) -> int:
        """Read 'Identification' field"""

        if "_cache__id" not in self.__dict__:
            self._cache__id = struct.unpack_from("!H", self._frame, self._hptr + 4)[0]
        return self._cache__id

    @property
    def flag_df(self) -> bool:
        """Read 'DF flag' field"""

        return bool(self._frame[self._hptr + 6] & 0b01000000)

    @property
    def flag_mf(self) -> bool:
        """Read 'MF flag' field"""

        return bool(self._frame[self._hptr + 6] & 0b00100000)

    @property
    def offset(self) -> int:
        """Read 'Fragment offset' field"""

        if "_cache__offset" not in self.__dict__:
            self._cache__offset = (struct.unpack_from("!H", self._frame, self._hptr + 6)[0] & 0b0001111111111111) << 3
        return self._cache__offset

    @property
    def ttl(self) -> int:
        """Read 'TTL' field"""

        return self._frame[self._hptr + 8]

    @property
    def proto(self) -> int:
        """Read 'Protocol' field"""

        return self._frame[self._hptr + 9]

    @property
    def cksum(self) -> int:
        """Read 'Checksum' field"""

        if "_cache__cksum" not in self.__dict__:
            self._cache__cksum = struct.unpack_from("!H", self._frame, self._hptr + 10)[0]
        return self._cache__cksum

    @property
    def src(self) -> IPv4Address:
        """Read 'Source address' field"""

        if "_cache__src" not in self.__dict__:
            self._cache__src = IPv4Address(self._frame[self._hptr + 12 : self._hptr + 16])
        return self._cache__src

    @property
    def dst(self) -> IPv4Address:
        """Read 'Destination address' field"""

        if "_cache__dst" not in self.__dict__:
            self._cache__dst = IPv4Address(self._frame[self._hptr + 16 : self._hptr + 20])
        return self._cache__dst

    @property
    def options(self) -> list:
        """Read list of options"""

        if "_cache__options" not in self.__dict__:
            self._cache__options: list = []
            optr = self._hptr + ip4.ps.HEADER_LEN

            while optr < self._hptr + self.hlen:
                if self._frame[optr] == ip4.ps.OPT_EOL:
                    self._cache__options.append(OptEol())
                    break
                if self._frame[optr] == ip4.ps.OPT_NOP:
                    self._cache__options.append(OptNop())
                    optr += ip4.ps.OPT_NOP_LEN
                    continue
                # typing: Had to put single mapping (0: lambda _, __: None) into dict to suppress typng error
                self._cache__options.append({0: lambda _, __: None}.get(self._frame[optr], OptUnk)(self._frame, optr))
                optr += self._frame[optr + 1]

        return self._cache__options

    @property
    def olen(self) -> int:
        """Calculate options length"""

        if "_cache__olen" not in self.__dict__:
            self._cache__olen = self.hlen - ip4.ps.HEADER_LEN
        return self._cache__olen

    @property
    def dlen(self) -> int:
        """Calculate data length"""

        if "_cache__dlen" not in self.__dict__:
            self._cache__dlen = self.plen - self.hlen
        return self._cache__dlen

    @property
    def header_copy(self) -> bytes:
        """Return copy of packet header"""

        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = self._frame[self._hptr : self._hptr + ip4.ps.HEADER_LEN]
        return self._cache__header_copy

    @property
    def options_copy(self) -> bytes:
        """Return copy of packet header"""

        if "_cache__options_copy" not in self.__dict__:
            self._cache__options_copy = self._frame[self._hptr + ip4.ps.HEADER_LEN : self._hptr + self.hlen]
        return self._cache__options_copy

    @property
    def data_copy(self) -> bytes:
        """Return copy of packet data"""

        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = self._frame[self._hptr + self.hlen : self._hptr + self.plen]
        return self._cache__data_copy

    @property
    def packet_copy(self) -> bytes:
        """Return copy of whole packet"""

        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self._cache__packet_copy

    @property
    def pshdr_sum(self) -> int:
        """Create IPv4 pseudo header used by TCP and UDP to compute their checksums"""

        if "_cache.__pshdr_sum" not in self.__dict__:
            pseudo_header = struct.pack("! 4s 4s BBH", self.src.packed, self.dst.packed, 0, self.proto, self.plen - self.hlen)
            self._cache__pshdr_sum = sum(struct.unpack("! 3L", pseudo_header))
        return self._cache__pshdr_sum

    def _packet_integrity_check(self) -> str:
        """Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return ""

        if len(self) < ip4.ps.HEADER_LEN:
            return "IPv4 integrity - wrong packet length (I)"

        if not ip4.ps.HEADER_LEN <= self.hlen <= self.plen <= len(self):
            return "IPv4 integrity - wrong packet length (II)"

        # Cannot compute checksum earlier because it depends on sanity of hlen field
        if inet_cksum(self._frame, self._hptr, self.hlen):
            return "IPv4 integriy - wrong packet checksum"

        optr = self._hptr + ip4.ps.HEADER_LEN
        while optr < self._hptr + self.hlen:
            if self._frame[optr] == ip4.ps.OPT_EOL:
                break
            if self._frame[optr] == ip4.ps.OPT_NOP:
                optr += 1
                if optr > self._hptr + self.hlen:
                    return "IPv4 integrity - wrong option length (I)"
                continue
            if optr + 1 > self._hptr + self.hlen:
                return "IPv4 integrity - wrong option length (II)"
            if self._frame[optr + 1] == 0:
                return "IPv4 integrity - wrong option length (III)"
            optr += self._frame[optr + 1]
            if optr > self._hptr + self.hlen:
                return "IPv4 integrity - wrong option length (IV)"

        return ""

    def _packet_sanity_check(self) -> str:
        """Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values"""

        if not config.packet_sanity_check:
            return ""

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

        return ""


#
#   IPv4 options
#


# IPv4 option - End of Option Linst


class OptEol(ip4.ps.OptEol):
    """IPv4 option - End of Option List"""

    def __init__(self) -> None:
        self.kind = ip4.ps.OPT_EOL


# IPv4 option - No Operation (1)


class OptNop(ip4.ps.OptNop):
    """IPv4 option - No Operation"""

    def __init__(self) -> None:
        self.kind = ip4.ps.OPT_NOP


# IPv4 option not supported by this stack


class OptUnk(ip4.ps.OptUnk):
    """IPv4 option not supported by this stack"""

    def __init__(self, frame: bytes, optr: int) -> None:
        self.kind = frame[optr + 0]
        self.len = frame[optr + 1]
        self.data = frame[optr + 2 : optr + self.len]
