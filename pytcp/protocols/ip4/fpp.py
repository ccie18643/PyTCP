#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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

# pylint: disable=attribute-defined-outside-init
# pylint: disable=too-many-instance-attributes
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-public-methods
# pylint: disable=invalid-name

"""
Module contains Fast Packet Parser support class for the IPv4 protocol.

pytcp/protocols/ip4/fpp.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.ip_helper import inet_cksum
from pytcp.protocols.ip4.ps import (
    IP4_HEADER_LEN,
    IP4_OPT_EOL,
    IP4_OPT_EOL_LEN,
    IP4_OPT_NOP,
    IP4_OPT_NOP_LEN,
    IP4_PROTO_TABLE,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Ip4Parser:
    """
    IPv4 packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        packet_rx.ip4 = self
        packet_rx.ip = self

        self._frame = packet_rx.frame

        packet_rx.parse_failed = (
            self._packet_integrity_check() or self._packet_sanity_check()
        )

        if not packet_rx.parse_failed:
            packet_rx.frame = packet_rx.frame[self.hlen :]

    def __len__(self) -> int:
        """
        Number of bytes remaining in the frame.
        """
        return len(self._frame)

    def __str__(self) -> str:
        """
        Packet log string.
        """
        return (
            f"IPv4 {self.src} > {self.dst}, proto {self.proto} "
            f"({IP4_PROTO_TABLE.get(self.proto, '???')}), id {self.id}"
            f"{', DF' if self.flag_df else ''}"
            f"{', MF' if self.flag_mf else ''}, offset {self.offset}, "
            f"plen {self.plen}, ttl {self.ttl}"
        )

    @property
    def ver(self) -> int:
        """
        Read the 'Version' field.
        """
        if "_cache__ver" not in self.__dict__:
            self._cache__ver = self._frame[0] >> 4
        return self._cache__ver

    @property
    def hlen(self) -> int:
        """
        Read the 'Header length' field.
        """
        if "_cache__hlen" not in self.__dict__:
            self._cache__hlen = (self._frame[0] & 0b00001111) << 2
        return self._cache__hlen

    @property
    def dscp(self) -> int:
        """
        Read the 'DSCP' field.
        """
        if "_cache__dscp" not in self.__dict__:
            self._cache__dscp = (self._frame[1] & 0b11111100) >> 2
        return self._cache__dscp

    @property
    def ecn(self) -> int:
        """
        Read the 'ECN' field.
        """
        if "_cache__ecn" not in self.__dict__:
            self._cache__ecn = self._frame[1] & 0b00000011
        return self._cache__ecn

    @property
    def plen(self) -> int:
        """
        Read the 'Packet length' field.
        """
        if "_cache__plen" not in self.__dict__:
            self._cache__plen: int = struct.unpack("!H", self._frame[2:4])[0]
        return self._cache__plen

    @property
    def id(self) -> int:
        """
        Read the 'Identification' field.
        """
        if "_cache__id" not in self.__dict__:
            self._cache__id: int = struct.unpack("!H", self._frame[4:6])[0]
        return self._cache__id

    @property
    def flag_df(self) -> bool:
        """
        Read the 'DF flag' field.
        """
        return bool(self._frame[6] & 0b01000000)

    @property
    def flag_mf(self) -> bool:
        """
        Read the 'MF flag' field.
        """
        return bool(self._frame[6] & 0b00100000)

    @property
    def offset(self) -> int:
        """
        Read the 'Fragment offset' field.
        """
        if "_cache__offset" not in self.__dict__:
            self._cache__offset: int = (
                struct.unpack("!H", self._frame[6:8])[0] & 0b0001111111111111
            ) << 3
        return self._cache__offset

    @property
    def ttl(self) -> int:
        """
        Read the 'TTL' field.
        """
        return self._frame[8]

    @property
    def proto(self) -> int:
        """
        Read 'Protocol' field.
        """
        return self._frame[9]

    @property
    def cksum(self) -> int:
        """
        Read the 'Checksum' field.
        """
        if "_cache__cksum" not in self.__dict__:
            self._cache__cksum: int = struct.unpack("!H", self._frame[10:12])[0]
        return self._cache__cksum

    @property
    def src(self) -> Ip4Address:
        """
        Read the 'Source address' field.
        """
        if "_cache__src" not in self.__dict__:
            self._cache__src = Ip4Address(self._frame[12:16])
        return self._cache__src

    @property
    def dst(self) -> Ip4Address:
        """
        Read the 'Destination address' field.
        """
        if "_cache__dst" not in self.__dict__:
            self._cache__dst = Ip4Address(self._frame[16:20])
        return self._cache__dst

    @property
    def options(self) -> list[Ip4OptEol | Ip4OptNop | Ip4OptUnk]:
        """
        Read list of options.
        """

        if "_cache__options" not in self.__dict__:
            self._cache__options: list = []
            optr = IP4_HEADER_LEN

            while optr < self.hlen:
                if self._frame[optr] == IP4_OPT_EOL:
                    self._cache__options.append(Ip4OptEol())
                    break
                if self._frame[optr] == IP4_OPT_NOP:
                    self._cache__options.append(Ip4OptNop())
                    optr += IP4_OPT_NOP_LEN
                    continue
                # typing: Had to put single mapping (0: lambda _: None)
                # into dict to suppress typng error
                self._cache__options.append(
                    {0: lambda _: None}.get(self._frame[optr], Ip4OptUnk)(
                        self._frame[optr:]
                    )
                )
                optr += self._frame[optr + 1]

        return self._cache__options

    @property
    def olen(self) -> int:
        """
        Calculate options length.
        """
        if "_cache__olen" not in self.__dict__:
            self._cache__olen = self.hlen - IP4_HEADER_LEN
        return self._cache__olen

    @property
    def dlen(self) -> int:
        """
        Calculate data length.
        """
        if "_cache__dlen" not in self.__dict__:
            self._cache__dlen = self.plen - self.hlen
        return self._cache__dlen

    @property
    def header_copy(self) -> bytes:
        """
        Return copy of packet header.
        """
        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = bytes(self._frame[:IP4_HEADER_LEN])
        return self._cache__header_copy

    @property
    def options_copy(self) -> bytes:
        """
        Return copy of packet options.
        """
        if "_cache__options_copy" not in self.__dict__:
            self._cache__options_copy = bytes(
                self._frame[IP4_HEADER_LEN : self.hlen]
            )
        return self._cache__options_copy

    @property
    def data_copy(self) -> bytes:
        """
        Return copy of packet data.
        """
        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = bytes(self._frame[self.hlen : self.plen])
        return self._cache__data_copy

    @property
    def packet_copy(self) -> bytes:
        """
        Return copy of whole packet.
        """
        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = bytes(self._frame[: self.plen])
        return self._cache__packet_copy

    @property
    def pshdr_sum(self) -> int:
        """
        Create IPv4 pseudo header used by TCP and UDP to compute
        their checksums.
        """
        if "_cache.__pshdr_sum" not in self.__dict__:
            pseudo_header = struct.pack(
                "! 4s 4s BBH",
                bytes(self.src),
                bytes(self.dst),
                0,
                self.proto,
                self.plen - self.hlen,
            )
            self._cache__pshdr_sum = int(
                sum(struct.unpack("! 3L", pseudo_header))
            )
        return self._cache__pshdr_sum

    def _packet_integrity_check(self) -> str:
        """
        Packet integrity check to be run on raw packet prior to parsing
        to make sure parsing is safe.
        """

        if not config.PACKET_INTEGRITY_CHECK:
            return ""

        if len(self) < IP4_HEADER_LEN:
            return "IPv4 integrity - wrong packet length (I)"

        if not IP4_HEADER_LEN <= self.hlen <= self.plen <= len(self):
            return "IPv4 integrity - wrong packet length (II)"

        # Cannot compute checksum earlier because it depends
        # on sanity of hlen field
        if inet_cksum(self._frame[: self.hlen]):
            return "IPv4 integriy - wrong packet checksum"

        optr = IP4_HEADER_LEN
        while optr < self.hlen:
            if self._frame[optr] == IP4_OPT_EOL:
                break
            if self._frame[optr] == IP4_OPT_NOP:
                optr += 1
                if optr > self.hlen:
                    return "IPv4 integrity - wrong option length (I)"
                continue
            if optr + 1 > self.hlen:
                return "IPv4 integrity - wrong option length (II)"
            if self._frame[optr + 1] == 0:
                return "IPv4 integrity - wrong option length (III)"
            optr += self._frame[optr + 1]
            if optr > self.hlen:
                return "IPv4 integrity - wrong option length (IV)"

        return ""

    def _packet_sanity_check(self) -> str:
        """
        Packet sanity check to be run on parsed packet to make sure packet's
        fields contain sane values.
        """

        if not config.PACKET_SANITY_CHECK:
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
            return (
                "IP sanity - 'flag_df' and 'flag_mf' must not be set "
                "simultaneously"
            )

        if self.offset and self.flag_df:
            return "IP sanity - 'offset' must be 0 when 'df_flag' is set"

        if self.options and config.IP4_OPTION_PACKET_DROP:
            return "IP sanity - packet must not contain options"

        return ""


#
#   IPv4 options
#


class Ip4OptEol:
    """IPv4 option - End of Ip4Option List"""

    def __init__(self) -> None:
        self.kind = IP4_OPT_EOL

    def __str__(self) -> str:
        """Option log string"""

        return "eol"

    def __len__(self) -> int:
        """Option length"""

        return IP4_OPT_EOL_LEN


class Ip4OptNop:
    """IPv4 option - No Operation"""

    def __init__(self) -> None:
        self.kind = IP4_OPT_NOP

    def __str__(self) -> str:
        """Option log string"""

        return "nop"

    def __len__(self) -> int:
        """Option length"""

        return IP4_OPT_NOP_LEN


class Ip4OptUnk:
    """IPv4 option not supported by this stack"""

    def __init__(self, frame: bytes) -> None:
        self.kind = frame[0]
        self.len = frame[1]
        self.data = frame[2 : self.len]

    def __str__(self) -> str:
        """Option log string"""

        return f"unk-{self.kind}-{self.len}"

    def __len__(self) -> int:
        """Option length"""

        return self.len
