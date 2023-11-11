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
from pytcp.lib.errors import PacketIntegrityError, PacketSanityError
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.ip_helper import inet_cksum
from pytcp.protocols.ip4.ps import (
    IP4_HEADER_LEN,
    Ip4,
    Ip4Option,
    Ip4OptionEol,
    Ip4OptionNop,
    Ip4OptionType,
    Ip4OptionUnknown,
    Ip4Proto,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Ip4IntegrityError(PacketIntegrityError):
    """
    Exception raised when IPv4 packet integrity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[IPv4] " + message)


class Ip4SanityError(PacketSanityError):
    """
    Exception raised when IPv4 packet sanity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[IPv4] " + message)


class Ip4Parser(Ip4):
    """
    IPv4 packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ip = packet_rx.ip4 = self
        packet_rx.frame = packet_rx.frame[self._hlen :]

    def __len__(self) -> int:
        """
        Get number of bytes remaining in the frame.
        """

        return len(self._frame)

    @property
    def header_copy(self) -> bytes:
        """
        Return copy of packet header.
        """

        return self._frame[:IP4_HEADER_LEN]

    @property
    def options_copy(self) -> bytes:
        """
        Return copy of packet options.
        """

        return self._frame[IP4_HEADER_LEN : self.hlen]

    @property
    def data_copy(self) -> bytes:
        """
        Return copy of packet data.
        """

        return self._frame[self.hlen : self.plen]

    @property
    def packet_copy(self) -> bytes:
        """
        Return copy of whole packet.
        """

        return self._frame[: self.plen]

    @property
    def pseudo_header_cksum(self) -> int:
        """
        Create IPv4 pseudo header used by TCP and UDP to compute
        their checksums.
        """
        if "_cache.__pshdr_sum" not in self.__dict__:
            pseudo_header = struct.pack(
                "! 4s 4s BBH",
                bytes(self._src),
                bytes(self._dst),
                0,
                self._proto,
                self._plen - self._hlen,
            )
            self._cache__pshdr_sum = int(
                sum(struct.unpack("! 3L", pseudo_header))
            )
        return self._cache__pshdr_sum

    def _validate_integrity(self) -> None:
        """
        Check integrity of incoming packet prior to parsing it.
        """

        if len(self) < IP4_HEADER_LEN:
            raise Ip4IntegrityError(
                "The wrong packet length (I)",
            )

        hlen = (self._frame[0] & 0b00001111) << 2
        plen: int = struct.unpack("!H", self._frame[2:4])[0]

        if not IP4_HEADER_LEN <= hlen <= plen <= len(self):
            raise Ip4IntegrityError(
                "The wrong packet length (II)",
            )

        # Cannot compute checksum earlier because it depends
        # on integrity of the 'hlen' field.
        if inet_cksum(self._frame[: hlen]):
            raise Ip4IntegrityError(
                "The wrong packet checksum",
            )

        option__ptr = IP4_HEADER_LEN
        while option__ptr < hlen:
            if self._frame[option__ptr] == Ip4OptionType.EOL.value:
                break
            if self._frame[option__ptr] == Ip4OptionType.NOP.value:
                option__ptr += 1
                if option__ptr > hlen:
                    raise Ip4IntegrityError(
                        "The integrity - wrong option length (I)",
                    )
                continue
            if option__ptr + 1 > hlen:
                raise Ip4IntegrityError(
                    "The wrong option length (II)",
                )
            if self._frame[option__ptr + 1] == 0:
                raise Ip4IntegrityError(
                    "The wrong option length (III)",
                )
            option__ptr += self._frame[option__ptr + 1]
            if option__ptr > hlen:
                raise Ip4IntegrityError(
                    "The wrong option length (IV)",
                )

    def _parse(self) -> None:
        """
        Parse IPv4 packet.
        """

        self._ver = self._frame[0] >> 4
        self._hlen = (self._frame[0] & 0b00001111) << 2
        self._dscp = (self._frame[1] & 0b11111100) >> 2
        self._ecn = self._frame[1] & 0b00000011
        self._plen: int = struct.unpack("!H", self._frame[2:4])[0]
        self._id: int = struct.unpack("!H", self._frame[4:6])[0]
        self._flag_df = bool(self._frame[6] & 0b01000000)
        self._flag_mf = bool(self._frame[6] & 0b00100000)
        self._offset: int = (
            struct.unpack("!H", self._frame[6:8])[0] & 0b0001111111111111
        ) << 3
        self._ttl = self._frame[8]
        self._proto = Ip4Proto.from_frame(self._frame)
        self._cksum: int = struct.unpack("!H", self._frame[10:12])[0]
        self._src = Ip4Address(self._frame[12:16])
        self._dst = Ip4Address(self._frame[16:20])

        option__ptr = IP4_HEADER_LEN
        self._options: list[Ip4Option] = []

        while option__ptr < self._hlen:
            match Ip4OptionType.from_frame(self._frame[option__ptr:]):
                case Ip4OptionType.EOL:
                    self._options.append(
                        Ip4OptionEolParser(self._frame[option__ptr:])
                    )
                    break
                case Ip4OptionType.NOP:
                    self._options.append(
                        Ip4OptionNopParser(self._frame[option__ptr:])
                    )
                case _:
                    self._options.append(
                        Ip4OptionUnknownParser(self._frame[option__ptr:])
                    )

            option__ptr += self._options[-1].len

        self._olen = self._hlen - IP4_HEADER_LEN
        self._dlen = self._plen - self._hlen

    def _validate_sanity(self) -> None:
        """
        Check sanity of incoming packet after it has been parsed.
        """

        if self._ver != 4:
            raise Ip4SanityError(
                "Value of the 'ver' field must be set to 4.",
            )

        if self._ver == 0:
            raise Ip4SanityError(
                "Value of the 'ttl' field must be greater than 0",
            )

        if self._src.is_multicast:
            raise Ip4SanityError(
                "Value of the 'src' field must not be a multicast address.",
            )

        if self._src.is_reserved:
            raise Ip4SanityError(
                "Value of the 'src' field must not be a reserved address.",
            )

        if self._src.is_limited_broadcast:
            raise Ip4SanityError(
                "Value of the 'src' field must not be a limited broadcast address.",
            )

        if self._flag_df and self._flag_mf:
            raise Ip4SanityError(
                "Flags 'DF' and 'MF' must not be set simultaneously.",
            )

        if self._flag_df and self._offset != 0:
            raise Ip4SanityError(
                "Value of the 'offset' field must be 0 when 'DF' flag is set.",
            )

        if config.IP4_OPTION_PACKET_DROP and len(self._options) > 0:
            raise Ip4SanityError(
                "The packet must not contain options.",
            )


#
#   IPv4 options
#


class Ip4OptionEolParser(Ip4OptionEol):
    """
    IPv4 EOL option parser.
    """

    def __init__(self, frame: bytes) -> None:
        """
        Option constructor.
        """

        pass


class Ip4OptionNopParser(Ip4OptionNop):
    """
    IPv4 NOP option parser.
    """

    def __init__(self, frame: bytes) -> None:
        """
        Option constructor.
        """

        pass


class Ip4OptionUnknownParser(Ip4OptionUnknown):
    """
    IPv4 unknown option parser.
    """

    def __init__(self, frame: bytes) -> None:
        """
        Option constructor.
        """

        self._type = Ip4OptionType.from_frame(frame)
        self._len = frame[1]
        self._data = frame[2 : self._len]
