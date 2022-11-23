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

# pylint: disable = attribute-defined-outside-init
# pylint: disable = invalid-name

"""
Module contains Fast Packet Parser for the IPv6 fragmentation
extension header.

pytcp/protocols/ip6_ext_frag/fpp.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.protocols.ip6_ext_frag.ps import (
    IP6_EXT_FRAG_HEADER_LEN,
    IP6_EXT_FRAG_NEXT_HEADER_TABLE,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Ip6ExtFragParser:
    """
    IPv6 fragmentation extension header parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        assert packet_rx.ip6 is not None

        packet_rx.ip6_ext_frag = self

        self._frame = packet_rx.frame
        self._plen = packet_rx.ip6.dlen

        packet_rx.parse_failed = (
            self._packet_integrity_check() or self._packet_sanity_check()
        )

        if not packet_rx.parse_failed:
            packet_rx.frame = packet_rx.frame[IP6_EXT_FRAG_HEADER_LEN:]

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
            f"IPv6_FRAG id {self.id}{', MF' if self.flag_mf else ''}, "
            f"offset {self.offset}, next {self.next} "
            f"({IP6_EXT_FRAG_NEXT_HEADER_TABLE.get(self.next, '???')})"
        )

    @property
    def next(self) -> int:
        """
        Read the 'Next' field.
        """
        return self._frame[0]

    @property
    def offset(self) -> int:
        """
        Read the 'Fragment offset' field.
        """
        if "_cache__offset" not in self.__dict__:
            self._cache__offset: int = (
                struct.unpack("!H", self._frame[2:4])[0] & 0b1111111111111000
            )
        return self._cache__offset

    @property
    def flag_mf(self) -> bool:
        """
        Read the 'MF flag' field.
        """
        return bool(self._frame[3] & 0b00000001)

    @property
    def id(self) -> int:
        """
        Read the 'Identification' field.
        """
        if "_cache__id" not in self.__dict__:
            self._cache__id: int = struct.unpack("!L", self._frame[4:8])[0]
        return self._cache__id

    @property
    def hlen(self) -> int:
        """
        Calculate header length.
        """
        return IP6_EXT_FRAG_HEADER_LEN

    @property
    def dlen(self) -> int:
        """
        Calculate data length.
        """
        return self._plen - IP6_EXT_FRAG_HEADER_LEN

    @property
    def plen(self) -> int:
        """
        Calculate packet length.
        """
        return self._plen

    @property
    def header_copy(self) -> bytes:
        """
        Return copy of packet header.
        """
        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = bytes(
                self._frame[:IP6_EXT_FRAG_HEADER_LEN]
            )
        return self._cache__header_copy

    @property
    def data_copy(self) -> bytes:
        """
        Return copy of packet data.
        """
        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = bytes(
                self._frame[IP6_EXT_FRAG_HEADER_LEN : self.plen]
            )
        return self._cache__data_copy

    @property
    def packet_copy(self) -> bytes:
        """
        Return copy of whole packet.
        """
        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = bytes(self._frame[: self.plen])
        return self._cache__packet_copy

    def _packet_integrity_check(self) -> str:
        """
        Packet integrity check to be run on raw packet prior to parsing
        to make sure parsing is safe.
        """

        if not config.PACKET_INTEGRITY_CHECK:
            return ""

        if len(self) < IP6_EXT_FRAG_HEADER_LEN:
            return "IPv4 integrity - wrong packet length (I)"

        return ""

    def _packet_sanity_check(self) -> str:
        """
        Packet sanity check to be run on parsed packet to make sure packet's
        fields contain sane values.
        """

        if not config.PACKET_SANITY_CHECK:
            return ""

        return ""
