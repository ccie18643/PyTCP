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

# pylint: disable = line-too-long
# pylint: disable = too-many-instance-attributes
# pylint: disable = attribute-defined-outside-init

"""
Module contains Fast Packet Parser support class for the ICMPv4 protocol.

pytcp/protocols/icmp4/fpp.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip_helper import inet_cksum
from pytcp.protocols.icmp4.ps import (
    ICMP4_ECHO_REPLY,
    ICMP4_ECHO_REQUEST,
    ICMP4_HEADER_LEN,
    ICMP4_UNREACHABLE,
    ICMP4_UNREACHABLE__PORT,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Icmp4Parser:
    """
    ICMPv4 packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        assert packet_rx.ip4 is not None

        packet_rx.icmp4 = self

        self._frame = packet_rx.frame
        self._plen = packet_rx.ip4.dlen

        packet_rx.parse_failed = (
            self._packet_integrity_check() or self._packet_sanity_check()
        )

    def __len__(self) -> int:
        """
        Number of bytes remaining in the frame.
        """
        return len(self._frame)

    def __str__(self) -> str:
        """
        Packet log string.
        """
        header = f"ICMPv4 {self.type}/{self.code}"

        if self.type == ICMP4_ECHO_REPLY:
            return f"{header} (echo_reply), id {self.ec_id}, seq {self.ec_seq}, dlen {len(self.ec_data)}"

        if (
            self.type == ICMP4_UNREACHABLE
            and self.code == ICMP4_UNREACHABLE__PORT
        ):
            return f"{header} (unreachable_port), dlen {len(self.un_data)}"

        if self.type == ICMP4_ECHO_REQUEST:
            return f"{header} (echo_request), id {self.ec_id}, seq {self.ec_seq}, dlen {len(self.ec_data)}"

        return f"{header} (unknown)"

    @property
    def type(self) -> int:
        """
        Read the 'Type' field.
        """
        return self._frame[0]

    @property
    def code(self) -> int:
        """
        Read the 'Code' field.
        """
        return self._frame[1]

    @property
    def cksum(self) -> int:
        """
        Read the 'Checksum' field.
        """
        if "_cache__cksum" not in self.__dict__:
            self._cache__cksum: int = struct.unpack("!H", self._frame[2:4])[0]
        return self._cache__cksum

    @property
    def ec_id(self) -> int:
        """
        Read the Echo 'Id' field.
        """
        if "_cache__ec_id" not in self.__dict__:
            assert self.type in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}
            self._cache__ec_id: int = struct.unpack("!H", self._frame[4:6])[0]
        return self._cache__ec_id

    @property
    def ec_seq(self) -> int:
        """
        Read the Echo 'Seq' field.
        """
        if "_cache__ec_seq" not in self.__dict__:
            assert self.type in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}
            self._cache__ec_seq: int = struct.unpack("!H", self._frame[6:8])[0]
        return self._cache__ec_seq

    @property
    def ec_data(self) -> bytes:
        """
        Read data carried by the Echo message.
        """
        if "_cache__ec_data" not in self.__dict__:
            assert self.type in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}
            self._cache__ec_data = self._frame[8 : self.plen]
        return self._cache__ec_data

    @property
    def un_data(self) -> bytes:
        """
        Read the data carried by Unreachable message.
        """
        if "_cache__un_data" not in self.__dict__:
            assert self.type == ICMP4_UNREACHABLE
            self._cache__un_data = self._frame[8 : self.plen]
        return self._cache__un_data

    @property
    def plen(self) -> int:
        """
        Calculate packet length.
        """
        return self._plen

    @property
    def packet_copy(self) -> bytes:
        """
        Read the whole packet.
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

        if inet_cksum(self._frame[: self._plen]):
            return "ICMPv4 integrity - wrong packet checksum"

        if not ICMP4_HEADER_LEN <= self._plen <= len(self):
            return "ICMPv4 integrity - wrong packet length (I)"

        if self._frame[0] in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}:
            if not 8 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"

        elif self._frame[0] == ICMP4_UNREACHABLE:
            if not 12 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"

        return ""

    def _packet_sanity_check(self) -> str:
        """
        Packet sanity check to be run on parsed packet to make sure packets's
        fields contain sane values.
        """

        if not config.PACKET_SANITY_CHECK:
            return ""

        if self.type in {ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY}:
            if not self.code == 0:
                return "ICMPv4 sanity - 'code' should be set to 0 (RFC 792)"

        if self.type == ICMP4_UNREACHABLE:
            if self.code not in {
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
            }:
                return "ICMPv4 sanity - 'code' must be set to [0-15] (RFC 792)"

        return ""
