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

# pylint: disable = too-many-instance-attributes
# pylint: disable = attribute-defined-outside-init

"""
Module contains Fast Packet Parser support class for the Ethernet protocol.

pytcp/protocols/ether/fpp.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.ether.ps import (
    ETHER_HEADER_LEN,
    ETHER_TYPE_MIN,
    ETHER_TYPE_TABLE,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class EtherParser:
    """
    Ethernet packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        packet_rx.ether = self

        self._frame = packet_rx.frame

        packet_rx.parse_failed = (
            self._packet_integrity_check() or self._packet_sanity_check()
        )

        if not packet_rx.parse_failed:
            packet_rx.frame = packet_rx.frame[ETHER_HEADER_LEN:]

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
            f"ETHER {self.src} > {self.dst}, 0x{self.type:0>4x} "
            f"({ETHER_TYPE_TABLE.get(self.type, '???')})"
        )

    @property
    def dst(self) -> MacAddress:
        """
        Read the 'Destination MAC address' field.
        """
        if "_cache__dst" not in self.__dict__:
            self._cache__dst = MacAddress(self._frame[0:6])
        return self._cache__dst

    @property
    def src(self) -> MacAddress:
        """
        Read the 'Source MAC address' field.
        """
        if "_cache__src" not in self.__dict__:
            self._cache__src = MacAddress(self._frame[6:12])
        return self._cache__src

    @property
    def type(self) -> int:
        """
        Read the 'EtherType' field.
        """
        if "_cache__type" not in self.__dict__:
            self._cache__type: int = struct.unpack("!H", self._frame[12:14])[0]
        return self._cache__type

    @property
    def header_copy(self) -> bytes:
        """
        Return copy of packet header.
        """
        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = bytes(self._frame[:ETHER_HEADER_LEN])
        return self._cache__header_copy

    @property
    def data_copy(self) -> bytes:
        """
        Return copy of packet data.
        """
        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = bytes(self._frame[ETHER_HEADER_LEN:])
        return self._cache__data_copy

    @property
    def packet_copy(self) -> bytes:
        """
        Return copy of whole packet.
        """
        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = bytes(self._frame[:])
        return self._cache__packet_copy

    @property
    def plen(self) -> int:
        """
        Calculate packet length.
        """
        if "_cache__plen" not in self.__dict__:
            self._cache__plen = len(self)
        return self._cache__plen

    def _packet_integrity_check(self) -> str:
        """
        Packet integrity check to be run on raw packet prior to parsing
        to make sure parsing is safe.
        """
        if not config.PACKET_INTEGRITY_CHECK:
            return ""
        if len(self) < ETHER_HEADER_LEN:
            return "ETHER integrity - wrong packet length (I)"
        return ""

    def _packet_sanity_check(self) -> str:
        """
        Packet sanity check to be run on parsed packet to make sure packet's
        fields contain sane values.
        """
        if not config.PACKET_SANITY_CHECK:
            return ""
        if self.type < ETHER_TYPE_MIN:
            return "ETHER sanity - 'ether_type' must be greater than 0x0600"
        return ""
