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
# pylint: disable = too-many-instance-attributes

"""
Module contains Fast Packet Parser support class for UDP protocol.

protocols/udp/fpp.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip_helper import inet_cksum
from pytcp.protocols.udp.ps import UDP_HEADER_LEN

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class UdpParser:
    """
    UDP packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        assert packet_rx.ip is not None

        packet_rx.udp = self

        self._frame = packet_rx.frame
        self._plen = packet_rx.ip.dlen

        packet_rx.parse_failed = (
            self._packet_integrity_check(packet_rx.ip.pshdr_sum)
            or self._packet_sanity_check()
        )

        if not packet_rx.parse_failed:
            packet_rx.frame = packet_rx.frame[UDP_HEADER_LEN:]

    def __len__(self) -> int:
        """
        Number of bytes remaining in the frame.
        """
        return len(self._frame)

    def __str__(self) -> str:
        """
        Packet log string.
        """
        return f"UDP {self.sport} > {self.dport}, len {self.plen}"

    @property
    def sport(self) -> int:
        """
        Read the 'Source port' field.
        """
        if "_cache__sport" not in self.__dict__:
            self._cache__sport: int = struct.unpack("!H", self._frame[0:2])[0]
        return self._cache__sport

    @property
    def dport(self) -> int:
        """
        Read the 'Destination port' field.
        """
        if "_cache__dport" not in self.__dict__:
            self._cache__dport: int = struct.unpack("!H", self._frame[2:4])[0]
        return self._cache__dport

    @property
    def plen(self) -> int:
        """
        Read the 'Packet length' field.
        """
        if "_cache__plen" not in self.__dict__:
            self._cache__plen: int = struct.unpack("!H", self._frame[4:6])[0]
        return self._cache__plen

    @property
    def cksum(self) -> int:
        """
        Read the 'Checksum' field.
        """
        if "_cache__cksum" not in self.__dict__:
            self._cache__cksum: int = struct.unpack("!H", self._frame[6:8])[0]
        return self._cache__cksum

    @property
    def data(self) -> memoryview:
        """
        Read the data packet carries.
        """
        if "_cache__data" not in self.__dict__:
            self._cache__data = self._frame[UDP_HEADER_LEN : self.plen]
        return self._cache__data

    @property
    def dlen(self) -> int:
        """
        Calculate data length.
        """
        return self.plen - UDP_HEADER_LEN

    @property
    def header_copy(self) -> bytes:
        """
        Return copy of packet header.
        """
        if "_cache__header_copy" not in self.__dict__:
            self._cache__header_copy = bytes(self._frame[:UDP_HEADER_LEN])
        return self._cache__header_copy

    @property
    def data_copy(self) -> bytes:
        """
        Return copy of packet data.
        """
        if "_cache__data_copy" not in self.__dict__:
            self._cache__data_copy = bytes(
                self._frame[UDP_HEADER_LEN : self.plen - UDP_HEADER_LEN]
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

    def _packet_integrity_check(self, pshdr_sum: int) -> str:
        """
        Packet integrity check to be run on raw frame prior to parsing
        to make sure parsing is safe.
        """

        if not config.PACKET_INTEGRITY_CHECK:
            return ""

        if inet_cksum(self._frame[: self._plen], pshdr_sum):
            return "UDP integrity - wrong packet checksum"

        if not UDP_HEADER_LEN <= self._plen <= len(self):
            return "UDP integrity - wrong packet length (I)"

        plen = struct.unpack("!H", self._frame[4:6])[0]
        if not UDP_HEADER_LEN <= plen == self._plen <= len(self):
            return "UDP integrity - wrong packet length (II)"

        return ""

    def _packet_sanity_check(self) -> str:
        """
        Packet sanity check to be run on parsed packet to make sure packet's
        fields contain sane values.
        """

        if not config.PACKET_SANITY_CHECK:
            return ""

        if self.sport == 0:
            return "UDP sanity - 'udp_sport' must be greater than 0"

        if self.dport == 0:
            return "UDP sanity - 'udp_dport' must be greater then 0"

        return ""
