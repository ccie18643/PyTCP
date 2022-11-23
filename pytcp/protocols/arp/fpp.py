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
# pylint: disable = too-many-return-statements
# pylint: disable = attribute-defined-outside-init

"""
Module contains Fast Packet Parser support class for the ARP protocol.

pytcp/protocols/arp/fpp.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.arp.ps import ARP_HEADER_LEN, ARP_OP_REPLY, ARP_OP_REQUEST

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class ArpParser:
    """
    ARP packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        packet_rx.arp = self

        self._frame = packet_rx.frame

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
        if self.oper == ARP_OP_REQUEST:
            return (
                f"ARP request {self.spa} / {self.sha}"
                f" > {self.tpa} / {self.tha}"
            )
        if self.oper == ARP_OP_REPLY:
            return (
                f"ARP reply {self.spa} / {self.sha}"
                f" > {self.tpa} / {self.tha}"
            )
        return f"ARP request unknown operation {self.oper}"

    @property
    def hrtype(self) -> int:
        """
        Read the 'Hardware address type' field.
        """
        if "_cache__hrtype" not in self.__dict__:
            self._cache__hrtype: int = struct.unpack("!H", self._frame[0:2])[0]
        return self._cache__hrtype

    @property
    def prtype(self) -> int:
        """
        Read the 'Protocol address type' field.
        """
        if "_cache__prtype" not in self.__dict__:
            self._cache__prtype: int = struct.unpack("!H", self._frame[2:4])[0]
        return self._cache__prtype

    @property
    def hrlen(self) -> int:
        """
        Read the 'Hardware address length' field.
        """
        return self._frame[4]

    @property
    def prlen(self) -> int:
        """
        Read the 'Protocol address length' field.
        """
        return self._frame[5]

    @property
    def oper(self) -> int:
        """
        Read the 'Operation' field.
        """
        if "_cache__oper" not in self.__dict__:
            self._cache__oper: int = struct.unpack("!H", self._frame[6:8])[0]
        return self._cache__oper

    @property
    def sha(self) -> MacAddress:
        """
        Read the 'Sender hardware address' field.
        """
        if "_cache__sha" not in self.__dict__:
            self._cache__sha = MacAddress(self._frame[8:14])
        return self._cache__sha

    @property
    def spa(self) -> Ip4Address:
        """
        Read the 'Sender protocol address' field.
        """
        if "_cache__spa" not in self.__dict__:
            self._cache__spa = Ip4Address(self._frame[14:18])
        return self._cache__spa

    @property
    def tha(self) -> MacAddress:
        """
        Read the 'Target hardware address' field.
        """
        if "_cache__tha" not in self.__dict__:
            self._cache__tha = MacAddress(self._frame[18:24])
        return self._cache__tha

    @property
    def tpa(self) -> Ip4Address:
        """
        Read the 'Target protocol address' field.
        """
        if "_cache__tpa" not in self.__dict__:
            self._cache__tpa = Ip4Address(self._frame[24:28])
        return self._cache__tpa

    @property
    def packet_copy(self) -> bytes:
        """
        Read the whole packet.
        """
        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = bytes(self._frame[:ARP_HEADER_LEN])
        return self._cache__packet_copy

    def _packet_integrity_check(self) -> str:
        """
        Packet integrity check to be run on raw packet prior to parsing
        to make sure parsing is safe
        """

        if not config.PACKET_INTEGRITY_CHECK:
            return ""

        if len(self) < ARP_HEADER_LEN:
            return "ARP integrity - wrong packet length (I)"

        return ""

    def _packet_sanity_check(self) -> str:
        """
        Packet sanity check to be run on parsed packet to make sure packet's
        fields contain sane values
        """

        if not config.PACKET_SANITY_CHECK:
            return ""

        if self.hrtype != 1:
            return "ARP sanity - 'arp_hrtype' must be 1"

        if self.prtype != 0x0800:
            return "ARP sanity - 'arp_prtype' must be 0x0800"

        if self.hrlen != 6:
            return "ARP sanity - 'arp_hrlen' must be 6"

        if self.prlen != 4:
            return "ARP sanity - 'arp_prlen' must be 4"

        if self.oper not in {1, 2}:
            return "ARP sanity - 'oper' must be [1-2]"

        return ""
