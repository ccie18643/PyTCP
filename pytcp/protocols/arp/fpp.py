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

from typing import TYPE_CHECKING

from pytcp.lib.errors import PacketIntegrityError, PacketSanityError
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.proto import ProtoParser
from pytcp.protocols.arp.ps import (
    ARP_HEADER_LEN,
    Arp,
    ArpHardwareLength,
    ArpHardwareType,
    ArpOperation,
    ArpProtocolLength,
    ArpProtocolType,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class ArpIntegrityError(PacketIntegrityError):
    """
    Exception raised when ARP packet integrity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[ARP] " + message)


class ArpSanityError(PacketSanityError):
    """
    Exception raised when ARP packet sanity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[ARP] " + message)


class ArpParser(Arp, ProtoParser):
    """
    ARP packet parser class.
    """

    def __init__(self, /, packet_rx: PacketRx) -> None:
        """
        Create the ARP packet parser object.
        """

        self._frame = packet_rx.frame
        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.arp = self
        packet_rx.frame = packet_rx.frame[ARP_HEADER_LEN:]

    def __len__(self) -> int:
        """
        Get the packet length.
        """

        return len(self._frame)

    def _validate_integrity(self) -> None:
        """
        Validate the packet integrity prior to parsing it.
        """

        if len(self) < ARP_HEADER_LEN:
            raise ArpIntegrityError(
                f"The minimum packet length must be {ARP_HEADER_LEN} "
                f"bytes, got {len(self)} bytes."
            )

    def _parse(self) -> None:
        """
        Parse the packet.
        """

        self._hrtype = ArpHardwareType.from_frame(self._frame)
        self._prtype = ArpProtocolType.from_frame(self._frame)
        self._hrlen = ArpHardwareLength.from_frame(self._frame)
        self._prlen = ArpProtocolLength.from_frame(self._frame)
        self._oper = ArpOperation.from_frame(self._frame)
        self._sha = MacAddress(self._frame[8:14])
        self._spa = Ip4Address(self._frame[14:18])
        self._tha = MacAddress(self._frame[18:24])
        self._tpa = Ip4Address(self._frame[24:28])

    def _validate_sanity(self) -> None:
        """
        Validate the packet sanity after parsing it.
        """

        if self._hrtype.is_unknown:
            raise ArpSanityError(
                "The 'hrtype' field value must be one of "
                f"{ArpHardwareType.get_core_values()}, got '{int(self.hrtype)}'."
            )

        if self._prtype.is_unknown:
            raise ArpSanityError(
                "The 'prtype' field value must be one of "
                f"{ArpProtocolType.get_core_values()}, got '{int(self.prtype)}'."
            )

        if self._hrlen.is_unknown:
            raise ArpSanityError(
                "The 'hrlen' field value must be one of "
                f"{ArpHardwareLength.get_core_values()}, got '{int(self.hrlen)}'."
            )

        if self._prlen.is_unknown:
            raise ArpSanityError(
                "The 'prlen' field value must be one of "
                f"{ArpProtocolLength.get_core_values()}, got '{int(self.prlen)}'."
            )

        if self._oper.is_unknown:
            raise ArpSanityError(
                "The 'oper' field value must be one of "
                f"{ArpOperation.get_core_values()}, got '{int(self.oper)}'."
            )
