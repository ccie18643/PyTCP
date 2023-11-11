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

pytcp/protocols/ethernet/fpp.py

ver 2.7
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp.lib.errors import PacketIntegrityError, PacketSanityError
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.proto import ProtoParser
from pytcp.protocols.ethernet.ps import (
    ETHERNET_HEADER_LEN,
    Ethernet,
    EthernetType,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class EthernetIntegrityError(PacketIntegrityError):
    """
    Exception raised when Ethernet packet integrity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[ETHER] " + message)


class EthernetSanityError(PacketSanityError):
    """
    Exception raised when Ethernet packet sanity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[ETHER] " + message)


class EthernetParser(Ethernet, ProtoParser):
    """
    Ethernet packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Class constructor.
        """

        self._frame = packet_rx.frame
        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ethernet = self
        packet_rx.frame = packet_rx.frame[ETHERNET_HEADER_LEN:]

    def __len__(self) -> int:
        """
        Get number of bytes remaining in the frame.
        """
        return len(self._frame)

    def _validate_integrity(self) -> None:
        """
        Validate the packet integrity prior to parsing it.
        """

        if len(self) < ETHERNET_HEADER_LEN:
            raise EthernetIntegrityError(
                "The minimum packet length must be "
                f"'{ETHERNET_HEADER_LEN}' bytes, got {len(self)} bytes."
            )

    def _parse(self) -> None:
        """
        Parse the packet.
        """

        self._dst = MacAddress(self._frame[0:6])
        self._src = MacAddress(self._frame[6:12])
        self._type = EthernetType.from_frame(self._frame)

    def _validate_sanity(self) -> None:
        """
        Validate the packet sanity after parsing it.
        """

        # TODO: Add more sanity checks.
