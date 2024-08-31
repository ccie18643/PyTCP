#!/usr/bin/env python3

################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the Ethernet 802.3 packet parser class.

pytcp/protocols/ethernet_802_3/ethernet_802_3__parser.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp.lib.proto_parser import ProtoParser
from pytcp.protocols.ethernet_802_3.ethernet_802_3__base import Ethernet8023
from pytcp.protocols.ethernet_802_3.ethernet_802_3__errors import (
    Ethernet8023IntegrityError,
)
from pytcp.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__HEADER__LEN,
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Header,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Ethernet8023Parser(Ethernet8023, ProtoParser):
    """
    The Ethernet 802.3 packet parser.
    """

    _payload: memoryview

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the Ethernet 802.3 packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ethernet_802_3 = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the Ethernet 802.3 packet before parsing it.
        """

        if len(self._frame) < ETHERNET_802_3__HEADER__LEN:
            raise Ethernet8023IntegrityError(
                "The minimum packet length must be "
                f"{ETHERNET_802_3__HEADER__LEN} bytes, got {len(self._frame)} bytes."
            )

        if (dlen := int.from_bytes(self._frame[12:14])) != len(
            self._frame
        ) - ETHERNET_802_3__HEADER__LEN:
            raise Ethernet8023IntegrityError(
                f"Inconsistent payload length ({dlen} bytes) in the Ethernet 802.3 header. "
                f"Frame length is {ETHERNET_802_3__HEADER__LEN} + "
                f"{len(self._frame) - ETHERNET_802_3__HEADER__LEN} bytes."
            )

        if (
            dlen := int.from_bytes(self._frame[12:14])
        ) > ETHERNET_802_3__PAYLOAD__MAX_LEN:
            raise Ethernet8023IntegrityError(
                f"Payload length ({dlen} bytes) exceeds the maximum allowed value "
                f"of {ETHERNET_802_3__PAYLOAD__MAX_LEN} bytes."
            )

    @override
    def _parse(self) -> None:
        """
        Parse the Ethernet 802.3 packet.
        """

        self._header = Ethernet8023Header.from_bytes(self._frame)
        self._payload = self._frame[
            len(self._header) : len(self._header) + self._header.dlen
        ]

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the Ethernet 802.3 packet after parsing it.
        """

        # Currently no sanity checks are implemented for the Ethernet 802.3
        # packet parser.
