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
This module contains the Ethernet II packet parser class.

pytcp/protocols/ethernet/ethernet__parser.py

ver 3.0.3
"""


from typing import override

from pytcp.lib.packet_rx import PacketRx
from pytcp.lib.proto_parser import ProtoParser
from pytcp.protocols.ethernet.ethernet__base import Ethernet
from pytcp.protocols.ethernet.ethernet__errors import (
    EthernetIntegrityError,
    EthernetSanityError,
)
from pytcp.protocols.ethernet.ethernet__header import (
    ETHERNET__HEADER__LEN,
    EthernetHeader,
)


class EthernetParser(Ethernet[memoryview], ProtoParser):
    """
    The Ethernet packet parser.
    """

    _payload: memoryview

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the Ethernet packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ethernet = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the Ethernet packet before parsing it.
        """

        if len(self._frame) < ETHERNET__HEADER__LEN:
            raise EthernetIntegrityError(
                "The minimum packet length must be "
                f"{ETHERNET__HEADER__LEN} bytes, got {len(self._frame)} bytes."
            )

    @override
    def _parse(self) -> None:
        """
        Parse the Ethernet packet.
        """

        self._header = EthernetHeader.from_bytes(self._frame)
        self._payload = self._frame[len(self._header) :]

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the Ethernet packet after parsing it.
        """

        if int(self._header.type) < 0x0600:
            raise EthernetSanityError(
                f"The minimum 'type' field value must be 0x0600, got 0x{int(self._header.type):04x}."
            )
