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
This module contains the IPv6 Ext Frag packet parser class.

pytcp/protocols/ip6_ext_frag/ip6_ext_frag__parser.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp.lib.proto_parser import ProtoParser
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__base import Ip6ExtFrag
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__errors import (
    Ip6ExtFragIntegrityError,
)
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__header import (
    IP6_EXT_FRAG__HEADER__LEN,
    Ip6ExtFragHeader,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Ip6ExtFragParser(Ip6ExtFrag, ProtoParser):
    """
    IPv6 Ext Frag packet parser.
    """

    _payload: memoryview

    def __init__(self, *, packet_rx: PacketRx) -> None:
        """
        Initialize the IPv6 Ext Frag packet parser.
        """

        self._frame = packet_rx.frame
        self._ip6__dlen = packet_rx.ip6.dlen

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ip6_ext_frag = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the IPv6 Ext Frag packet before parsing it.
        """

        if len(self._frame) < IP6_EXT_FRAG__HEADER__LEN:
            raise Ip6ExtFragIntegrityError(
                "The wrong packet length (I).",
            )

    @override
    def _parse(self) -> None:
        """
        Parse the IPv6 Ext Frag packet.
        """

        self._header = Ip6ExtFragHeader.from_bytes(self._frame)
        self._payload = self._frame[
            len(self._header) : len(self._header) + self._ip6__dlen
        ]

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the IPv6 Ext Frag packet after parsing it.
        """

        # Currently no sanity checks are implemented for the IPv6 Ext Frag protocol.

    @property
    def header_bytes(self) -> bytes:
        """
        Get the IPv6 Ext Frag packet header bytes.
        """

        return bytes(self._frame[: len(self._header)])

    @property
    def payload_bytes(self) -> bytes:
        """
        Get the IPv6 Ext Frag packet payload bytes.
        """

        return bytes(self._payload)

    @property
    def packet_bytes(self) -> bytes:
        """
        Get the IPv6 Ext Frag packet bytes.
        """

        return bytes(self._frame[: len(self._header) + len(self._payload)])
