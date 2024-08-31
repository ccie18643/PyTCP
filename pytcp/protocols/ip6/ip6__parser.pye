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
This module contains the IPv6 packet parser.

pytcp/protocols/ip6/ip6__parser.py

ver 3.0.0
"""


from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp.lib.proto_parser import ProtoParser
from pytcp.protocols.ip6.ip6__base import Ip6
from pytcp.protocols.ip6.ip6__errors import Ip6IntegrityError, Ip6SanityError
from pytcp.protocols.ip6.ip6__header import IP6__HEADER__LEN, Ip6Header

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Ip6Parser(Ip6, ProtoParser):
    """
    The IPv6 packet parser
    """

    _payload: memoryview

    def __init__(self, *, packet_rx: PacketRx) -> None:
        """
        Initialize the IPv6 packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ip = packet_rx.ip6 = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the IPv6 packet before parsing it.
        """

        if len(self._frame) < IP6__HEADER__LEN:
            raise Ip6IntegrityError(
                "The wrong packet length (I).",
            )

        if self._frame[0] >> 4 != 6:
            raise Ip6IntegrityError(
                "The 'ver' must be 6.",
            )

        if (
            int.from_bytes(self._frame[4:6])
            != len(self._frame) - IP6__HEADER__LEN
        ):
            raise Ip6IntegrityError(
                "The wrong packet length (II).",
            )

    @override
    def _parse(self) -> None:
        """
        Parse the IPv6 packet.
        """

        self._header = Ip6Header.from_bytes(self._frame)
        self._payload = self._frame[
            len(self._header) : len(self._header) + self._header.dlen
        ]

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the IPv6 packet after parsing it.
        """

        if self.hop == 0:
            raise Ip6SanityError(
                "The 'hop' must not be 0.",
            )

        if self.src.is_multicast:
            raise Ip6SanityError(
                "The 'src' must not be multicast.",
            )

    @property
    def header_bytes(self) -> bytes:
        """
        Get the IPv6 packet header bytes.
        """

        return bytes(self._frame[: len(self._header)])

    @property
    def payload_bytes(self) -> bytes:
        """
        Get the IPv6 packet payload bytes.
        """

        return bytes(self._payload)

    @property
    def packet_bytes(self) -> bytes:
        """
        Get the IPv6 packet bytes.
        """

        return bytes(self._frame[: len(self._header) + self._header.dlen])
