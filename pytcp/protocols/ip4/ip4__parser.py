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
This module contains the IPv4 protocol parser.

pytcp/protocols/ip4/ip4__parser.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.proto_parser import ProtoParser
from pytcp.protocols.ip4.ip4__base import Ip4
from pytcp.protocols.ip4.ip4__errors import Ip4IntegrityError, Ip4SanityError
from pytcp.protocols.ip4.ip4__header import IP4__HEADER__LEN, Ip4Header
from pytcp.protocols.ip4.options.ip4_options import Ip4Options

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Ip4Parser(Ip4, ProtoParser):
    """
    The IPv4 packet parser.
    """

    _payload: memoryview

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the IPv4 packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ip = packet_rx.ip4 = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the IPv4 packet before parsing it.
        """

        if len(self._frame) < IP4__HEADER__LEN:
            raise Ip4IntegrityError(
                "The wrong packet length (I).",
            )

        if self._frame[0] >> 4 != 4:
            raise Ip4IntegrityError(
                "Value of the 'ver' field must be set to 4.",
            )

        hlen = (self._frame[0] & 0b00001111) << 2
        plen = int.from_bytes(self._frame[2:4])

        if not IP4__HEADER__LEN <= hlen <= plen <= len(self._frame):
            raise Ip4IntegrityError(
                "The wrong packet length (II).",
            )

        if inet_cksum(self._frame[:hlen]):
            raise Ip4IntegrityError(
                "The wrong packet checksum.",
            )

        Ip4Options.validate_integrity(frame=self._frame, hlen=hlen)

    @override
    def _parse(self) -> None:
        """
        Parse the IPv4 packet.
        """

        self._header = Ip4Header.from_bytes(self._frame)

        self._options = Ip4Options.from_bytes(
            self._frame[len(self._header) : self._header.hlen]
        )

        self._payload = self._frame[self._header.hlen : self._header.plen]

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the IPv4 packet after parsing it.
        """

        if self._header.ttl == 0:
            raise Ip4SanityError(
                "Value of the 'ttl' field must be greater than 0.",
            )

        if self._header.src.is_multicast:
            raise Ip4SanityError(
                "Value of the 'src' field must not be a multicast address.",
            )

        if self._header.src.is_reserved:
            raise Ip4SanityError(
                "Value of the 'src' field must not be a reserved address.",
            )

        if self._header.src.is_limited_broadcast:
            raise Ip4SanityError(
                "Value of the 'src' field must not be a limited broadcast address.",
            )

        if self._header.flag_df and self._header.flag_mf:
            raise Ip4SanityError(
                "Flags 'DF' and 'MF' must not be set simultaneously.",
            )

        if self._header.flag_df and self._header.offset != 0:
            raise Ip4SanityError(
                "Value of the 'offset' field must be 0 when 'DF' flag is set.",
            )

    @property
    def header_bytes(self) -> bytes:
        """
        Get the IPv4 packet header bytes.
        """

        return self._frame[: len(self._header)]

    @property
    def payload_bytes(self) -> bytes:
        """
        Get the IPv4 packet payload bytes.
        """

        return self._payload

    @property
    def packet_bytes(self) -> bytes:
        """
        Get the whole IPv4 packet bytes.
        """

        return self._frame[
            : len(self._header) + len(self._options) + len(self._payload)
        ]
