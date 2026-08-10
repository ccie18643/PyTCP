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
This module contains the IPv6 Frag packet parser class.

net_proto/protocols/ip6_frag/ip6_frag__parser.py

ver 3.0.10
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.ip6_frag.ip6_frag__base import Ip6Frag
from net_proto.protocols.ip6_frag.ip6_frag__errors import (
    Ip6FragIntegrityError,
    Ip6FragSanityError,
)
from net_proto.protocols.ip6_frag.ip6_frag__header import (
    IP6_FRAG__HEADER__LEN,
    Ip6FragHeader,
)


class Ip6FragParser(Ip6Frag, ProtoParser):
    """
    The IPv6 Frag packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the IPv6 Frag packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ip6_frag = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the IPv6 Frag packet before parsing it.
        """

        # RFC 8200 §4.5 — the Fragment header is a fixed 8 octets
        # (Next Header / Reserved / Fragment Offset+M / Identification);
        # anything shorter cannot be parsed.
        if len(self._frame) < IP6_FRAG__HEADER__LEN:
            raise Ip6FragIntegrityError(
                "The condition 'IP6_FRAG__HEADER__LEN <= len(self._frame)' must be met. "
                f"Got: {IP6_FRAG__HEADER__LEN=}, {len(self._frame)=}",
            )

    @override
    def _parse(self) -> None:
        """
        Parse the IPv6 Frag packet.
        """

        self._header = Ip6FragHeader.from_buffer(self._frame)
        self._payload = self._frame[len(self._header) :]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the IPv6 Frag packet after parsing it.

        Reference: RFC 8200 §4.5 (non-final fragment payload length
        MUST be a multiple of 8 octets; receiver discards otherwise).
        """

        if self._header.flag_mf and (value := len(self._payload)) % 8 != 0:
            raise Ip6FragSanityError(
                "Non-final fragment payload length must be a multiple of 8. "
                f"Got: len(self._payload)={value}, "
                f"self._header.flag_mf={self._header.flag_mf}",
            )

    @property
    def header_bytes(self) -> Buffer:
        """
        Get the IPv6 Frag packet header bytes.
        """

        return self._frame[: len(self._header)]

    @property
    def payload_bytes(self) -> Buffer:
        """
        Get the IPv6 Frag packet payload bytes.
        """

        return self._payload

    @property
    def packet_bytes(self) -> Buffer:
        """
        Get the IPv6 Frag packet bytes.
        """

        return self._frame[: len(self._header) + len(self._payload)]
