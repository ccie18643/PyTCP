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
Module contains the ICMPv6 unknown message support class.

pytcp/protocols/icmp6/message/icmp6_message__unknown.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, override

from pytcp.lib.int_checks import is_uint16
from pytcp.protocols.icmp6.message.icmp6_message import (
    ICMP6__HEADER__LEN,
    ICMP6__HEADER__STRUCT,
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)

if TYPE_CHECKING:
    from pytcp.lib.ip6_address import Ip6Address


@dataclass(frozen=True, kw_only=True)
class Icmp6UnknownMessage(Icmp6Message):
    """
    The ICMPv6 unknown message support.
    """

    type: Icmp6Type
    code: Icmp6Code
    cksum: int = 0
    raw: bytes = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv6 unknown message fields.
        """

        assert isinstance(self.type, Icmp6Type), (
            f"The 'type' field must be an Icmp6Type. "
            f"Got: {type(self.type)!r}"
        )

        assert isinstance(self.code, Icmp6Code), (
            f"The 'code' field must be an Icmp6Code. "
            f"Got: {type(self.code)!r}"
        )

        assert is_uint16(self.cksum), (
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {self.cksum!r}"
        )

        assert isinstance(self.raw, (bytes, memoryview)), (
            f"The 'raw' field must be a bytes or memoryview. "
            f"Got: {type(self.raw)!r}"
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 unknown message length.
        """

        return ICMP6__HEADER__LEN + len(self.raw)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 unknown message log string.
        """

        return (
            f"ICMPv6 Unknown Message, type {int(self.type)}, "
            f"code {int(self.code)}, cksum {self.cksum}, "
            f"len {len(self)} ({ICMP6__HEADER__LEN}+{len(self.raw)})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 unknown message as bytes.
        """

        return (
            struct.pack(
                ICMP6__HEADER__STRUCT,
                int(self.type),
                int(self.code),
                0,
            )
            + self.raw
        )

    @override
    def validate_sanity(
        self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address
    ) -> None:
        """
        Validate the ICMPv6 unknown message sanity after parsing it.
        """

        # Currently no sanity checks are implemented.

    @override
    @staticmethod
    def validate_integrity(*, frame: bytes, ip6__dlen: int) -> None:
        """
        Validate integrity of the ICMPv6 unknown message before parsing it.
        """

        # Currently no integrity checks are implemented.

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6UnknownMessage:
        """
        Initialize the ICMPv6 unknown message from bytes.
        """

        type, code, cksum = struct.unpack(
            ICMP6__HEADER__STRUCT, _bytes[:ICMP6__HEADER__LEN]
        )

        assert (received_type := type) not in Icmp6Type.get_known_values(), (
            "The 'type' field must not be known. "
            f"Got: {Icmp6Type.from_int(received_type)!r}"
        )

        return Icmp6UnknownMessage(
            type=Icmp6Type.from_int(type),
            code=Icmp6Code.from_int(code),
            cksum=cksum,
            raw=_bytes[ICMP6__HEADER__LEN:],
        )
