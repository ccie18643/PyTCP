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
Module contains the ICMPv4 unknown message support class.

pytcp/protocols/icmp4/message/icmp4_message__unknown.py

ver 3.0.1
"""


from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import override

from pytcp.lib.int_checks import is_uint16
from pytcp.protocols.icmp4.message.icmp4_message import (
    ICMP4__HEADER__LEN,
    ICMP4__HEADER__STRUCT,
    Icmp4Code,
    Icmp4Message,
    Icmp4Type,
)


@dataclass(frozen=True, kw_only=True)
class Icmp4UnknownMessage(Icmp4Message):
    """
    The ICMPv4 unknown message support.
    """

    type: Icmp4Type
    code: Icmp4Code
    cksum: int = 0
    raw: bytes = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv4 unknown message fields.
        """

        assert isinstance(self.type, Icmp4Type), (
            f"The 'type' field must be an Icmp4Type. "
            f"Got: {type(self.type)!r}"
        )

        assert isinstance(self.code, Icmp4Code), (
            f"The 'code' field must be an Icmp4Code. "
            f"Got: {type(self.code)!r}"
        )

        assert is_uint16(self.cksum), (
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {self.cksum!r}"
        )

        assert isinstance(
            self.raw, (bytes, memoryview)
        ), f"The 'raw' field must be a bytes or memoryview. Got: {type(self.raw)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv4 unknown message length.
        """

        return ICMP4__HEADER__LEN + len(self.raw)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv4 unknown message log string.
        """

        return (
            f"ICMPv4 Unknown Message, type {int(self.type)}, code {int(self.code)}, "
            f"cksum {self.cksum}, len {len(self)} ({ICMP4__HEADER__LEN}+{len(self.raw)})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv4 unknown message as bytes.
        """

        return (
            struct.pack(
                ICMP4__HEADER__STRUCT,
                int(self.type),
                int(self.code),
                0,
            )
            + self.raw
        )

    @override
    def validate_sanity(self) -> None:
        """
        Validate the ICMPv4 unknown message sanity after parsing it.
        """

        # Currently no sanity checks are implemented.

    @override
    @staticmethod
    def validate_integrity(*, frame: bytes, ip4__payload_len: int) -> None:
        """
        Validate integrity of the ICMPv4 unknown message before parsing it.
        """

        # Currently no integrity checks are implemented.

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp4UnknownMessage:
        """
        Initialize the ICMPv4 unknown message from bytes.
        """

        type, code, cksum = struct.unpack(
            ICMP4__HEADER__STRUCT, _bytes[:ICMP4__HEADER__LEN]
        )

        return Icmp4UnknownMessage(
            type=Icmp4Type.from_int(type),
            code=Icmp4Code.from_int(code),
            cksum=cksum,
            raw=_bytes[ICMP4__HEADER__LEN:],
        )
