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
Module contains the ICMPv6 Destination Unreachable message support class.

pytcp/protocols/icmp6/message/icmp6_message__destination_unreachable.py

ver 3.0.1
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.config import IP6__MIN_MTU
from pytcp.lib.int_checks import is_uint16
from pytcp.protocols.icmp4.icmp4__errors import Icmp4IntegrityError
from pytcp.protocols.icmp6.message.icmp6_message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)
from pytcp.protocols.ip6.ip6__header import (
    IP6__HEADER__LEN,
    IP6__PAYLOAD__MAX_LEN,
)

# The ICMPv6 Destination Unreachable message (1/0-6) [RFC4443].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP6__DESTINATION_UNREACHABLE__LEN = 8
ICMP6__DESTINATION_UNREACHABLE__STRUCT = "! BBH L"

ICMP6_DESTINATION_UNREACHABLE_ORIGINAL_DATAGRAM_LEN = (
    IP6__MIN_MTU - IP6__HEADER__LEN - ICMP6__DESTINATION_UNREACHABLE__LEN
)


class Icmp6DestinationUnreachableCode(Icmp6Code):
    """
    The ICMPv6 Destination Unreachable message 'code' values.
    """

    NO_ROUTE = 0
    PROHIBITED = 1
    SCOPE = 2
    ADDRESS = 3
    PORT = 4
    FAILED_POLICY = 5
    REJECT_ROUTE = 6
    SOURCE_ROUTING_HEADER = 7


@dataclass(frozen=True, kw_only=True)
class Icmp6DestinationUnreachableMessage(Icmp6Message):
    """
    The ICMPv6 Destination Unreachable message base.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.DESTINATION_UNREACHABLE,
    )
    code: Icmp6DestinationUnreachableCode
    cksum: int = 0

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv6 Destination Unreachable message fields.
        """

        assert isinstance(self.code, Icmp6DestinationUnreachableCode), (
            f"The 'code' field must be an Icmp6DestinationUnreachableCode. "
            f"Got: {type(self.code)!r}"
        )

        assert is_uint16(self.cksum), (
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {self.cksum}"
        )

        assert (
            len(self.data)
            <= IP6__PAYLOAD__MAX_LEN - ICMP6__DESTINATION_UNREACHABLE__LEN
        ), (
            "The 'data' field length must be a 16-bit unsigned integer less than or "
            f"equal to {IP6__PAYLOAD__MAX_LEN - ICMP6__DESTINATION_UNREACHABLE__LEN}. "
            f"Got: {len(self.data)}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "data",
            self.data[
                : IP6__MIN_MTU
                - IP6__HEADER__LEN
                - ICMP6__DESTINATION_UNREACHABLE__LEN
            ],
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 Destination Unreachable message length.
        """

        return ICMP6__DESTINATION_UNREACHABLE__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 Destination Unreachable message log string.
        """

        return (
            f"ICMPv6 Destination Unreachable - {self.code}, len {len(self)} "
            f"({ICMP6__DESTINATION_UNREACHABLE__LEN}+{len(self.data)})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 Destination Unreachable message as bytes.
        """

        return (
            struct.pack(
                ICMP6__DESTINATION_UNREACHABLE__STRUCT,
                int(self.type),
                int(self.code),
                0,
                0,
            )
            + self.data
        )

    @override
    @staticmethod
    def validate_integrity(*, frame: bytes, ip6__dlen: int) -> None:
        """
        Validate the ICMPv6 Destination Unreachable message integrity before
        parsing it.
        """

        if not (ICMP6__DESTINATION_UNREACHABLE__LEN <= ip6__dlen <= len(frame)):
            raise Icmp4IntegrityError(
                "The condition 'ICMP6__DESTINATION_UNREACHABLE__LEN <= "
                "ip4__dlen <= len(frame)' must be met. Got: "
                f"{ICMP6__DESTINATION_UNREACHABLE__LEN=}, "
                f"{ip6__dlen=}, {len(frame)=}"
            )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6DestinationUnreachableMessage:
        """
        Initialize the ICMPv6 Destination Unreachable message from bytes.
        """

        type, code, cksum, _ = struct.unpack(
            ICMP6__DESTINATION_UNREACHABLE__STRUCT,
            _bytes[:ICMP6__DESTINATION_UNREACHABLE__LEN],
        )

        assert (received_type := Icmp6Type.from_int(type)) == (
            valid_type := Icmp6Type.DESTINATION_UNREACHABLE
        ), (
            f"The 'type' field must be {valid_type!r}. "
            f"Got: {received_type!r}"
        )

        return Icmp6DestinationUnreachableMessage(
            code=Icmp6DestinationUnreachableCode.from_int(code),
            cksum=cksum,
            data=_bytes[ICMP6__DESTINATION_UNREACHABLE__LEN:],
        )
