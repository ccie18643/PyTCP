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
Module contains the ICMPv4 Echo Request message support class.

pytcp/protocols/icmp4/message/icmp4_message__echo_request.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint16
from pytcp.protocols.icmp4.icmp4__errors import Icmp4IntegrityError
from pytcp.protocols.icmp4.message.icmp4_message import (
    Icmp4Code,
    Icmp4Message,
    Icmp4Type,
)
from pytcp.protocols.ip4.ip4__header import IP4__PAYLOAD__MAX_LEN

# The ICMPv4 Echo Request message (8/0) [RFC 792].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP4__ECHO_REQUEST__LEN = 8
ICMP4__ECHO_REQUEST__STRUCT = "! BBH HH"


class Icmp4EchoRequestCode(Icmp4Code):
    """
    The ICMPv4 Echo Request 'code' field value.
    """

    DEFAULT = 0


@dataclass(frozen=True, kw_only=True)
class Icmp4EchoRequestMessage(Icmp4Message):
    """
    ICMPv4 Echo Request message.
    """

    type: Icmp4Type = field(
        repr=False,
        init=False,
        default=Icmp4Type.ECHO_REQUEST,
    )
    code: Icmp4EchoRequestCode = Icmp4EchoRequestCode.DEFAULT
    cksum: int = 0

    id: int = 0
    seq: int = 0
    data: bytes = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv4 Echo Request message fields.
        """

        assert isinstance(self.code, Icmp4EchoRequestCode), (
            f"The 'code' field must be an Icmp4EchoRequestCode. "
            f"Got: {type(self.code)!r}"
        )

        assert is_uint16(self.cksum), (
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {self.cksum!r}"
        )

        assert is_uint16(self.id), (
            f"The 'id' field must be a 16-bit unsigned integer. "
            f"Got: {self.id!r}"
        )

        assert is_uint16(self.seq), (
            f"The 'seq' field must be a 16-bit unsigned integer. "
            f"Got: {self.seq!r}"
        )

        assert isinstance(self.data, (bytes, memoryview)), (
            f"The 'data' field must be bytes or memoryview. "
            f"Got: {type(self.data)!r}."
        )

        assert (
            len(self.data) <= IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REQUEST__LEN
        ), (
            f"The 'data' field length must be a 16-bit unsigned integer less than "
            f"or equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REQUEST__LEN}. "
            f"Got: {len(self.data)!r}"
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv4 Echo Request message length.
        """

        return ICMP4__ECHO_REQUEST__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv4 Echo Request message log string.
        """

        return (
            f"ICMPv4 Echo Request, id {self.id}, seq {self.seq}, len {len(self)} "
            f"({ICMP4__ECHO_REQUEST__LEN}+{len(self.data)})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv4 Echo Request message as bytes.
        """

        return struct.pack(
            ICMP4__ECHO_REQUEST__STRUCT,
            int(self.type),
            int(self.code),
            0,
            self.id,
            self.seq,
        ) + bytes(self.data)

    @override
    def validate_sanity(self) -> None:
        """
        Validate the ICMPv4 Echo Request message sanity after parsing it.
        """

        # Currently no sanity checks are implemented.

    @override
    @staticmethod
    def validate_integrity(*, frame: bytes, ip4__payload_len: int) -> None:
        """
        Validate the integrity of the ICMPv4 Echo Request message before parsing it.
        """

        if not (ICMP4__ECHO_REQUEST__LEN <= ip4__payload_len <= len(frame)):
            raise Icmp4IntegrityError(
                "The condition 'ICMP4__ECHO_REQUEST__LEN <= ip4__payload_len <= "
                f"len(frame)' must be met. Got: {ICMP4__ECHO_REQUEST__LEN=}, "
                f"{ip4__payload_len=}, {len(frame)=}"
            )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp4EchoRequestMessage:
        """
        Initialize the ICMPv4 Echo Request message from bytes.
        """

        type, code, cksum, id, seq = struct.unpack(
            ICMP4__ECHO_REQUEST__STRUCT, _bytes[:ICMP4__ECHO_REQUEST__LEN]
        )

        assert (received_type := Icmp4Type.from_int(type)) == (
            valid_type := Icmp4Type.ECHO_REQUEST
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return Icmp4EchoRequestMessage(
            code=Icmp4EchoRequestCode.from_int(code),
            cksum=cksum,
            id=id,
            seq=seq,
            data=_bytes[ICMP4__ECHO_REQUEST__LEN:],
        )
