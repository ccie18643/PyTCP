#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains the ICMPv6 Echo Reply message support class.

pytcp/protocols/icmp6/message/icmp6_message__echo_request.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint16
from pytcp.protocols.icmp6.message.icmp6_message import (
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)
from pytcp.protocols.ip6.ip6__header import IP6__PAYLOAD__MAX_LEN

# The 'Echo Request' message (128/0) [RFC4443].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ECHO_REQUEST__LEN = 8
ICMP6__ECHO_REQUEST__STRUCT = "! BBH HH"


class Icmp6EchoRequestCode(Icmp6Code):
    """
    The ICMPv6 Echo Request message 'code' values.
    """

    DEFAULT = 0


@dataclass(frozen=True, kw_only=True)
class Icmp6EchoRequestMessage(Icmp6Message):
    """
    The ICMPv6 Echo Request message.
    """

    type: Icmp6Type = field(
        repr=False,
        init=False,
        default=Icmp6Type.ECHO_REQUEST,
    )
    code: Icmp6EchoRequestCode = Icmp6EchoRequestCode.DEFAULT
    cksum: int = 0

    id: int
    seq: int
    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv6 Echo Request message fields.
        """

        assert isinstance(
            self.code, Icmp6EchoRequestCode
        ), f"The 'code' field must be an Icmp6EchoRequestCode. Got: {type(self.code)!r}"

        assert is_uint16(
            self.cksum
        ), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert is_uint16(
            self.id
        ), f"The 'id' field must be a 16-bit unsigned integer. Got: {self.id!r}"

        assert is_uint16(
            self.seq
        ), f"The 'seq' field must be a 16-bit unsigned integer. Got: {self.seq!r}"

        assert isinstance(
            self.data, (bytes, memoryview)
        ), f"The 'data' field must be bytes or memoryview. Got: {type(self.data)!r}"

        assert (
            len(self.data) <= IP6__PAYLOAD__MAX_LEN - ICMP6__ECHO_REQUEST__LEN
        ), (
            f"The 'data' field length must be a 16-bit unsigned integer less than or equal "
            f"to {IP6__PAYLOAD__MAX_LEN - ICMP6__ECHO_REQUEST__LEN}. Got: {len(self.data)!r}"
        )

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 Echo Request message length.
        """

        return ICMP6__ECHO_REQUEST__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 Echo Request message log string.
        """

        return (
            f"ICMPv6 Echo Request, id {self.id}, seq {self.seq}, len {len(self)} "
            f"({ICMP6__ECHO_REQUEST__LEN}+{len(self.data)})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 Echo Request message as bytes.
        """

        return (
            struct.pack(
                ICMP6__ECHO_REQUEST__STRUCT,
                int(self.type),
                int(self.code),
                0,
                self.id,
                self.seq,
            )
            + self.data
        )

    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6EchoRequestMessage:
        """
        Initialize the ICMPv6 Echo Request message from bytes.
        """

        type, code, cksum, id, seq = struct.unpack(
            ICMP6__ECHO_REQUEST__STRUCT, _bytes[:ICMP6__ECHO_REQUEST__LEN]
        )

        assert (received_type := Icmp6Type.from_int(type)) == (
            valid_type := Icmp6Type.ECHO_REQUEST
        ), f"The 'type' field must be {valid_type!r}. Got: {received_type!r}"

        return Icmp6EchoRequestMessage(
            code=Icmp6EchoRequestCode.from_int(code),
            cksum=cksum,
            id=id,
            seq=seq,
            data=_bytes[ICMP6__ECHO_REQUEST__LEN:],
        )
