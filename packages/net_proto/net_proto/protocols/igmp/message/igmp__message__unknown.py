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
This module contains the IGMP unknown-message support class — the
parser carrier for an unrecognised IGMP 'type' value, which the host
silently ignores (RFC 3376 §4).

net_proto/protocols/igmp/message/igmp__message__unknown.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.igmp.igmp__errors import IgmpSanityError
from net_proto.protocols.igmp.message.igmp__message import (
    IgmpMessage,
    IgmpType,
)

IGMP__UNKNOWN__HEADER__LEN = 4
IGMP__UNKNOWN__HEADER__STRUCT = "! BBH"


@dataclass(frozen=True, kw_only=True, slots=True)
class IgmpMessageUnknown(IgmpMessage):
    """
    The IGMP unknown message — the parser carrier for an unrecognised
    'type' value. RFC 3376 §4 mandates that unrecognised message types
    be silently ignored, which PyTCP enforces by rejecting the frame at
    parser sanity (the RX handler maps the drop to a stat counter).
    """

    type: IgmpType
    cksum: int = 0
    data: Buffer = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IGMP unknown message fields.
        """

        assert isinstance(self.type, IgmpType), f"The 'type' field must be an IgmpType. Got: {type(self.type)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert isinstance(
            self.data, (bytes, bytearray, memoryview)
        ), f"The 'data' field must be a bytes, bytearray or memoryview. Got: {type(self.data)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the IGMP unknown message length.
        """

        return IGMP__UNKNOWN__HEADER__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the IGMP unknown message log string.
        """

        return f"IGMP Unknown Message, type {int(self.type)}, cksum {self.cksum}, len {len(self)}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IGMP unknown message as a memoryview.
        """

        struct.pack_into(
            IGMP__UNKNOWN__HEADER__STRUCT,
            buffer := bytearray(IGMP__UNKNOWN__HEADER__LEN),
            0,
            int(self.type),
            0,
            0,
        )
        buffer += self.data

        return memoryview(buffer)

    @override
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the IGMP unknown message after parsing it.
        """

        # RFC 3376 §4 — "Unrecognized message types MUST be silently
        # ignored." PyTCP's IgmpType enum declares the five types this
        # host handles; any other wire 'type' materialises as UNKNOWN_n
        # here and the frame is rejected at parser sanity.
        raise IgmpSanityError(
            f"The 'type' field value must be one of {IgmpType.get_known_values()}. Got: {int(self.type)}."
        )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the IGMP unknown message before parsing it.
        """

        # No integrity checks: the unknown carrier exists only to be
        # rejected at sanity; the parser-level minimum-length and
        # checksum checks already ran.

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IGMP unknown message from buffer.
        """

        type_, _, cksum = struct.unpack(IGMP__UNKNOWN__HEADER__STRUCT, buffer[:IGMP__UNKNOWN__HEADER__LEN])

        assert (
            received_type := type_
        ) not in IgmpType.get_known_values(), (
            f"The 'type' field must not be known. Got: {IgmpType.from_int(received_type)!r}"
        )

        return cls(
            type=IgmpType.from_int(type_),
            cksum=cksum,
            data=buffer[IGMP__UNKNOWN__HEADER__LEN:],
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the IGMP unknown message into the buffer list.
        """

        buffers.append(bytearray(memoryview(self)))
