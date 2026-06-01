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
This module contains the ICMPv4 unknown message support class.

net_proto/protocols/icmp4/message/icmp4__message__unknown.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.icmp4.icmp4__errors import Icmp4SanityError
from net_proto.protocols.icmp4.message.icmp4__message import (
    ICMP4__HEADER__LEN,
    ICMP4__HEADER__STRUCT,
    Icmp4Code,
    Icmp4Message,
    Icmp4Type,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp4MessageUnknown(Icmp4Message):
    """
    The ICMPv4 unknown message.
    """

    type: Icmp4Type
    code: Icmp4Code
    cksum: int = 0
    data: Buffer = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv4 unknown message fields.
        """

        assert isinstance(self.type, Icmp4Type), f"The 'type' field must be an Icmp4Type. Got: {type(self.type)!r}"

        assert isinstance(self.code, Icmp4Code), f"The 'code' field must be an Icmp4Code. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert isinstance(
            self.data, (bytes, bytearray, memoryview)
        ), f"The 'data' field must be a bytes, bytearray or memoryview. Got: {type(self.data)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv4 unknown message length.
        """

        return ICMP4__HEADER__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv4 unknown message log string.
        """

        return (
            f"ICMPv4 Unknown Message, type {int(self.type)}, code {int(self.code)}, "
            f"cksum {self.cksum}, len {len(self)} ({ICMP4__HEADER__LEN}+{len(self.data)})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv4 unknown message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP4__HEADER__LEN:] = self.data

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP4__HEADER__LEN,
        /,
    ) -> bytearray:
        """
        Get the ICMPv4 unknown message as bytes.
        """

        struct.pack_into(
            ICMP4__HEADER__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
        )

        return buffer

    @override
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the ICMPv4 unknown message after parsing it.
        """

        # RFC 1122 §3.2.2 — "If an ICMP message of unknown type is received,
        # it MUST be silently discarded." PyTCP's Icmp4Type enum declares the
        # five types that this host stack handles (Echo Reply, Destination
        # Unreachable, Echo Request, Time Exceeded, Parameter Problem); any
        # other wire 'type' value (including the deprecated Source Quench
        # type 4 per RFC 6633) materialises as UNKNOWN_n here and the frame
        # is rejected at parser sanity.
        raise Icmp4SanityError(
            f"The 'type' field value must be one of {Icmp4Type.get_known_values()}. " f"Got: {int(self.type)}."
        )

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the ICMPv4 unknown message before parsing it.
        """

        # Currently no integrity checks are implemented.

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv4 unknown message from buffer.
        """

        type_, code, cksum = struct.unpack(ICMP4__HEADER__STRUCT, buffer[:ICMP4__HEADER__LEN])

        assert (
            received_type := type_
        ) not in Icmp4Type.get_known_values(), (
            f"The 'type' field must not be known. Got: {Icmp4Type.from_int(received_type)!r}"
        )

        return cls(
            type=Icmp4Type.from_int(type_),
            code=Icmp4Code.from_int(code),
            cksum=cksum,
            data=buffer[ICMP4__HEADER__LEN:],
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv4 unknown message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self.data)
