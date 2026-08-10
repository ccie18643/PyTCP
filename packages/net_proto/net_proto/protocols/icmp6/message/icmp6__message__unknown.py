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
This module contains the ICMPv6 unknown message support class.

Per RFC 4443 §2.4 the receiver's action depends on whether
the unknown Type byte falls in the error range (1..127) or
the informational range (128..255):

- (b) Unknown informational messages — silently discarded.
- (c) Unknown error messages — passed to the upper-layer
  process for application-defined handling.

PyTCP's parser materialises the wire bytes verbatim into
this class so the packet handler's RX dispatch can route
unknown types per the two-branch rule above. The wrapper
is intentionally tolerant of `UNKNOWN_n` enum members for
both 'type' and 'code'; the closed-set TX-strict check at
`Icmp6Assembler` is gated by an
`isinstance(message, Icmp6MessageUnknown)` exemption so a
roundtrip emit path stays open (security testing /
raw-socket replay).

net_proto/protocols/icmp6/message/icmp6__message__unknown.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.icmp6.message.icmp6__message import (
    ICMP6__HEADER__LEN,
    ICMP6__HEADER__STRUCT,
    Icmp6Code,
    Icmp6Message,
    Icmp6Type,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6MessageUnknown(Icmp6Message):
    """
    The ICMPv6 unknown message.
    """

    type: Icmp6Type
    code: Icmp6Code
    cksum: int = 0
    data: Buffer = bytes()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 unknown message fields.
        """

        assert isinstance(self.type, Icmp6Type), f"The 'type' field must be an Icmp6Type. Got: {type(self.type)!r}"

        assert isinstance(self.code, Icmp6Code), f"The 'code' field must be an Icmp6Code. Got: {type(self.code)!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert isinstance(
            self.data, (bytes, bytearray, memoryview)
        ), f"The 'data' field must be a bytes, bytearray or memoryview. Got: {type(self.data)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 unknown message length.
        """

        return ICMP6__HEADER__LEN + len(self.data)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 unknown message log string.
        """

        return (
            f"ICMPv6 Unknown Message, type {int(self.type)}, code {int(self.code)}, "
            f"cksum {self.cksum}, len {len(self)} ({ICMP6__HEADER__LEN}+{len(self.data)})"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 unknown message as a memoryview.
        """

        buffer = self._pack_header(len(self))
        buffer[ICMP6__HEADER__LEN:] = self.data

        return memoryview(buffer)

    @override
    def _pack_header(
        self,
        buffer_len: int = ICMP6__HEADER__LEN,
        /,
    ) -> bytearray:
        """
        Pack the ICMPv6 unknown message header into a fresh bytearray.
        """

        struct.pack_into(
            ICMP6__HEADER__STRUCT,
            buffer := bytearray(buffer_len),
            0,
            int(self.type),
            int(self.code),
            0,
        )

        return buffer

    @override
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 unknown message after parsing it.
        """

        # Currently no sanity checks are implemented.

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 unknown message before parsing it.
        """

        # Currently no integrity checks are implemented.

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 unknown message from buffer.
        """

        type_, code, cksum = struct.unpack(ICMP6__HEADER__STRUCT, buffer[:ICMP6__HEADER__LEN])

        assert (
            received_type := type_
        ) not in Icmp6Type.get_known_values(), (
            f"The 'type' field must not be known. Got: {Icmp6Type.from_int(received_type)!r}"
        )

        return cls(
            type=Icmp6Type.from_int(type_),
            code=Icmp6Code.from_int(code),
            cksum=cksum,
            data=buffer[ICMP6__HEADER__LEN:],
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 unknown message into the buffer list.
        """

        buffers.append(self._pack_header())
        buffers.append(self.data)
