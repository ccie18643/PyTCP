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
This module contains the unknown ICMPv6 ND option support code.

Per RFC 4861 §4.6 unrecognised ND options MUST be silently
ignored by the receiver. PyTCP's parser preserves the wire
bytes verbatim into this class so the packet handler can
log the codepoint for operator visibility and so a
Phase-2 forwarder can re-emit options it doesn't itself
consume. The wrapper is intentionally tolerant of any
`UNKNOWN_n` Icmp6NdOptionType pseudo-member synthesised
via the `ProtoEnum._missing_` hook.

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__unknown.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_8_byte_alligned, is_uint8
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    ICMP6__ND__OPTION__LEN,
    ICMP6__ND__OPTION__STRUCT,
    Icmp6NdOption,
    Icmp6NdOptionType,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOptionUnknown(Icmp6NdOption):
    """
    The ICMPv6 ND unknown option support class.
    """

    type: Icmp6NdOptionType = field(
        repr=True,
        init=True,
        default=Icmp6NdOptionType.from_int(255),
    )
    len: int = field(
        repr=True,
        init=False,
    )

    data: Buffer

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND unknown option fields.
        """

        assert isinstance(
            self.type, Icmp6NdOptionType
        ), f"The 'type' field must be an Icmp6NdOptionType. Got: {type(self.type)!r}"

        assert (
            int(self.type) not in Icmp6NdOptionType.get_known_values()
        ), f"The 'type' field must not be a known Icmp6NdOptionType. Got: {self.type!r}"

        object.__setattr__(self, "len", ICMP6__ND__OPTION__LEN + len(self.data))

        assert is_uint8(self.len), f"The 'len' field must be an 8-bit unsigned integer. Got: {self.len!r}"

        assert is_8_byte_alligned(self.len), f"The 'len' field must be 8-byte aligned. Got: {self.len!r}"

    @override
    def __str__(self) -> str:
        """
        Get the unknown ICMPv6 ND option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the unknown ICMPv6 ND option as a memoryview.
        """

        struct.pack_into(
            ICMP6__ND__OPTION__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len >> 3,
        )

        buffer[ICMP6__ND__OPTION__LEN:] = self.data

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the unknown ICMPv6 ND option before parsing it.
        """

        if (value := buffer[1] << 3) > len(buffer):
            raise Icmp6IntegrityError(
                "The unknown ICMPv6 ND option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the unknown ICMPv6 ND option from buffer.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the unknown ICMPv6 ND option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (
            value := buffer[0]
        ) not in Icmp6NdOptionType.get_known_values(), (
            f"The unknown ICMPv6 ND option type must not be known. Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            type=Icmp6NdOptionType(buffer[0]),
            data=buffer[ICMP6__ND__OPTION__LEN : buffer[1] << 3],
        )
