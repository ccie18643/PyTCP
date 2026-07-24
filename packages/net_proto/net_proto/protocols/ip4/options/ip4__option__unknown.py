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
This module contains the unknown IPv4 option support code.

net_proto/protocols/ip4/options/ip4__option__unknown.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.ip4.ip4__errors import Ip4IntegrityError
from net_proto.protocols.ip4.options.ip4__option import (
    IP4__OPTION__LEN,
    IP4__OPTION__STRUCT,
    Ip4Option,
    Ip4OptionType,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Ip4OptionUnknown(Ip4Option):
    """
    The IPv4 unknown option support class.
    """

    type: Ip4OptionType = field(
        repr=True,
        init=True,
        default=Ip4OptionType.from_int(255),
    )
    len: int = field(
        repr=True,
        init=False,
    )

    data: Buffer

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv4 unknown option fields.
        """

        assert isinstance(
            self.type, Ip4OptionType
        ), f"The 'type' field must be an Ip4OptionType. Got: {type(self.type)!r}"

        assert (
            int(self.type) not in Ip4OptionType.get_known_values()
        ), f"The 'type' field must not be a known Ip4OptionType. Got: {self.type!r}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", IP4__OPTION__LEN + len(self.data))

        assert is_uint8(self.len), f"The 'len' field must be an 8-bit unsigned integer. Got: {self.len!r}"

    @override
    def __str__(self) -> str:
        """
        Get the unknown IPv4 option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the unknown IPv4 option as a memoryview.
        """

        struct.pack_into(
            IP4__OPTION__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len,
        )

        buffer[IP4__OPTION__LEN:] = self.data

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the unknown IPv4 option before parsing it.
        """

        # RFC 791 §3.1 (Case 2 TLV) — the option length byte bounds
        # the option within the IPv4 options region. For unknown
        # codepoints PyTCP preserves the wire bytes verbatim
        # (RFC 1122 §3.2.1.8 "silently ignore the others"), so the
        # only structural check that applies is "length fits buffer".
        if (value := buffer[1]) > len(buffer):
            raise Ip4IntegrityError(
                "The unknown IPv4 option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the unknown IPv4 option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= IP4__OPTION__LEN, (
            f"The minimum length of the unknown IPv4 option must be {IP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (
            value := buffer[0]
        ) not in Ip4OptionType.get_known_values(), (
            f"The unknown IPv4 option type must not be known. Got: {Ip4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            type=Ip4OptionType(buffer[0]),
            data=buffer[IP4__OPTION__LEN : buffer[1]],
        )
