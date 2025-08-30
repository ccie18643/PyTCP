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
Module contains the unknown IPv4 option support code.

net_proto/protocols/ip4/options/ip4_option__unknown.py

ver 3.0.4
"""


import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.ip4.ip4__errors import Ip4IntegrityError
from net_proto.protocols.ip4.options.ip4_option import (
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
        init=True,
        default=IP4__OPTION__LEN,
    )

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Validate the IPv4 unknown option fields.
        """

        assert isinstance(self.type, Ip4OptionType), (
            f"The 'type' field must be a Ip4OptionType. "
            f"Got: {type(self.type)!r}"
        )

        assert int(self.type) not in Ip4OptionType.get_known_values(), (
            "The 'type' field must not be a known Ip4OptionType. "
            f"Got: {self.type!r}"
        )

        assert is_uint8(self.len), (
            f"The 'len' field must be an 8-bit unsigned integer. "
            f"Got: {self.len}"
        )

        assert self.len == IP4__OPTION__LEN + len(self.data), (
            "The 'len' field must reflect the length of the 'data' field. "
            f"Got: {self.len!r} != {IP4__OPTION__LEN + len(self.data)!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the unknown IPv4 option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the unknown IPv4 option as bytes.
        """

        return (
            struct.pack(
                IP4__OPTION__STRUCT,
                int(self.type),
                self.len,
            )
            + self.data
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the unknown IPv4 option integrity before parsing it.
        """

        if (value := _bytes[1]) > len(_bytes):
            raise Ip4IntegrityError(
                "The unknown IPv4 option length must be less than or equal to "
                f"the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Initialize the unknown IPv4 option from bytes.
        """

        assert (value := len(_bytes)) >= IP4__OPTION__LEN, (
            f"The minimum length of the unknown IPv4 option must be "
            f"{IP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) not in Ip4OptionType.get_known_values(), (
            f"The unknown IPv4 option type must not be known. "
            f"Got: {Ip4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(_bytes)

        return cls(
            type=Ip4OptionType(_bytes[0]),
            len=_bytes[1],
            data=_bytes[IP4__OPTION__LEN : _bytes[1]],
        )
