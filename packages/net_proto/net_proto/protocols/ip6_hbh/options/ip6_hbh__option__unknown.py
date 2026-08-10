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
This module contains the unknown IPv6 Hop-by-Hop Options option support code.

net_proto/protocols/ip6_hbh/options/ip6_hbh__option__unknown.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhIntegrityError
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import (
    IP6_HBH__OPTION__LEN,
    IP6_HBH__OPTION__STRUCT,
    Ip6HbhOption,
    Ip6HbhOptionType,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Ip6HbhOptionUnknown(Ip6HbhOption):
    """
    The unknown IPv6 Hop-by-Hop Options option support class.

    Preserves the original Type byte (including its top-2-bit
    action-on-unrecognized code per RFC 8200 §4.2) and the raw
    Data payload so a future Phase-2 forwarder can re-emit the
    option byte-for-byte.
    """

    type: Ip6HbhOptionType = field(
        repr=True,
        init=True,
        default=Ip6HbhOptionType.from_int(0xFF),
    )
    len: int = field(
        repr=True,
        init=False,
    )

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the unknown IPv6 HBH option fields.
        """

        assert isinstance(
            self.type, Ip6HbhOptionType
        ), f"The 'type' field must be an Ip6HbhOptionType. Got: {type(self.type)!r}"

        assert (
            int(self.type) not in Ip6HbhOptionType.get_known_values()
        ), f"The 'type' field must not be a known Ip6HbhOptionType. Got: {self.type!r}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", IP6_HBH__OPTION__LEN + len(self.data))

        assert is_uint8(self.len), f"The 'len' field must be an 8-bit unsigned integer. Got: {self.len!r}"

    @override
    def __str__(self) -> str:
        """
        Get the unknown IPv6 HBH option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the unknown IPv6 HBH option as a memoryview.
        """

        struct.pack_into(
            IP6_HBH__OPTION__STRUCT,
            buffer := bytearray(self.len),
            0,
            int(self.type),
            self.len - IP6_HBH__OPTION__LEN,
        )

        buffer[IP6_HBH__OPTION__LEN:] = self.data

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the unknown IPv6 HBH option before parsing it.
        """

        if (value := buffer[1] + IP6_HBH__OPTION__LEN) > len(buffer):
            raise Ip6HbhIntegrityError(
                "The unknown IPv6 HBH option length value must not extend past the "
                f"length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the unknown IPv6 HBH option from buffer.
        """

        assert (value := len(buffer)) >= IP6_HBH__OPTION__LEN, (
            f"The minimum length of the unknown IPv6 HBH option must be "
            f"{IP6_HBH__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) not in Ip6HbhOptionType.get_known_values(), (
            f"The unknown IPv6 HBH option type must not be known. " f"Got: {Ip6HbhOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            type=Ip6HbhOptionType.from_int(buffer[0]),
            data=bytes(buffer[IP6_HBH__OPTION__LEN : IP6_HBH__OPTION__LEN + buffer[1]]),
        )
