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
This module contains the unknown IPv6 Destination Options option support code.

net_proto/protocols/ip6_dest_opts/options/ip6_dest_opts__option__unknown.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__errors import Ip6DestOptsIntegrityError
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option import (
    IP6_DEST_OPTS__OPTION__LEN,
    IP6_DEST_OPTS__OPTION__STRUCT,
    Ip6DestOptsOption,
    Ip6DestOptsOptionType,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Ip6DestOptsOptionUnknown(Ip6DestOptsOption):
    """
    The unknown IPv6 Destination Options option support class.

    Preserves the original Type byte (including its top-2-bit
    action-on-unrecognized code per RFC 8200 §4.2) and the raw
    Data payload so a future Phase-2 forwarder can re-emit the
    option byte-for-byte.
    """

    type: Ip6DestOptsOptionType = field(
        repr=True,
        init=True,
        default=Ip6DestOptsOptionType.from_int(0xFF),
    )
    len: int = field(
        repr=True,
        init=False,
    )

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the unknown IPv6 Dest Opts option fields.
        """

        assert isinstance(
            self.type, Ip6DestOptsOptionType
        ), f"The 'type' field must be an Ip6DestOptsOptionType. Got: {type(self.type)!r}"

        assert (
            int(self.type) not in Ip6DestOptsOptionType.get_known_values()
        ), f"The 'type' field must not be a known Ip6DestOptsOptionType. Got: {self.type!r}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", IP6_DEST_OPTS__OPTION__LEN + len(self.data))

        assert is_uint8(self.len), f"The 'len' field must be an 8-bit unsigned integer. Got: {self.len!r}"

    @override
    def __str__(self) -> str:
        """
        Get the unknown IPv6 Dest Opts option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the unknown IPv6 Dest Opts option as a memoryview.
        """

        struct.pack_into(
            IP6_DEST_OPTS__OPTION__STRUCT,
            buffer := bytearray(self.len),
            0,
            int(self.type),
            self.len - IP6_DEST_OPTS__OPTION__LEN,
        )

        buffer[IP6_DEST_OPTS__OPTION__LEN:] = self.data

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the unknown IPv6 Dest Opts option before parsing it.
        """

        if (value := buffer[1] + IP6_DEST_OPTS__OPTION__LEN) > len(buffer):
            raise Ip6DestOptsIntegrityError(
                "The unknown IPv6 Dest Opts option length value must not extend past the "
                f"length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the unknown IPv6 Dest Opts option from buffer.
        """

        assert (value := len(buffer)) >= IP6_DEST_OPTS__OPTION__LEN, (
            f"The minimum length of the unknown IPv6 Dest Opts option must be "
            f"{IP6_DEST_OPTS__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) not in Ip6DestOptsOptionType.get_known_values(), (
            f"The unknown IPv6 Dest Opts option type must not be known. "
            f"Got: {Ip6DestOptsOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            type=Ip6DestOptsOptionType.from_int(buffer[0]),
            data=bytes(buffer[IP6_DEST_OPTS__OPTION__LEN : IP6_DEST_OPTS__OPTION__LEN + buffer[1]]),
        )
