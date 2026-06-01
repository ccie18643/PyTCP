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
This module contains the IPv4 Ssrr (Strict Source and Record Route) option support code.

net_proto/protocols/ip4/options/ip4__option__ssrr.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Ip4Address
from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.ip4.ip4__errors import Ip4IntegrityError
from net_proto.protocols.ip4.options.ip4__option import Ip4Option, Ip4OptionType

# The IPv4 Ssrr (Strict Source and Record Route) option [RFC 791].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Type = 137   |    Length     |    Pointer    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  Route Data 1                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                      ...                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  Route Data N                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP4__OPTION__SSRR__HDR_LEN = 3
IP4__OPTION__SSRR__SLOT_LEN = 4
IP4__OPTION__SSRR__MIN_LEN = IP4__OPTION__SSRR__HDR_LEN + IP4__OPTION__SSRR__SLOT_LEN
IP4__OPTION__SSRR__POINTER_BASE = 4
IP4__OPTION__SSRR__STRUCT = "! BBB"


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip4OptionSsrr(Ip4Option):
    """
    The IPv4 Ssrr (Strict Source and Record Route) option support class.
    """

    type: Ip4OptionType = field(
        repr=False,
        init=False,
        default=Ip4OptionType.SSRR,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    pointer: int
    route: list[Ip4Address]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv4 Ssrr option fields.
        """

        assert is_uint8(self.pointer), f"The 'pointer' field must be an 8-bit unsigned integer. Got: {self.pointer!r}"

        assert self.pointer >= IP4__OPTION__SSRR__POINTER_BASE, (
            f"The 'pointer' field must be at least {IP4__OPTION__SSRR__POINTER_BASE}. " f"Got: {self.pointer!r}"
        )

        assert (self.pointer - IP4__OPTION__SSRR__POINTER_BASE) % IP4__OPTION__SSRR__SLOT_LEN == 0, (
            f"The 'pointer' field must be aligned to the {IP4__OPTION__SSRR__SLOT_LEN}-byte slot "
            f"boundary. Got: {self.pointer!r}"
        )

        assert len(self.route) >= 1, f"The 'route' field must have at least 1 entry. Got: {len(self.route)!r}"

        assert all(
            isinstance(hop, Ip4Address) for hop in self.route
        ), f"The 'route' field must be a list of Ip4Address. Got: {self.route!r}"

        total_len = IP4__OPTION__SSRR__HDR_LEN + IP4__OPTION__SSRR__SLOT_LEN * len(self.route)

        # RFC 791 §3.1 (Case 2 TLV) — the option-length byte is a
        # single octet; an SSRR with more than 63 hops would overflow
        # it. The Ip4Options walker already caps wire input via
        # 'hlen <= 60', so this assert catches programmer error at
        # construction with a clear message instead of an opaque
        # struct.error at __buffer__ serialization.
        assert is_uint8(total_len), (
            f"The total IPv4 SSRR option length must fit in a single uint8 length byte. "
            f"Got: {total_len} (route has {len(self.route)} entries; max 63)"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", total_len)

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 Ssrr option log string.
        """

        return f"ssrr [{', '.join(str(hop) for hop in self.route)}] ptr={self.pointer}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 Ssrr option as a memoryview.
        """

        struct.pack_into(
            IP4__OPTION__SSRR__STRUCT,
            buffer := bytearray(self.len),
            0,
            int(self.type),
            self.len,
            self.pointer,
        )

        for index, hop in enumerate(self.route):
            offset = IP4__OPTION__SSRR__HDR_LEN + IP4__OPTION__SSRR__SLOT_LEN * index
            buffer[offset : offset + IP4__OPTION__SSRR__SLOT_LEN] = bytes(hop)

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv4 Ssrr option before parsing it.
        """

        # RFC 791 §3.1 'Strict Source and Record Route' — length byte
        # bounds the option; shortest legal SSRR carries one 4-byte
        # slot (3-byte header + 4-byte slot = 7).
        if (value := buffer[1]) < IP4__OPTION__SSRR__MIN_LEN:
            raise Ip4IntegrityError(
                f"The IPv4 Ssrr option length must be at least {IP4__OPTION__SSRR__MIN_LEN} " f"bytes. Got: {value!r}"
            )

        # RFC 791 §3.1 — route data is a sequence of 4-byte IPv4
        # addresses; (length - 3-byte header) MUST be a multiple of 4.
        if (buffer[1] - IP4__OPTION__SSRR__HDR_LEN) % IP4__OPTION__SSRR__SLOT_LEN:
            raise Ip4IntegrityError(
                "The IPv4 Ssrr option route data length must be a multiple of "
                f"{IP4__OPTION__SSRR__SLOT_LEN} bytes. Got: {buffer[1]!r}"
            )

        # RFC 791 §3.1 — option length MUST NOT exceed the buffer
        # available.
        if (value := buffer[1]) > len(buffer):
            raise Ip4IntegrityError(
                "The IPv4 Ssrr option length value must be less than or equal to the "
                f"length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # RFC 791 §3.1 — "smallest legal value for the pointer is 4";
        # defense-in-depth at the integrity layer so a hostile wire
        # pointer below the base does not leak as AssertionError out
        # of the dataclass __post_init__.
        if (value := buffer[2]) < IP4__OPTION__SSRR__POINTER_BASE:
            raise Ip4IntegrityError(
                f"The IPv4 Ssrr option pointer must be at least {IP4__OPTION__SSRR__POINTER_BASE}. " f"Got: {value!r}"
            )

        # RFC 791 §3.1 — pointer addresses a 4-byte slot boundary;
        # (pointer - 4) MUST be a multiple of 4.
        if (buffer[2] - IP4__OPTION__SSRR__POINTER_BASE) % IP4__OPTION__SSRR__SLOT_LEN:
            raise Ip4IntegrityError(
                "The IPv4 Ssrr option pointer must be aligned to the "
                f"{IP4__OPTION__SSRR__SLOT_LEN}-byte slot boundary. Got: {buffer[2]!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv4 Ssrr option from buffer.
        """

        assert (value := len(buffer)) >= IP4__OPTION__SSRR__MIN_LEN, (
            f"The minimum length of the IPv4 Ssrr option must be {IP4__OPTION__SSRR__MIN_LEN} " f"bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip4OptionType.SSRR), (
            f"The IPv4 Ssrr option type must be {Ip4OptionType.SSRR!r}. " f"Got: {Ip4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            pointer=buffer[2],
            route=[
                Ip4Address(bytes(buffer[offset : offset + IP4__OPTION__SSRR__SLOT_LEN]))
                for offset in range(
                    IP4__OPTION__SSRR__HDR_LEN,
                    buffer[1],
                    IP4__OPTION__SSRR__SLOT_LEN,
                )
            ],
        )
