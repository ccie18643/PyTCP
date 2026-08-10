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
This module contains the ICMPv6 ND Route Information option support code (RFC 4191 §2.3).

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__route_info.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address, Ip6Mask, Ip6Network
from net_proto.lib.int_checks import is_uint32
from net_proto.lib.proto_enum import ProtoEnumByte
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND Route Information option [RFC 4191 §2.3].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 24  |    Length     | Prefix Length |Resvd|Prf|Resvd|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Route Lifetime                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                   Prefix (Variable Length)                    |
# .                                                               .
# .                                                               .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Fixed portion = type(1) + length(1) + prefix_length(1) + prf-byte(1) +
# route_lifetime(4) = 8 bytes. Total option size depends on prefix length:
#   prefix_length = 0       → 8 bytes  (length-field = 1, no prefix bytes).
#   prefix_length 1..64     → 16 bytes (length-field = 2, 8 prefix bytes).
#   prefix_length 65..128   → 24 bytes (length-field = 3, 16 prefix bytes).
ICMP6__ND__OPTION__ROUTE_INFO__FIXED_LEN = 8
ICMP6__ND__OPTION__ROUTE_INFO__STRUCT__FIXED = "! BB BB L"


class Icmp6NdRoutePreference(ProtoEnumByte):
    """
    The Route Preference (Prf) field values per RFC 4191 §2.1.

    Wire encoding is a 2-bit signed integer at bits 4-3 of the
    Reserved/Prf/Reserved byte:
      01 = HIGH
      00 = MEDIUM (default)
      11 = LOW
      10 = RESERVED — receivers MUST ignore the option (handler
                       responsibility, not parser).
    """

    HIGH = 0b01
    MEDIUM = 0b00
    LOW = 0b11
    RESERVED = 0b10


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOptionRouteInfo(Icmp6NdOption):
    """
    The ICMPv6 ND Route Information option support class
    (RFC 4191 §2.3).

    Carried in Router Advertisement messages to indicate that
    the advertising router has a route for the given prefix
    (more-specific routing beyond the default route).
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.ROUTE_INFO,
    )
    len: int = field(
        repr=True,
        init=False,
    )

    prf: Icmp6NdRoutePreference
    route_lifetime: int
    prefix: Ip6Network

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND Route Information
        option fields.

        The 'len' attribute is computed from the prefix length
        per RFC 4191 §2.3 and stored on the frozen dataclass via
        'object.__setattr__' (codebase convention).
        """

        assert isinstance(
            self.prf, Icmp6NdRoutePreference
        ), f"The 'prf' field must be an Icmp6NdRoutePreference. Got: {type(self.prf)!r}"

        assert is_uint32(
            self.route_lifetime
        ), f"The 'route_lifetime' field must be a 32-bit unsigned integer. Got: {self.route_lifetime!r}"

        assert isinstance(
            self.prefix, Ip6Network
        ), f"The 'prefix' field must be an Ip6Network. Got: {type(self.prefix)!r}"

        # Per RFC 4191 §2.3 the option length is the smallest
        # value that fits the prefix length:
        #   prefix_length == 0      → 8 bytes (length-field = 1).
        #   prefix_length 1..64     → 16 bytes (length-field = 2).
        #   prefix_length 65..128   → 24 bytes (length-field = 3).
        prefix_length = self.prefix_length
        if prefix_length == 0:
            object.__setattr__(self, "len", 8)
        elif prefix_length <= 64:
            object.__setattr__(self, "len", 16)
        else:
            object.__setattr__(self, "len", 24)

    @property
    def prefix_length(self) -> int:
        """
        Get the Prefix Length field value (the prefix's mask
        width in bits).
        """

        return len(self.prefix.mask)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Route Information option log string.
        """

        return f"route_info (prefix {self.prefix}, prf {self.prf}, " f"route_lifetime {self.route_lifetime})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND Route Information option as a memoryview.

        Emits the smallest length-field value that fits the
        prefix length per RFC 4191 §2.3 and truncates the prefix
        to 0 / 8 / 16 wire bytes accordingly.
        """

        buffer = bytearray(len(self))
        struct.pack_into(
            ICMP6__ND__OPTION__ROUTE_INFO__STRUCT__FIXED,
            buffer,
            0,
            int(self.type),
            self.len >> 3,
            self.prefix_length,
            (int(self.prf) & 0b11) << 3,
            self.route_lifetime,
        )

        # Variable-length prefix tail: 0 / 8 / 16 bytes.
        prefix_bytes_to_emit = self.len - ICMP6__ND__OPTION__ROUTE_INFO__FIXED_LEN
        if prefix_bytes_to_emit > 0:
            buffer[
                ICMP6__ND__OPTION__ROUTE_INFO__FIXED_LEN : ICMP6__ND__OPTION__ROUTE_INFO__FIXED_LEN
                + prefix_bytes_to_emit
            ] = bytes(self.prefix.address)[:prefix_bytes_to_emit]

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the ICMPv6 ND Route Information
        option before parsing it.
        """

        encoded_len = buffer[1] << 3
        if encoded_len not in (8, 16, 24):
            raise Icmp6IntegrityError(
                "The ICMPv6 ND Route Info option length value must be " f"8, 16, or 24 bytes. Got: {encoded_len!r}"
            )

        if encoded_len > len(buffer):
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND Route Info option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {encoded_len!r}"
            )

        prefix_length = buffer[2]
        if prefix_length > 128:
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND Route Info option prefix length must be in 0..128. " f"Got: {prefix_length!r}"
            )

        # Length-vs-prefix-length consistency per RFC 4191 §2.3:
        #   length=8  → prefix_length must be 0
        #   length=16 → prefix_length must be 0..64
        #   length=24 → prefix_length must be 0..128 (already checked above)
        if encoded_len == 8 and prefix_length != 0:
            raise Icmp6IntegrityError(
                "The ICMPv6 ND Route Info option prefix length must be 0 when "
                f"option length is 8 bytes. Got: {prefix_length!r}"
            )
        if encoded_len == 16 and prefix_length > 64:
            raise Icmp6IntegrityError(
                "The ICMPv6 ND Route Info option prefix length must be at most 64 "
                f"when option length is 16 bytes. Got: {prefix_length!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND Route Information option from buffer.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND Route Info option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Icmp6NdOptionType.ROUTE_INFO), (
            f"The ICMPv6 ND Route Info option type must be "
            f"{Icmp6NdOptionType.ROUTE_INFO!r}. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        _type, length_units, prefix_length, prf_byte, route_lifetime = struct.unpack(
            ICMP6__ND__OPTION__ROUTE_INFO__STRUCT__FIXED,
            buffer[:ICMP6__ND__OPTION__ROUTE_INFO__FIXED_LEN],
        )
        encoded_len = length_units << 3
        prefix_bytes_on_wire = encoded_len - ICMP6__ND__OPTION__ROUTE_INFO__FIXED_LEN

        # Pad the wire prefix bytes (0 / 8 / 16) to a full
        # 16-byte Ip6Address by zero-extending the trailing bytes.
        prefix_full = bytearray(16)
        if prefix_bytes_on_wire > 0:
            prefix_full[:prefix_bytes_on_wire] = buffer[
                ICMP6__ND__OPTION__ROUTE_INFO__FIXED_LEN : ICMP6__ND__OPTION__ROUTE_INFO__FIXED_LEN
                + prefix_bytes_on_wire
            ]

        prf = Icmp6NdRoutePreference((prf_byte >> 3) & 0b11)

        return cls(
            prf=prf,
            route_lifetime=route_lifetime,
            prefix=Ip6Network((Ip6Address(bytes(prefix_full)), Ip6Mask(f"/{prefix_length}"))),
        )
