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
This module contains the ICMPv6 Pi (Prefix Information) option support code.

net_proto/protocols/icmp6/message/nd/option/icmp6_nd_option__pi.py

ver 3.0.4
"""


import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Ip6Address, Ip6Mask, Ip6Network
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND Pi (Prefix Information) option [RFC4861].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |    Length     | Prefix Length |L|A|R|    0    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Valid Lifetime                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Preferred Lifetime                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                               0                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            Prefix                             +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__OPTION__PI__LEN = 32
ICMP6__ND__OPTION__PI__STRUCT = "! BB BB L L L 16s"


@dataclass(frozen=True, kw_only=True, slots=True)
class NdPrefixInfo:
    """
    Neighbor Discovery Prefix Information.
    """

    flag_l: bool
    flag_a: bool
    flag_r: bool
    valid_lifetime: int
    preferred_lifetime: int
    prefix: Ip6Network


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOptionPi(Icmp6NdOption):
    """
    The ICMPv6 ND Pi option support.
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.PI,
    )
    len: int = field(
        repr=False,
        init=False,
        default=ICMP6__ND__OPTION__PI__LEN,
    )

    flag_l: bool = False
    flag_a: bool = False
    flag_r: bool = False
    valid_lifetime: int
    preferred_lifetime: int
    prefix: Ip6Network

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv4 ND Pi option fields.
        """

        assert isinstance(self.flag_l, bool), (
            f"The 'flag_l' field must be a boolean. "
            f"Got: {type(self.flag_l)!r}"
        )

        assert isinstance(self.flag_a, bool), (
            f"The 'flag_a' field must be a boolean. "
            f"Got: {type(self.flag_a)!r}"
        )

        assert isinstance(self.flag_r, bool), (
            f"The 'flag_r' field must be a boolean. "
            f"Got: {type(self.flag_r)!r}"
        )

        assert is_uint32(self.valid_lifetime), (
            f"The 'valid_lifetime' field must be a 32-bit unsigned integer. "
            f"Got: {self.valid_lifetime!r}"
        )

        assert is_uint32(self.preferred_lifetime), (
            f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. "
            f"Got: {self.preferred_lifetime!r}"
        )

        assert isinstance(self.prefix, Ip6Network), (
            f"The 'prefix' field must be an Ip6Network. "
            f"Got: {type(self.prefix)!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Pi option log string.
        """

        return (
            f"prefix_info (prefix {self.prefix}, flags "
            f"{'L' if self.flag_l else '-'}"
            f"{'A' if self.flag_a else '-'}"
            f"{'R' if self.flag_r else '-'}, "
            f"valid_lifetime {self.valid_lifetime}, "
            f"preferred_lifetime {self.preferred_lifetime})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 Nd Pi option as bytes.
        """

        return struct.pack(
            ICMP6__ND__OPTION__PI__STRUCT,
            int(self.type),
            self.len >> 3,
            len(self.prefix.mask),
            (self.flag_l << 7)
            | (self.flag_a << 6)
            | (self.flag_r << 5)
            | (0 & 0b00011111),
            self.valid_lifetime,
            self.preferred_lifetime,
            0,
            bytes(self.prefix.address),
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the ICMPv6 ND Pi option integrity before parsing it.
        """

        if (value := _bytes[1] << 3) != ICMP6__ND__OPTION__PI__LEN:
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND Pi option length must be {ICMP6__ND__OPTION__PI__LEN} "
                f"bytes. Got: {value!r}"
            )

        if (value := _bytes[1] << 3) > len(_bytes):
            raise Icmp6IntegrityError(
                "The ICMPv6 ND Pi option length must be less than or equal to the "
                f"length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Initialize the ICMPv6 ND Pi option from bytes.
        """

        assert (value := len(_bytes)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND Pi option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(Icmp6NdOptionType.PI), (
            f"The ICMPv6 ND Pi option type must be {Icmp6NdOptionType.PI!r}. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        Icmp6NdOptionPi._validate_integrity(_bytes)

        (
            _,
            _,
            prefix_len,
            flags,
            valid_lifetime,
            preferred_lifetime,
            _,
            prefix,
        ) = struct.unpack(
            ICMP6__ND__OPTION__PI__STRUCT, _bytes[:ICMP6__ND__OPTION__PI__LEN]
        )

        return cls(
            flag_l=bool(flags & 0b10000000),
            flag_a=bool(flags & 0b01000000),
            flag_r=bool(flags & 0b00100000),
            valid_lifetime=valid_lifetime,
            preferred_lifetime=preferred_lifetime,
            prefix=Ip6Network((Ip6Address(prefix), Ip6Mask(f"/{prefix_len}"))),
        )
