#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains the ICMPv6 Pi (Prefix Information) option support code.

pytcp/protocols/icmp6/message/nd/option/icmp6_nd_option__pi.py

ver 3.0.0 (code refactor needed for 'from_bytes' method)
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint32
from pytcp.lib.ip6_address import Ip6Address, Ip6Mask, Ip6Network
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option import (
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

ICMP6__ND_OPTION_PI__LEN = 32
ICMP6__ND_OPTION_PI__STRUCT = "! BB BB L L L 16s"


@dataclass(frozen=True, kw_only=True)
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


@dataclass(frozen=True, kw_only=True)
class Icmp6NdOptionPi(Icmp6NdOption):
    """
    The ICMPv6 ND Pi option support.
    """

    type: Icmp6NdOptionType = field(
        repr=False, init=False, default=Icmp6NdOptionType.PI
    )
    len: int = field(repr=False, init=False, default=ICMP6__ND_OPTION_PI__LEN)

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

        assert isinstance(
            self.flag_l, bool
        ), f"The 'flag_l' field must be a boolean. Got: {type(self.flag_l)!r}"

        assert isinstance(
            self.flag_a, bool
        ), f"The 'flag_a' field must be a boolean. Got: {type(self.flag_a)!r}"

        assert isinstance(
            self.flag_r, bool
        ), f"The 'flag_r' field must be a boolean. Got: {type(self.flag_r)!r}"

        assert is_uint32(
            self.valid_lifetime
        ), f"The 'valid_lifetime' field must be a 32-bit unsigned integer. Got: {self.valid_lifetime!r}"

        assert is_uint32(
            self.preferred_lifetime
        ), f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. Got: {self.preferred_lifetime!r}"

        assert isinstance(
            self.prefix, Ip6Network
        ), f"The 'prefix' field must be an Ip6Network. Got: {type(self.prefix)!r}"

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Pi option log string.
        """

        # TODO: Update the option string to show all data.

        return f"prefix_info {self.prefix}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 Nd Pi option as bytes.
        """

        return struct.pack(
            ICMP6__ND_OPTION_PI__STRUCT,
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
    def from_bytes(_bytes: bytes) -> Icmp6NdOptionPi:
        """
        Initialize the ICMPv6 ND Pi option from bytes.
        """

        # TODO: Refactor this code after unit tests are in place.

        return Icmp6NdOptionPi(
            flag_l=bool(_bytes[3] & 0b10000000),
            flag_a=bool(_bytes[3] & 0b01000000),
            flag_r=bool(_bytes[3] & 0b00100000),
            valid_lifetime=struct.unpack_from("!L", _bytes, 4)[0],
            preferred_lifetime=struct.unpack_from("!L", _bytes, 8)[0],
            prefix=Ip6Network(
                (Ip6Address(_bytes[16:32]), Ip6Mask(f"/{_bytes[2]}"))
            ),
        )
