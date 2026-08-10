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
This module contains the IPv6 HBH Jumbo Payload option support code.

net_proto/protocols/ip6_hbh/options/ip6_hbh__option__jumbo_payload.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import UINT_16__MAX, is_uint32
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhIntegrityError
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import (
    IP6_HBH__OPTION__LEN,
    Ip6HbhOption,
    Ip6HbhOptionType,
)

# The IPv6 HBH Jumbo Payload option [RFC 2675].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Option Type  |  Opt Data Len |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   Jumbo Payload Length         |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Type=0xC2 (top-2-bits=11 -> discard + Param Problem unless dst
# is multicast), Opt Data Len=4, Jumbo Payload Length is a 32-bit
# unsigned integer that replaces the standard IPv6 Payload Length
# field when the latter is zero (RFC 2675 §3). Per RFC 2675 §3
# the Jumbo Payload Length must be > 65535 — values <= UINT16_MAX
# are spec violations.

IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN = 6
IP6_HBH__OPTION__JUMBO_PAYLOAD__OPT_DATA_LEN = 4
IP6_HBH__OPTION__JUMBO_PAYLOAD__STRUCT = "! BBL"
IP6_HBH__OPTION__JUMBO_PAYLOAD__MIN_VALUE = UINT_16__MAX + 1


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip6HbhOptionJumboPayload(Ip6HbhOption):
    """
    The IPv6 HBH Jumbo Payload option support class.
    """

    type: Ip6HbhOptionType = field(
        repr=False,
        init=False,
        default=Ip6HbhOptionType.JUMBO_PAYLOAD,
    )
    len: int = field(
        repr=False,
        init=False,
        default=IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN,
    )

    value: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv6 HBH Jumbo Payload option fields.
        """

        assert is_uint32(self.value), f"The 'value' field must be a 32-bit unsigned integer. Got: {self.value!r}"

        assert self.value > UINT_16__MAX, (
            f"The 'value' field must be greater than {UINT_16__MAX} "
            f"(jumbograms only — RFC 2675 §3). Got: {self.value!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 HBH Jumbo Payload option log string.
        """

        return f"jumbo-payload ({self.value})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 HBH Jumbo Payload option as a memoryview.
        """

        struct.pack_into(
            IP6_HBH__OPTION__JUMBO_PAYLOAD__STRUCT,
            buffer := bytearray(IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN),
            0,
            int(self.type),
            IP6_HBH__OPTION__JUMBO_PAYLOAD__OPT_DATA_LEN,
            self.value,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv6 HBH Jumbo Payload option
        before parsing it. Hostile-wire defense-in-depth so the
        Opt Data Len mismatch and the RFC 2675 §3 "value > 65535"
        rule do not leak as bare AssertionErrors past the IPv6
        chain walker's PacketValidationError catch.
        """

        # RFC 2675 §2 — Jumbo Payload is fixed-shape: 1-byte type
        # + 1-byte Opt Data Len + 4-byte Jumbo Payload Length =
        # 6 octets total; Opt Data Len MUST be 4.
        if (value := buffer[1]) != IP6_HBH__OPTION__JUMBO_PAYLOAD__OPT_DATA_LEN:
            raise Ip6HbhIntegrityError(
                f"The IPv6 HBH Jumbo Payload option Opt Data Len must be "
                f"{IP6_HBH__OPTION__JUMBO_PAYLOAD__OPT_DATA_LEN}. Got: {value!r}"
            )

        # RFC 2675 §3 — "Jumbo Payload Length is the length of the
        # IPv6 packet in octets, excluding the IPv6 header but
        # including the Hop-by-Hop Options header; it must be
        # greater than 65,535." Values ≤ 65535 would have fit in
        # the standard 16-bit Payload Length field, so a Jumbo
        # Payload option carrying such a value is a spec violation.
        value = int.from_bytes(buffer[IP6_HBH__OPTION__LEN:IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN])
        if value <= UINT_16__MAX:
            raise Ip6HbhIntegrityError(
                f"The IPv6 HBH Jumbo Payload option value must be greater than "
                f"{UINT_16__MAX} (jumbograms only — RFC 2675 §3). Got: {value}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv6 HBH Jumbo Payload option from buffer.
        """

        assert (value := len(buffer)) >= IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN, (
            f"The minimum length of the IPv6 HBH Jumbo Payload option must be "
            f"{IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip6HbhOptionType.JUMBO_PAYLOAD), (
            f"The IPv6 HBH Jumbo Payload option type must be {Ip6HbhOptionType.JUMBO_PAYLOAD!r}. "
            f"Got: {Ip6HbhOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(value=int.from_bytes(buffer[IP6_HBH__OPTION__LEN:IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN]))
