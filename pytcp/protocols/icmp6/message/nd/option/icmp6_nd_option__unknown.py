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
This module contains the unknown ICMPv6 option support code.

pytcp/protocols/icmp6/options/icmp6_nd_option__unknown.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint8
from pytcp.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    ICMP6__ND_OPTION__LEN,
    ICMP6__ND_OPTION__STRUCT,
    Icmp6NdOption,
    Icmp6NdOptionType,
)


@dataclass(frozen=True, kw_only=True)
class Icmp6NdOptionUnknown(Icmp6NdOption):
    """
    The ICMPv6 ND unknown option support class.
    """

    type: Icmp6NdOptionType = field(
        repr=True, init=True, default=Icmp6NdOptionType.from_int(255)
    )
    len: int = field(repr=True, init=True, default=ICMP6__ND_OPTION__LEN)

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv6 unknown option fields.
        """

        assert is_uint8(
            self.len
        ), f"The 'len' field must be an 8-bit unsigned integer. Got: {len}."

    @override
    def __str__(self) -> str:
        """
        Get the unknown ICMPv6 option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the unknown ICMPv6 option as bytes.
        """

        return (
            struct.pack(
                ICMP6__ND_OPTION__STRUCT,
                int(self.type),
                self.len >> 3,
            )
            + self.data
        )

    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6NdOptionUnknown:
        """
        Initialize the unknown ICMPv6 option from bytes.
        """

        assert len(_bytes) >= 2
        assert _bytes[0] not in Icmp6NdOptionType.get_core_values()

        # There is no option length integrity check (I) here as the length
        # of the unown option is not known in advance.

        if _bytes[1] > len(_bytes):
            raise Icmp6IntegrityError("Invalid unknown option length (II).")

        return Icmp6NdOptionUnknown(
            type=Icmp6NdOptionType(_bytes[0]),
            len=_bytes[1] << 3,
            data=_bytes[2 : _bytes[1]],
        )
