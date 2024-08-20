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
This module contains the ICMPv6 Slla (Source Link Layer Address) option support code.

pytcp/protocols/icmp6/message/nd/option/icmp6_nd_option__slla.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND Slla (Source Link Layer Address) option [RFC4861].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 1   |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND_OPTION_SLLA__LEN = 8
ICMP6__ND_OPTION_SLLA__STRUCT = "! BB 6s"


@dataclass(frozen=True, kw_only=True)
class Icmp6NdOptionSlla(Icmp6NdOption):
    """
    The ICMPv6 ND Slla option support.
    """

    type: Icmp6NdOptionType = field(
        repr=False, init=False, default=Icmp6NdOptionType.SLLA
    )
    len: int = field(repr=False, init=False, default=ICMP6__ND_OPTION_SLLA__LEN)

    slla: MacAddress

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv4 ND Slla option fields.
        """

        assert isinstance(
            self.slla, MacAddress
        ), f"The 'slla' field must be a MacAddress. Got: {type(self.slla)!r}."

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Slla option log string.
        """

        return f"slla {self.slla}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 ND Slla option as bytes.
        """

        return struct.pack(
            ICMP6__ND_OPTION_SLLA__STRUCT,
            int(self.type),
            self.len >> 3,
            bytes(self.slla),
        )

    @staticmethod
    def from_bytes(_bytes: bytes) -> Icmp6NdOptionSlla:
        """
        Initialize the ICMPv6 ND Slla option from bytes.
        """

        return Icmp6NdOptionSlla(slla=MacAddress(_bytes[2:8]))
