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
Module contains the DHCPv4 Pad option support code.

pytcp/protocols/dhcp4/options/dhcp4_option__pad.py

ver 3.0.2
"""


from __future__ import annotations

from dataclasses import dataclass, field
from typing import override

from pytcp.protocols.dhcp4.options.dhcp4_option import (
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Pad option [RFC 2132].

# +-+-+-+-+-+-+-+-+
# |    Type = 0   |
# +-+-+-+-+-+-+-+-+


DHCP4__OPTION__PAD__LEN = 1
DHCP4__OPTION__PAD__STRUCT = "! B"


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4OptionPad(Dhcp4Option):
    """
    The DHCPv4 Pad option support.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.PAD,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__PAD__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 Pad option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the the DHCPv4 Pad option log string.
        """

        return "pad"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the DHCPv4 Pad option as bytes.
        """

        return bytes(self.type)

    @override
    @staticmethod
    def from_bytes(_bytes: bytes, /) -> Dhcp4OptionPad:
        """
        Initialize the DHCPv4 Pad option from bytes.
        """

        assert (value := len(_bytes)) >= DHCP4__OPTION__PAD__LEN, (
            f"The minimum length of the DHCPv4 Pad option must be "
            f"{DHCP4__OPTION__PAD__LEN} byte. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(Dhcp4OptionType.PAD), (
            f"The DHCPv4 Pad option type must be {Dhcp4OptionType.PAD!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        return Dhcp4OptionPad()
