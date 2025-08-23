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
This module contains the unknown DHCPv4 option support code.

pytcp/protocols/dhcp4/options/dhcp4_option__unknown.py

ver 3.0.3
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint8
from pytcp.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from pytcp.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    DHCP4__OPTION__STRUCT,
    Dhcp4Option,
    Dhcp4OptionType,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4OptionUnknown(Dhcp4Option):
    """
    The DHCPv4 unknown option support class.
    """

    type: Dhcp4OptionType = field(
        repr=True,
        init=True,
        default=Dhcp4OptionType.from_int(255),
    )
    len: int = field(
        repr=True,
        init=True,
        default=DHCP4__OPTION__LEN,
    )

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 unknown option fields.
        """

        assert isinstance(self.type, Dhcp4OptionType), (
            f"The 'type' field must be a Dhcp4OptionType. "
            f"Got: {type(self.type)!r}"
        )

        assert int(self.type) not in Dhcp4OptionType.get_known_values(), (
            "The 'type' field must not be a core Dhcp4OptionType. "
            f"Got: {self.type!r}"
        )

        assert is_uint8(self.len), (
            f"The 'len' field must be an 8-bit unsigned integer. "
            f"Got: {self.len!r}"
        )

        assert self.len == DHCP4__OPTION__LEN + len(self.data), (
            "The 'len' field must reflect the length of the 'data' field. "
            f"Got: {self.len!r} != {DHCP4__OPTION__LEN + len(self.data)!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the unknown DHCPv4 option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the unknown DHCPv4 option as bytes.
        """

        return (
            struct.pack(
                DHCP4__OPTION__STRUCT,
                int(self.type),
                self.len,
            )
            + self.data
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the unknown DHCPv4 option integrity before parsing it.
        """

        if (value := _bytes[1]) > len(_bytes):
            raise Dhcp4IntegrityError(
                "The unknown DHCPv4 option length must be less than or equal to "
                f"the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes, /) -> Dhcp4OptionUnknown:
        """
        Initialize the unknown DHCPv4 option from bytes.
        """

        assert (value := len(_bytes)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the unknown DHCPv4 option must be "
            f"{DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) not in Dhcp4OptionType.get_known_values(), (
            f"The unknown DHCPv4 option type must not be known. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        Dhcp4OptionUnknown._validate_integrity(_bytes)

        return Dhcp4OptionUnknown(
            type=Dhcp4OptionType(_bytes[0]),
            len=_bytes[1],
            data=_bytes[DHCP4__OPTION__LEN : _bytes[1]],
        )
