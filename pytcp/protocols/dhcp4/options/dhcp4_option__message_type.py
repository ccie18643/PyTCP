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
Module contains the DHCPv4 Message Type option support code.

pytcp/protocols/dhcp4/options/dhcp4_option__message_type.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType
from pytcp.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from pytcp.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Message Type option [RFC 2132].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 1   |   Length = 1  |     Value     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__MESSAGE_TYPE__LEN = 3
DHCP4__OPTION__MESSAGE_TYPE__STRUCT = "! BB B"


@dataclass(frozen=True, kw_only=False)
class Dhcp4OptionMessageType(Dhcp4Option):
    """
    The DHCPv4 Message Type option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.MESSAGE_TYPE,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__MESSAGE_TYPE__LEN,
    )

    message_type: Dhcp4MessageType

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 Message Type option fields.
        """

        assert isinstance(self.message_type, Dhcp4MessageType), (
            f"The 'message_type' field must be a Dhcp4MessageType. "
            f"Got: {type(self.message_type)!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Message Type option log string.
        """

        return f"message_type {self.message_type}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the DHCPv4 Message Type option as bytes.
        """

        return struct.pack(
            DHCP4__OPTION__MESSAGE_TYPE__STRUCT,
            int(self.type),
            self.len,
            int(self.message_type),
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the DHCPv4 Message Type option integrity before parsing it.
        """

        if (value := _bytes[1]) != DHCP4__OPTION__MESSAGE_TYPE__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Message Type option length must be "
                f"{DHCP4__OPTION__MESSAGE_TYPE__LEN} bytes. Got: {value!r}"
            )

        if (value := _bytes[1]) > len(_bytes):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Message Type option length must be less than or equal "
                f"to the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes, /) -> Dhcp4OptionMessageType:
        """
        Initialize the DHCPv4 Message Type option from bytes.
        """

        assert (value := len(_bytes)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Message Type option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(Dhcp4OptionType.MESSAGE_TYPE), (
            f"The DHCPv4 Message Type option type must be {Dhcp4OptionType.MESSAGE_TYPE!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        Dhcp4OptionMessageType._validate_integrity(_bytes)

        return Dhcp4OptionMessageType(Dhcp4MessageType.from_int(_bytes[2]))
