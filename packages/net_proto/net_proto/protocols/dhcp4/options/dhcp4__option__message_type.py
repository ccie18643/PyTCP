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
This module contains the DHCPv4 Message Type option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__message_type.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Message Type option [RFC 2132].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Code = 53   |   Length = 1  |     Value     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__MESSAGE_TYPE__LEN = 3
DHCP4__OPTION__MESSAGE_TYPE__STRUCT = "! BB B"


@dataclass(frozen=True, kw_only=False, slots=True)
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
        Ensure integrity of the DHCPv4 Message Type option fields.
        """

        assert isinstance(
            self.message_type, Dhcp4MessageType
        ), f"The 'message_type' field must be a Dhcp4MessageType. Got: {type(self.message_type)!r}"

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Message Type option log string.
        """

        return f"message_type {self.message_type}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Message Type option as a memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__MESSAGE_TYPE__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            int(self.message_type),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Message Type option before parsing it.
        """

        if (value := DHCP4__OPTION__LEN + buffer[1]) != DHCP4__OPTION__MESSAGE_TYPE__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Message Type option length value must be "
                f"{DHCP4__OPTION__MESSAGE_TYPE__LEN} bytes. Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Message Type option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Message Type option from buffer.
        """

        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Message Type option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.MESSAGE_TYPE), (
            f"The DHCPv4 Message Type option type must be {Dhcp4OptionType.MESSAGE_TYPE!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(Dhcp4MessageType.from_int(buffer[2]))
