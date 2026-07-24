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
This module contains the DHCPv6 Option Request option support code.

net_proto/protocols/dhcp6/options/dhcp6__option__oro.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    DHCP6__OPTION__STRUCT,
    Dhcp6Option,
    Dhcp6OptionType,
)

# The DHCPv6 Option Request option (ORO) [RFC 8415 §21.7].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         OPTION_ORO = 6        |           option-len          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    requested-option-code-1    |    requested-option-code-2    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                              ...                              .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP6__OPTION__ORO__ELEMENT__LEN = 2
DHCP6__OPTION__ORO__ELEMENT__STRUCT = "! H"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp6OptionOro(Dhcp6Option):
    """
    The DHCPv6 Option Request option support class.
    """

    type: Dhcp6OptionType = field(
        repr=False,
        init=False,
        default=Dhcp6OptionType.ORO,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    requested_options: list[Dhcp6OptionType]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 Option Request option fields.
        """

        assert isinstance(
            self.requested_options, list
        ), f"The 'requested_options' field must be a list. Got: {type(self.requested_options)!r}"

        assert all(isinstance(item, Dhcp6OptionType) for item in self.requested_options), (
            f"The 'requested_options' field must be a list of Dhcp6OptionType elements. "
            f"Got: {[type(element) for element in self.requested_options]!r}"
        )

        assert len(self.requested_options) >= 1, (
            f"The 'requested_options' field must carry at least 1 requested option code "
            f"(RFC 8415 §21.7). Got: {len(self.requested_options)}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self, "len", DHCP6__OPTION__LEN + len(self.requested_options) * DHCP6__OPTION__ORO__ELEMENT__LEN
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv6 Option Request option log string.
        """

        return f"oro {[option.name for option in self.requested_options]}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 Option Request option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
        )

        for index, option in enumerate(self.requested_options):
            struct.pack_into(
                DHCP6__OPTION__ORO__ELEMENT__STRUCT,
                buffer,
                DHCP6__OPTION__LEN + index * DHCP6__OPTION__ORO__ELEMENT__LEN,
                int(option),
            )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv6 Option Request option before parsing it.
        """

        option_len = int.from_bytes(buffer[2:4])

        if option_len < DHCP6__OPTION__ORO__ELEMENT__LEN:
            raise Dhcp6IntegrityError(
                "The DHCPv6 Option Request option must carry at least one requested option "
                f"code (RFC 8415 §21.7). Got: {option_len!r}"
            )

        if (value := option_len % DHCP6__OPTION__ORO__ELEMENT__LEN) != 0:
            raise Dhcp6IntegrityError(
                f"The DHCPv6 Option Request option length value (less header) must be a multiple "
                f"of {DHCP6__OPTION__ORO__ELEMENT__LEN}. Got: {value!r}"
            )

        if (value := DHCP6__OPTION__LEN + option_len) > len(buffer):
            raise Dhcp6IntegrityError(
                "The DHCPv6 Option Request option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 Option Request option from buffer.
        """

        assert (value := len(buffer)) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the DHCPv6 Option Request option must "
            f"be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := int.from_bytes(buffer[0:2])) == int(Dhcp6OptionType.ORO), (
            f"The DHCPv6 Option Request option type must be {Dhcp6OptionType.ORO!r}. "
            f"Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        option_len = int.from_bytes(buffer[2:4])

        return cls(
            [
                Dhcp6OptionType.from_int(int.from_bytes(buffer[index : index + DHCP6__OPTION__ORO__ELEMENT__LEN]))
                for index in range(
                    DHCP6__OPTION__LEN, DHCP6__OPTION__LEN + option_len, DHCP6__OPTION__ORO__ELEMENT__LEN
                )
            ]
        )
