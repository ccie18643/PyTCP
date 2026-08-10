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
This module contains the DHCPv6 Preference option support code.

net_proto/protocols/dhcp6/options/dhcp6__option__preference.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    Dhcp6Option,
    Dhcp6OptionType,
)

# The DHCPv6 Preference option [RFC 8415 §21.8].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     OPTION_PREFERENCE = 7     |         option-len = 1        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   pref-value  |
# +-+-+-+-+-+-+-+-+


DHCP6__OPTION__PREFERENCE__LEN = 5
DHCP6__OPTION__PREFERENCE__STRUCT = "! HH B"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp6OptionPreference(Dhcp6Option):
    """
    The DHCPv6 Preference option support class.
    """

    type: Dhcp6OptionType = field(
        repr=False,
        init=False,
        default=Dhcp6OptionType.PREFERENCE,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP6__OPTION__PREFERENCE__LEN,
    )

    preference: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 Preference option fields.
        """

        assert is_uint8(
            self.preference
        ), f"The 'preference' field must be an 8-bit unsigned integer. Got: {self.preference}"

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv6 Preference option log string.
        """

        return f"preference {self.preference}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 Preference option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__PREFERENCE__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
            self.preference,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv6 Preference option before parsing it.
        """

        if (value := DHCP6__OPTION__LEN + int.from_bytes(buffer[2:4])) != DHCP6__OPTION__PREFERENCE__LEN:
            raise Dhcp6IntegrityError(
                "The DHCPv6 Preference option length value must be "
                f"{DHCP6__OPTION__PREFERENCE__LEN} bytes. Got: {value!r}"
            )

        if (value := DHCP6__OPTION__LEN + int.from_bytes(buffer[2:4])) > len(buffer):
            raise Dhcp6IntegrityError(
                "The DHCPv6 Preference option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 Preference option from buffer.
        """

        assert (value := len(buffer)) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the DHCPv6 Preference option must " f"be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := int.from_bytes(buffer[0:2])) == int(Dhcp6OptionType.PREFERENCE), (
            f"The DHCPv6 Preference option type must be {Dhcp6OptionType.PREFERENCE!r}. "
            f"Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(int.from_bytes(buffer[DHCP6__OPTION__LEN : DHCP6__OPTION__LEN + 1]))
