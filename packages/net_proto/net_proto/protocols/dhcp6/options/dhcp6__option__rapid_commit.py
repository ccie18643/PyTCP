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
This module contains the DHCPv6 Rapid Commit option support code.

net_proto/protocols/dhcp6/options/dhcp6__option__rapid_commit.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    DHCP6__OPTION__STRUCT,
    Dhcp6Option,
    Dhcp6OptionType,
)

# The DHCPv6 Rapid Commit option [RFC 8415 §21.14].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    OPTION_RAPID_COMMIT = 14   |         option-len = 0        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP6__OPTION__RAPID_COMMIT__LEN = 4


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6OptionRapidCommit(Dhcp6Option):
    """
    The DHCPv6 Rapid Commit option support class.
    """

    type: Dhcp6OptionType = field(
        repr=False,
        init=False,
        default=Dhcp6OptionType.RAPID_COMMIT,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP6__OPTION__RAPID_COMMIT__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 Rapid Commit option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv6 Rapid Commit option log string.
        """

        return "rapid_commit"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 Rapid Commit option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv6 Rapid Commit option before parsing it.
        """

        # RFC 8415 §21.14 — "The Rapid Commit option ... has no data;
        # its option-len MUST be 0."
        if (value := int.from_bytes(buffer[2:4])) != 0:
            raise Dhcp6IntegrityError(
                f"The DHCPv6 Rapid Commit option length value must be 0 (RFC 8415 §21.14). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 Rapid Commit option from buffer.
        """

        assert (value := len(buffer)) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the DHCPv6 Rapid Commit option must "
            f"be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := int.from_bytes(buffer[0:2])) == int(Dhcp6OptionType.RAPID_COMMIT), (
            f"The DHCPv6 Rapid Commit option type must be {Dhcp6OptionType.RAPID_COMMIT!r}. "
            f"Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls()
