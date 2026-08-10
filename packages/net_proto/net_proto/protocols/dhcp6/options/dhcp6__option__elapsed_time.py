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
This module contains the DHCPv6 Elapsed Time option support code.

net_proto/protocols/dhcp6/options/dhcp6__option__elapsed_time.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    Dhcp6Option,
    Dhcp6OptionType,
)

# The DHCPv6 Elapsed Time option [RFC 8415 §21.9].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    OPTION_ELAPSED_TIME = 8    |         option-len = 2        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          elapsed-time         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP6__OPTION__ELAPSED_TIME__LEN = 6
DHCP6__OPTION__ELAPSED_TIME__STRUCT = "! HH H"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp6OptionElapsedTime(Dhcp6Option):
    """
    The DHCPv6 Elapsed Time option support class.
    """

    type: Dhcp6OptionType = field(
        repr=False,
        init=False,
        default=Dhcp6OptionType.ELAPSED_TIME,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP6__OPTION__ELAPSED_TIME__LEN,
    )

    elapsed_time: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 Elapsed Time option fields.
        """

        assert is_uint16(
            self.elapsed_time
        ), f"The 'elapsed_time' field must be a 16-bit unsigned integer. Got: {self.elapsed_time}"

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv6 Elapsed Time option log string.
        """

        return f"elapsed_time {self.elapsed_time}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 Elapsed Time option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__ELAPSED_TIME__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
            self.elapsed_time,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv6 Elapsed Time option before parsing it.
        """

        if (value := DHCP6__OPTION__LEN + int.from_bytes(buffer[2:4])) != DHCP6__OPTION__ELAPSED_TIME__LEN:
            raise Dhcp6IntegrityError(
                "The DHCPv6 Elapsed Time option length value must be "
                f"{DHCP6__OPTION__ELAPSED_TIME__LEN} bytes. Got: {value!r}"
            )

        if (value := DHCP6__OPTION__LEN + int.from_bytes(buffer[2:4])) > len(buffer):
            raise Dhcp6IntegrityError(
                "The DHCPv6 Elapsed Time option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 Elapsed Time option from buffer.
        """

        assert (value := len(buffer)) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the DHCPv6 Elapsed Time option must "
            f"be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := int.from_bytes(buffer[0:2])) == int(Dhcp6OptionType.ELAPSED_TIME), (
            f"The DHCPv6 Elapsed Time option type must be {Dhcp6OptionType.ELAPSED_TIME!r}. "
            f"Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(int.from_bytes(buffer[DHCP6__OPTION__LEN : DHCP6__OPTION__LEN + 2]))
