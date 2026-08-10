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
This module contains the DHCPv4 Renewal (T1) Time Value option
support code (RFC 2132 §9.7).

net_proto/protocols/dhcp4/options/dhcp4__option__renewal_time.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Renewal (T1) Time Value option [RFC 2132 §9.7].
#
#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Code = 58  |   Length = 4  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       T1 Interval (seconds)                   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

DHCP4__OPTION__RENEWAL_TIME__LEN = 6
DHCP4__OPTION__RENEWAL_TIME__STRUCT = "! BB I"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionRenewalTime(Dhcp4Option):
    """
    The DHCPv4 Renewal (T1) Time Value option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.RENEWAL_TIME,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__RENEWAL_TIME__LEN,
    )

    renewal_time: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Renewal Time option fields.
        """

        assert is_uint32(
            self.renewal_time
        ), f"The 'renewal_time' field must be a 32-bit unsigned integer. Got: {self.renewal_time}"

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Renewal Time option log string.
        """

        return f"renewal_time {self.renewal_time}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Renewal Time option as a memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__RENEWAL_TIME__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            int(self.renewal_time),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Renewal Time option before parsing it.
        """

        if (value := DHCP4__OPTION__LEN + buffer[1]) != DHCP4__OPTION__RENEWAL_TIME__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Renewal Time option length value must be "
                f"{DHCP4__OPTION__RENEWAL_TIME__LEN} bytes. Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Renewal Time option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Renewal Time option from buffer.
        """

        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Renewal Time option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.RENEWAL_TIME), (
            f"The DHCPv4 Renewal Time option type must be {Dhcp4OptionType.RENEWAL_TIME!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(int.from_bytes(buffer[2:6], "big"))
