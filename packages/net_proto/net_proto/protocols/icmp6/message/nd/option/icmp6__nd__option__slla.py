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
This module contains the ICMPv6 ND Slla (Source Link Layer Address) option support code.

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__slla.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, MacAddress
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND Slla (Source Link Layer Address) option [RFC 4861].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 1   |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__OPTION__SLLA__LEN = 8
ICMP6__ND__OPTION__SLLA__STRUCT = "! BB 6s"


@dataclass(frozen=True, kw_only=False, slots=True)
class Icmp6NdOptionSlla(Icmp6NdOption):
    """
    The ICMPv6 ND Slla option support class.
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.SLLA,
    )
    len: int = field(
        repr=False,
        init=False,
        default=ICMP6__ND__OPTION__SLLA__LEN,
    )

    slla: MacAddress

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND Slla option fields.
        """

        assert isinstance(self.slla, MacAddress), f"The 'slla' field must be a MacAddress. Got: {type(self.slla)!r}"

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Slla option log string.
        """

        return f"slla {self.slla}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND Slla option as a memoryview.
        """

        struct.pack_into(
            ICMP6__ND__OPTION__SLLA__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len >> 3,
            bytes(self.slla),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the ICMPv6 ND Slla option before parsing it.
        """

        if (value := buffer[1] << 3) != ICMP6__ND__OPTION__SLLA__LEN:
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND Slla option length value must be "
                f"{ICMP6__ND__OPTION__SLLA__LEN} bytes. Got: {value!r}"
            )

        if (value := buffer[1] << 3) > len(buffer):
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND Slla option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND Slla option from buffer.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND Slla option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Icmp6NdOptionType.SLLA), (
            f"The ICMPv6 ND Slla option type must be {Icmp6NdOptionType.SLLA!r}. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(slla=MacAddress(buffer[2:8]))
