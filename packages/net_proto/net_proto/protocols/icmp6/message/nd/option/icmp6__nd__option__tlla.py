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
This module contains the ICMPv6 ND Tlla (Target Link Layer Address) option support code.

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__tlla.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import MacAddress
from net_proto.lib.buffer import Buffer
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND Tlla (Target Link Layer Address) option [RFC 4861].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 2   |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__OPTION__TLLA__LEN = 8
ICMP6__ND__OPTION__TLLA__STRUCT = "! BB 6s"


@dataclass(frozen=True, kw_only=False, slots=True)
class Icmp6NdOptionTlla(Icmp6NdOption):
    """
    The ICMPv6 ND Tlla option support class.
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.TLLA,
    )
    len: int = field(
        repr=False,
        init=False,
        default=ICMP6__ND__OPTION__TLLA__LEN,
    )

    tlla: MacAddress

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND Tlla option fields.
        """

        assert isinstance(self.tlla, MacAddress), f"The 'tlla' field must be a MacAddress. Got: {type(self.tlla)!r}"

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Tlla option log string.
        """

        return f"tlla {self.tlla}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND Tlla option as a memoryview.
        """

        struct.pack_into(
            ICMP6__ND__OPTION__TLLA__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len >> 3,
            bytes(self.tlla),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the ICMPv6 ND Tlla option before parsing it.
        """

        if (value := buffer[1] << 3) != ICMP6__ND__OPTION__TLLA__LEN:
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND Tlla option length value must be {ICMP6__ND__OPTION__TLLA__LEN} "
                f"bytes. Got: {value!r}"
            )

        if (value := buffer[1] << 3) > len(buffer):
            raise Icmp6IntegrityError(
                "The ICMPv6 ND Tlla option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND Tlla option from buffer.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND Tlla option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Icmp6NdOptionType.TLLA), (
            f"The ICMPv6 ND Tlla option type must be {Icmp6NdOptionType.TLLA!r}. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(tlla=MacAddress(buffer[2:8]))
