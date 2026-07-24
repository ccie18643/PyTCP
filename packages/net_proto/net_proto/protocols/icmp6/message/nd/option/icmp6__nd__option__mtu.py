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
This module contains the ICMPv6 ND MTU option support code.

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__mtu.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND MTU option [RFC 4861 §4.6.4].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 5   |    Length = 1 |           Reserved            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                              MTU                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__OPTION__MTU__LEN = 8
ICMP6__ND__OPTION__MTU__STRUCT = "! BB H L"


@dataclass(frozen=True, kw_only=False, slots=True)
class Icmp6NdOptionMtu(Icmp6NdOption):
    """
    The ICMPv6 ND MTU option support class.

    Carried in Router Advertisement messages to advertise the
    link MTU. Per RFC 4861 §4.6.4 the option MUST be silently
    ignored on any non-RA Neighbor Discovery message.
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.MTU,
    )
    len: int = field(
        repr=False,
        init=False,
        default=ICMP6__ND__OPTION__MTU__LEN,
    )

    mtu: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND MTU option fields.
        """

        assert is_uint32(self.mtu), f"The 'mtu' field must be a 32-bit unsigned integer. Got: {self.mtu!r}"

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND MTU option log string.
        """

        return f"mtu {self.mtu}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND MTU option as a memoryview.
        """

        struct.pack_into(
            ICMP6__ND__OPTION__MTU__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len >> 3,
            0,
            self.mtu,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the ICMPv6 ND MTU option before parsing it.
        """

        if (value := buffer[1] << 3) != ICMP6__ND__OPTION__MTU__LEN:
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND MTU option length value must be " f"{ICMP6__ND__OPTION__MTU__LEN} bytes. Got: {value!r}"
            )

        if (value := buffer[1] << 3) > len(buffer):
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND MTU option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND MTU option from buffer.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND MTU option must be " f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Icmp6NdOptionType.MTU), (
            f"The ICMPv6 ND MTU option type must be {Icmp6NdOptionType.MTU!r}. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        _type, _length, _reserved, mtu = struct.unpack(
            ICMP6__ND__OPTION__MTU__STRUCT,
            buffer[:ICMP6__ND__OPTION__MTU__LEN],
        )

        return cls(mtu=mtu)
