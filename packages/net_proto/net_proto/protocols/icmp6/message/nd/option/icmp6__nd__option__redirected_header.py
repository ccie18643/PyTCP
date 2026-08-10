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
This module contains the ICMPv6 ND Redirected Header option support code.

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__redirected_header.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_8_byte_alligned, is_uint8
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND Redirected Header option [RFC 4861 §4.6.3].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 4   |     Length    |            Reserved           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# ~                       IP header + data                        ~
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Fixed-portion length: type(1) + length(1) + reserved(6) = 8 bytes.
ICMP6__ND__OPTION__REDIRECTED_HEADER__LEN = 8
ICMP6__ND__OPTION__REDIRECTED_HEADER__STRUCT = "! BB 6s"


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOptionRedirectedHeader(Icmp6NdOption):
    """
    The ICMPv6 ND Redirected Header option support class.

    Carries the original packet (IP header + leading payload) that
    triggered the Redirect, so the host can correlate the Redirect
    with the flow that prompted it. The total option size MUST be
    8-byte aligned per RFC 4861 §4.6 — the carried packet is
    assumed to be padded by the caller; this class does not pad.
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.REDIRECTED_HEADER,
    )
    len: int = field(
        repr=True,
        init=False,
    )

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND Redirected Header option fields.
        """

        assert isinstance(self.data, bytes), f"The 'data' field must be bytes. Got: {type(self.data)!r}"

        object.__setattr__(self, "len", ICMP6__ND__OPTION__REDIRECTED_HEADER__LEN + len(self.data))

        assert is_uint8(self.len), f"The 'len' field must be an 8-bit unsigned integer. Got: {self.len!r}"

        assert is_8_byte_alligned(self.len), (
            f"The 'len' field must be 8-byte aligned. "
            f"Got: {self.len!r} (data length {len(self.data)} not a multiple of 8)"
        )

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND Redirected Header option log string.
        """

        return f"redirected-header {len(self.data)}B"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND Redirected Header option as a memoryview.
        """

        struct.pack_into(
            ICMP6__ND__OPTION__REDIRECTED_HEADER__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len >> 3,
            b"\x00\x00\x00\x00\x00\x00",
        )

        buffer[ICMP6__ND__OPTION__REDIRECTED_HEADER__LEN:] = self.data

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the ICMPv6 ND Redirected Header option before parsing it.
        """

        if (encoded := buffer[1] << 3) < ICMP6__ND__OPTION__REDIRECTED_HEADER__LEN:
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND Redirected Header option length value must be at least "
                f"{ICMP6__ND__OPTION__REDIRECTED_HEADER__LEN} bytes. Got: {encoded!r}"
            )

        if encoded > len(buffer):
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND Redirected Header option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {encoded!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND Redirected Header option from buffer.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND Redirected Header option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Icmp6NdOptionType.REDIRECTED_HEADER), (
            f"The ICMPv6 ND Redirected Header option type must be "
            f"{Icmp6NdOptionType.REDIRECTED_HEADER!r}. Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(data=bytes(buffer[ICMP6__ND__OPTION__REDIRECTED_HEADER__LEN : buffer[1] << 3]))
