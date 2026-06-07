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
This module contains the IPv6 Hop-by-Hop Options PadN option support code.

net_proto/protocols/ip6_hbh/options/ip6_hbh__option__padn.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhIntegrityError
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import (
    IP6_HBH__OPTION__LEN,
    IP6_HBH__OPTION__STRUCT,
    Ip6HbhOption,
    Ip6HbhOptionType,
)

# The IPv6 Hop-by-Hop Options PadN option [RFC 8200 §4.2].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |       1       |  Opt Data Len |  Option Data...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Type=1, Opt Data Len=N, N bytes of payload (SHOULD be all-zero
# but receivers MUST accept any value). Total option length on the
# wire is N + 2 (the 2-byte Type/Length prefix).

IP6_HBH__OPTION__PADN__MIN_LEN = IP6_HBH__OPTION__LEN  # 2-byte header, 0 data bytes minimum.


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip6HbhOptionPadN(Ip6HbhOption):
    """
    The IPv6 Hop-by-Hop Options PadN option support class.
    """

    type: Ip6HbhOptionType = field(
        repr=False,
        init=False,
        default=Ip6HbhOptionType.PADN,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv6 HBH PadN option fields.
        """

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", IP6_HBH__OPTION__LEN + len(self.data))

        assert is_uint8(self.len), f"The 'len' field must be an 8-bit unsigned integer. Got: {self.len!r}"

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 HBH PadN option log string.
        """

        return f"padN ({self.len - IP6_HBH__OPTION__LEN})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 HBH PadN option as a memoryview.
        """

        struct.pack_into(
            IP6_HBH__OPTION__STRUCT,
            buffer := bytearray(self.len),
            0,
            int(self.type),
            self.len - IP6_HBH__OPTION__LEN,
        )

        buffer[IP6_HBH__OPTION__LEN:] = self.data

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv6 HBH PadN option before parsing it.
        """

        if (value := buffer[1] + IP6_HBH__OPTION__LEN) > len(buffer):
            raise Ip6HbhIntegrityError(
                "The IPv6 HBH PadN option length value must not extend past the "
                f"length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv6 HBH PadN option from buffer.
        """

        assert (value := len(buffer)) >= IP6_HBH__OPTION__PADN__MIN_LEN, (
            f"The minimum length of the IPv6 HBH PadN option must be "
            f"{IP6_HBH__OPTION__PADN__MIN_LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip6HbhOptionType.PADN), (
            f"The IPv6 HBH PadN option type must be {Ip6HbhOptionType.PADN!r}. "
            f"Got: {Ip6HbhOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(data=bytes(buffer[IP6_HBH__OPTION__LEN : IP6_HBH__OPTION__LEN + buffer[1]]))
