#!/usr/bin/env python3

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
Module contains the TCP Timestamps option support code.

pytcp/protocols/tcp/options/tcp_option__timestamps.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint32
from pytcp.protocols.tcp.options.tcp_option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Timestamps option [RFC 1323].

#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Type = 1   |   Length = 1  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             Tsval                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             Tsecr                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


TCP__OPTION__TIMESTAMPS__LEN = 10
TCP__OPTION__TIMESTAMPS__STRUCT = "! BB LL"


@dataclass
class TcpTimestamps:
    """
    The TCP Timestamps option values.
    """

    tsval: int
    tsecr: int


@dataclass(frozen=True, kw_only=True)
class TcpOptionTimestamps(TcpOption):
    """
    The TCP Timestamps option support class.
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.TIMESTAMPS,
    )
    len: int = field(
        repr=False,
        init=False,
        default=TCP__OPTION__TIMESTAMPS__LEN,
    )

    tsval: int
    tsecr: int

    @override
    def __post_init__(self) -> None:
        """
        Validate the TCP Timestamps option fields.
        """

        assert is_uint32(self.tsval), (
            f"The 'tsval' field must be a 32-bit unsigned integer. "
            f"Got: {self.tsval}"
        )

        assert is_uint32(self.tsecr), (
            f"The 'tsecr' field must be a 32-bit unsigned integer. "
            f"Got: {self.tsecr}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the TCP Timestamps option log string.
        """

        return f"timestamps {self.tsval}/{self.tsecr}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the TCP Timestamps option as bytes.
        """

        return struct.pack(
            TCP__OPTION__TIMESTAMPS__STRUCT,
            int(self.type),
            self.len,
            self.tsval,
            self.tsecr,
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the TCP Timestamps option integrity before parsing it.
        """

        if (value := _bytes[1]) != TCP__OPTION__TIMESTAMPS__LEN:
            raise TcpIntegrityError(
                f"The TCP Timestamps option length must be {TCP__OPTION__TIMESTAMPS__LEN} "
                f"bytes. Got: {value!r}"
            )

        if (value := _bytes[1]) > len(_bytes):
            raise TcpIntegrityError(
                "The TCP Timestamps option length must be less than or equal to "
                f"the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes, /) -> TcpOptionTimestamps:
        """
        Initialize the TCP Timestamps option from bytes.
        """

        assert (value := len(_bytes)) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Timestamps option must be "
            f"{TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(TcpOptionType.TIMESTAMPS), (
            f"The TCP Timestamps option type must be {TcpOptionType.TIMESTAMPS!r}. "
            f"Got: {TcpOptionType.from_int(value)!r}"
        )

        TcpOptionTimestamps._validate_integrity(_bytes)

        _, _, tsval, tsecr = struct.unpack_from(
            TCP__OPTION__TIMESTAMPS__STRUCT, _bytes
        )

        return TcpOptionTimestamps(
            tsval=tsval,
            tsecr=tsecr,
        )
