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
Module contains TCP Wscale (Window Scale) option support code.

pytcp/protocols/tcp/options/tcp_option__wscale.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint8
from pytcp.protocols.tcp.options.tcp_option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Wscale option [RFC 1323].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 3   |   Length = 3  |     Value     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


TCP__OPTION__WSCALE__LEN = 3
TCP__OPTION__WSCALE__STRUCT = "! BB B"
TCP__OPTION__WSCALE__MAX_VALUE = 14


@dataclass(frozen=True, kw_only=False)
class TcpOptionWscale(TcpOption):
    """
    The TCP Wscale (Window Scale) option support class.
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.WSCALE,
    )
    len: int = field(
        repr=False,
        init=False,
        default=TCP__OPTION__WSCALE__LEN,
    )

    wscale: int

    @override
    def __post_init__(self) -> None:
        """
        Validate the TCP Wscale option fields.
        """

        assert (
            is_uint8(self.wscale)
            and self.wscale <= TCP__OPTION__WSCALE__MAX_VALUE
        ), (
            f"The 'wscale' field must be a 8-bit unsigned integer less than "
            f"or equal to {TCP__OPTION__WSCALE__MAX_VALUE}. Got: {self.wscale}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the TCP Wscale option log string.
        """

        return f"wscale {self.wscale}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the TCP Wscale option as bytes.
        """

        return struct.pack(
            TCP__OPTION__WSCALE__STRUCT,
            int(self.type),
            self.len,
            self.wscale,
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the TCP Wscale option integrity before parsing it.
        """

        if (value := _bytes[1]) != TCP__OPTION__WSCALE__LEN:
            raise TcpIntegrityError(
                f"The TCP Wscale option length must be {TCP__OPTION__WSCALE__LEN} "
                f"bytes. Got: {value!r}"
            )

        if (value := _bytes[1]) > len(_bytes):
            raise TcpIntegrityError(
                "The TCP Wscale option length must be less than or equal to "
                f"the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes, /) -> TcpOptionWscale:
        """
        Initialize the TCP Wscale option from bytes.
        """

        assert (value := len(_bytes)) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Wscale option must be "
            f"{TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(TcpOptionType.WSCALE), (
            f"The TCP Wscale option type must be {TcpOptionType.WSCALE!r}. "
            f"Got: {TcpOptionType.from_int(value)!r}"
        )

        TcpOptionWscale._validate_integrity(_bytes)

        # Correct the received Wscale option value to maximum allowed
        # if it exceeds the limit.
        wscale = min(_bytes[2], TCP__OPTION__WSCALE__MAX_VALUE)

        return TcpOptionWscale(wscale=wscale)
