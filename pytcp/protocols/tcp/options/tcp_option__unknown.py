#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains the unknown TCP option support code.

pytcp/protocols/tcp/options/tcp_option__unknown.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint8
from pytcp.protocols.tcp.options.tcp_option import (
    TCP__OPTION__LEN,
    TCP__OPTION__STRUCT,
    TcpOption,
    TcpOptionType,
)
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError


@dataclass(frozen=True, kw_only=True)
class TcpOptionUnknown(TcpOption):
    """
    The TCP unknown option support class.
    """

    type: TcpOptionType = field(
        repr=True, init=True, default=TcpOptionType.from_int(255)
    )
    len: int = field(repr=True, init=True, default=TCP__OPTION__LEN)

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Validate the TCP unknown option fields.
        """

        assert isinstance(
            self.type, TcpOptionType
        ), f"The 'type' field must be a TcpOptionType. Got: {type(self.type)!r}"

        assert is_uint8(
            self.len
        ), f"The 'len' field must be an 8-bit unsigned integer. Got: {self.len!r}"

    @override
    def __str__(self) -> str:
        """
        Get the unknown TCP option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the unknown TCP option as bytes.
        """

        return (
            struct.pack(
                TCP__OPTION__STRUCT,
                int(self.type),
                self.len,
            )
            + self.data
        )

    @staticmethod
    def from_bytes(_bytes: bytes) -> TcpOptionUnknown:
        """
        Initialize the unknown TCP option from bytes.
        """

        assert len(_bytes) >= 2
        assert _bytes[0] not in TcpOptionType.get_core_values()

        # There is no option length integrity check (I) here as the length
        # of the unown option is not known in advance.

        if _bytes[1] > len(_bytes):
            raise TcpIntegrityError("Invalid unknown option length (II).")

        return TcpOptionUnknown(
            type=TcpOptionType(_bytes[0]),
            len=_bytes[1],
            data=_bytes[2 : _bytes[1]],
        )
