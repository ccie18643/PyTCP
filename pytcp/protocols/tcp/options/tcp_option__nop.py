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
This module contains TCP Nop (No Operation) option support code.

pytcp/protocols/tcp/options/tcp_option__nop.py

ver 3.0.3
"""


from dataclasses import dataclass, field
from typing import Self, override

from pytcp.protocols.tcp.options.tcp_option import TcpOption, TcpOptionType

# The TCP Nop (No Operation) option [RFC 793].

# +-+-+-+-+-+-+-+-+
# |    Type = 1   |
# +-+-+-+-+-+-+-+-+

TCP__OPTION__NOP__LEN = 1
TCP__OPTION__NOP__STRUCT = "! B"


@dataclass(frozen=True, kw_only=False, slots=True)
class TcpOptionNop(TcpOption):
    """
    The TCP Nop (No Operation) option support class.
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.NOP,
    )
    len: int = field(
        repr=False,
        init=False,
        default=TCP__OPTION__NOP__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Validate the TCP Nop option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the TCP Nop option log string.
        """

        return "nop"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the TCP Nop option as bytes.
        """

        return bytes(self.type)

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Initialize the TCP Nop option from bytes.
        """

        assert (value := len(_bytes)) >= TCP__OPTION__NOP__LEN, (
            f"The minimum length of the TCP Nop option must be "
            f"{TCP__OPTION__NOP__LEN} byte. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(TcpOptionType.NOP), (
            f"The TCP Nop option type must be {TcpOptionType.NOP!r}. "
            f"Got: {TcpOptionType.from_int(value)!r}"
        )

        return cls()
