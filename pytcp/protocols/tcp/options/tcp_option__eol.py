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
Module contains the TCP Eol (End of Option List) option support code.

pytcp/protocols/tcp/options/tcp_option__eol.py

ver 3.0.1
"""


from __future__ import annotations

from dataclasses import dataclass, field
from typing import override

from pytcp.protocols.tcp.options.tcp_option import TcpOption, TcpOptionType

# The TCP Eol (End of Option List) option [RFC 793].

# +-+-+-+-+-+-+-+-+
# |    Type = 0   |
# +-+-+-+-+-+-+-+-+


TCP__OPTION_EOL__LEN = 1


@dataclass(frozen=True, kw_only=True)
class TcpOptionEol(TcpOption):
    """
    The TCP Eol (End of Option List) option support.
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.EOL,
    )
    len: int = field(
        repr=False,
        init=False,
        default=TCP__OPTION_EOL__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Validate the TCP Eol option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the the TCP Eol option log string.
        """

        return "eol"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the TCP Eol option as bytes.
        """

        return bytes(self.type)

    @staticmethod
    def from_bytes(_bytes: bytes) -> TcpOptionEol:
        """
        Initialize the TCP Eol option from bytes.
        """

        assert (value := len(_bytes)) >= TCP__OPTION_EOL__LEN, (
            f"The minimum length of the TCP Eol option must be "
            f"{TCP__OPTION_EOL__LEN} byte. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(TcpOptionType.EOL), (
            f"The TCP Eol option type must be {TcpOptionType.EOL!r}. "
            f"Got: {TcpOptionType.from_int(value)!r}"
        )

        return TcpOptionEol()
