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
Module contains the TCP Sack (Selective ACK) option support code.

pytcp/protocols/tcp/options/tcp_option__sack.py

ver 3.0.1
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.protocols.tcp.options.tcp_option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Sackp option [RFC 2018].

#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Type = 4   |   Length = 2  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Left Edge of 1st Block                     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                   Right Edge of 1st Block                     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    . . .                                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Left Edge of nth Block                     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                   Right Edge of nth Block                     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


TCP__OPTION_SACK__LEN = 2
TCP__OPTION_SACK__BLOCK_LEN = 8
TCP__OPTION_SACK__MAX_BLOCK_NUM = 4


@dataclass(frozen=True, kw_only=False)
class TcpSackBlock:
    """
    The TCP Sack block support class.
    """

    left: int
    right: int

    def __len__(self) -> int:
        """
        Get the TCP Sack block length.
        """

        return TCP__OPTION_SACK__BLOCK_LEN

    def __bytes__(self) -> bytes:
        """
        Get the TCP Sack block as bytes.
        """

        return struct.pack(
            "! LL",
            self.left,
            self.right,
        )

    def __str__(self) -> str:
        """
        Get the TCP Sack block log string.
        """

        return f"{self.left}-{self.right}"


@dataclass(frozen=True, kw_only=True)
class TcpOptionSack(TcpOption):
    """
    The TCP Sack option support class.
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.SACK,
    )
    len: int = field(
        repr=False,
        init=False,
        default=TCP__OPTION_SACK__LEN,
    )

    blocks: list[TcpSackBlock]

    @override
    def __post_init__(self) -> None:
        """
        Validate the TCP Sack option fields.
        """

        assert len(self.blocks) <= TCP__OPTION_SACK__MAX_BLOCK_NUM, (
            f"The 'blocks' field must have at most {TCP__OPTION_SACK__MAX_BLOCK_NUM} "
            f"elements. Got: {len(self.blocks)}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "len",
            TCP__OPTION_SACK__LEN
            + TCP__OPTION_SACK__BLOCK_LEN * len(self.blocks),
        )

    @override
    def __str__(self) -> str:
        """
        Get the TCP Sack option log string.
        """

        return f"sack [{', '.join([str(block) for block in self.blocks])}]"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the TCP Sack option as bytes.
        """

        return struct.pack(
            f"! BB {TCP__OPTION_SACK__BLOCK_LEN * len(self.blocks)}s",
            int(self.type),
            self.len,
            b"".join([bytes(block) for block in self.blocks]),
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes) -> None:
        """
        Validate the TCP Sack option integrity before parsing it.
        """

        if (value := _bytes[1]) > len(_bytes):
            raise TcpIntegrityError(
                "The TCP Sack option length must be less than or equal to "
                f"the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

        if (
            value := _bytes[1] - TCP__OPTION_SACK__LEN
        ) % TCP__OPTION_SACK__BLOCK_LEN:
            raise TcpIntegrityError(
                "The TCP Sack option blocks length must be a multiple of "
                f"{TCP__OPTION_SACK__BLOCK_LEN}. Got: {value!r}"
            )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> TcpOptionSack:
        """
        Initialize the TCP Sack option from bytes.
        """

        assert (value := len(_bytes)) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Sack option must be "
            f"{TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(TcpOptionType.SACK), (
            f"The TCP Sack option type must be {TcpOptionType.SACK!r}. "
            f"Got: {TcpOptionType.from_int(value)!r}"
        )

        TcpOptionSack._validate_integrity(_bytes)

        return TcpOptionSack(
            blocks=[
                TcpSackBlock(
                    left=int.from_bytes(
                        _bytes[
                            offset : offset + TCP__OPTION_SACK__BLOCK_LEN // 2
                        ]
                    ),
                    right=int.from_bytes(
                        _bytes[
                            offset
                            + TCP__OPTION_SACK__BLOCK_LEN // 2 : offset
                            + TCP__OPTION_SACK__BLOCK_LEN
                        ]
                    ),
                )
                for offset in range(
                    TCP__OPTION_SACK__LEN,
                    _bytes[1] - TCP__OPTION_SACK__LEN,
                    TCP__OPTION_SACK__BLOCK_LEN,
                )
            ]
        )
