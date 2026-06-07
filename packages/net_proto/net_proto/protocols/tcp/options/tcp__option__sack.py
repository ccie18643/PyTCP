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
This module contains the TCP Sack (Selective ACK) option support code.

net_proto/protocols/tcp/options/tcp__option__sack.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.tcp.options.tcp__option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Sack option [RFC 2018].

#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Type = 5   |   Length = N  |
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

TCP__OPTION__SACK__STRUCT = "! BB"
TCP__OPTION__SACK__LEN = 2
TCP__OPTION__SACK__BLOCK_LEN = 8
TCP__OPTION__SACK__BLOCK_STRUCT = "! LL"
TCP__OPTION__SACK__MAX_BLOCK_NUM = 4


@dataclass(frozen=True, kw_only=False, slots=True)
class TcpSackBlock:
    """
    The TCP Sack block support class.
    """

    left: int
    right: int

    def __post_init__(self) -> None:
        """
        Ensure integrity of the TCP Sack block fields.
        """

        # RFC 2018 §3 — "Each contiguous block of data queued at the
        # data receiver is defined in the SACK option by two 32-bit
        # unsigned integers in network byte order". The wire path
        # already trims each block to 4 bytes via `int.from_bytes`,
        # so this assert catches programmer error at construction
        # with a clear message instead of an opaque struct.error
        # ("'L' format requires 0 <= number <= 4294967295") at
        # __buffer__ serialization. Note: the RFC does NOT mandate
        # `left < right` — sequence-number wraparound makes the
        # ordering meaningless modulo 2**32, so no ordering check.
        assert is_uint32(self.left), (
            f"The 'left' field must be a 32-bit unsigned integer (RFC 2018 §3). " f"Got: {self.left!r}"
        )

        assert is_uint32(self.right), (
            f"The 'right' field must be a 32-bit unsigned integer (RFC 2018 §3). " f"Got: {self.right!r}"
        )

    def __len__(self) -> int:
        """
        Get the TCP Sack block length.
        """

        return TCP__OPTION__SACK__BLOCK_LEN

    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP Sack block as a memoryview.
        """

        struct.pack_into(
            TCP__OPTION__SACK__BLOCK_STRUCT,
            buffer := bytearray(len(self)),
            0,
            self.left,
            self.right,
        )

        return memoryview(buffer)

    @override
    def __str__(self) -> str:
        """
        Get the TCP Sack block log string.
        """

        return f"{self.left}-{self.right}"


@dataclass(frozen=True, kw_only=False, slots=True)
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
    )

    blocks: list[TcpSackBlock]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the TCP Sack option fields.
        """

        assert (value := len(self.blocks)) <= TCP__OPTION__SACK__MAX_BLOCK_NUM, (
            f"The 'blocks' field must have at most {TCP__OPTION__SACK__MAX_BLOCK_NUM} " f"elements. Got: {value!r}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "len",
            TCP__OPTION__LEN + TCP__OPTION__SACK__BLOCK_LEN * len(self.blocks),
        )

    @override
    def __str__(self) -> str:
        """
        Get the TCP Sack option log string.
        """

        return f"sack [{', '.join([str(block) for block in self.blocks])}]"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP Sack option as a memoryview.
        """

        struct.pack_into(
            TCP__OPTION__SACK__STRUCT,
            buffer := bytearray(TCP__OPTION__SACK__LEN),
            0,
            int(self.type),
            self.len,
        )

        for block in self.blocks:
            buffer.extend(bytearray(block))

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the TCP Sack option before parsing it.
        """

        # RFC 2018 §3 — option length MUST NOT exceed the buffer
        # available (the parent options walker trims to hlen).
        if (value := buffer[1]) > len(buffer):
            raise TcpIntegrityError(
                "The TCP Sack option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # RFC 2018 §3 — each SACK block is exactly 8 octets
        # (32-bit Left Edge + 32-bit Right Edge); the option data
        # region (length minus 2-byte header) MUST be a whole
        # number of blocks.
        if (value := buffer[1] - TCP__OPTION__LEN) % TCP__OPTION__SACK__BLOCK_LEN:
            raise TcpIntegrityError(
                "The TCP Sack option blocks length value must be a multiple of "
                f"{TCP__OPTION__SACK__BLOCK_LEN}. Got: {value!r}"
            )

        # RFC 2018 §3 — "The maximum number of SACK blocks that
        # can be carried in a TCP packet is limited by the
        # maximum size of the TCP options field (40 bytes)";
        # 40 − 2 (option header) = 38, 38 / 8 = 4 blocks
        # ceiling. Defense-in-depth at the integrity layer so a
        # wire frame with 5+ blocks does not leak as a bare
        # AssertionError out of the dataclass __post_init__.
        if (value := (buffer[1] - TCP__OPTION__LEN) // TCP__OPTION__SACK__BLOCK_LEN) > TCP__OPTION__SACK__MAX_BLOCK_NUM:
            raise TcpIntegrityError(
                f"The TCP Sack option must carry at most {TCP__OPTION__SACK__MAX_BLOCK_NUM} blocks. " f"Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the TCP Sack option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Sack option must be {TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(
            TcpOptionType.SACK
        ), f"The TCP Sack option type must be {TcpOptionType.SACK!r}. Got: {TcpOptionType.from_int(value)!r}"

        cls._validate_integrity(buffer)

        return cls(
            blocks=[
                TcpSackBlock(
                    left=int.from_bytes(buffer[offset : offset + TCP__OPTION__SACK__BLOCK_LEN // 2]),
                    right=int.from_bytes(
                        buffer[offset + TCP__OPTION__SACK__BLOCK_LEN // 2 : offset + TCP__OPTION__SACK__BLOCK_LEN]
                    ),
                )
                for offset in range(
                    TCP__OPTION__LEN,
                    buffer[1],
                    TCP__OPTION__SACK__BLOCK_LEN,
                )
            ]
        )
