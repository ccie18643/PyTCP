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
This module contains the TCP Sackperm (SACK Permitted) option support code.

net_proto/protocols/tcp/options/tcp__option__sackperm.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.protocols.tcp.options.tcp__option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Sackperm (SACK Permitted) option [RFC 2018].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 4   |   Length = 2  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP__OPTION__SACKPERM__LEN = 2
TCP__OPTION__SACKPERM__STRUCT = "! BB"


@dataclass(frozen=True, kw_only=False, slots=True)
class TcpOptionSackperm(TcpOption):
    """
    The TCP Sackperm (SACK Permitted) option support class.
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.SACKPERM,
    )
    len: int = field(
        repr=False,
        init=False,
        default=TCP__OPTION__SACKPERM__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the TCP Sackperm option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the TCP Sackperm option log string.
        """

        return "sackperm"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP Sackperm option as a memoryview.
        """

        struct.pack_into(
            TCP__OPTION__SACKPERM__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the TCP Sackperm option before parsing it.
        """

        # RFC 2018 §2 — SACK-Permitted is exactly 2 octets:
        # 1-byte kind (4) + 1-byte length (2). No option data.
        if (value := buffer[1]) != TCP__OPTION__SACKPERM__LEN:
            raise TcpIntegrityError(
                f"The TCP Sackperm option length value must be {TCP__OPTION__SACKPERM__LEN} bytes. Got: {value!r}"
            )

        # The Sackperm option has no data, so the length should be exactly 2
        # and the option length integrity check (II) here wouldn't function
        # properly as the condition when length field is missing is already
        # being handled by an assert.

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the TCP Sackperm option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Sackperm option must be {TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(
            TcpOptionType.SACKPERM
        ), f"The TCP Sackperm option type must be {TcpOptionType.SACKPERM!r}. Got: {TcpOptionType.from_int(value)!r}"

        cls._validate_integrity(buffer)

        return cls()
