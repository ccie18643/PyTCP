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
This module contains the TCP Timestamps option support code.

net_proto/protocols/tcp/options/tcp__option__timestamps.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.tcp.options.tcp__option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Timestamps option [RFC 7323 §3].

#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Type = 8   |   Length = 10 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             Tsval                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             Tsecr                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP__OPTION__TIMESTAMPS__LEN = 10
TCP__OPTION__TIMESTAMPS__STRUCT = "! BB LL"


@dataclass(frozen=True, kw_only=False, slots=True)
class TcpTimestamps:
    """
    The TCP Timestamps option values.
    """

    tsval: int
    tsecr: int


@dataclass(frozen=True, kw_only=True, slots=True)
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
        Ensure integrity of the TCP Timestamps option fields.
        """

        assert is_uint32(self.tsval), f"The 'tsval' field must be a 32-bit unsigned integer. Got: {self.tsval!r}"

        assert is_uint32(self.tsecr), f"The 'tsecr' field must be a 32-bit unsigned integer. Got: {self.tsecr!r}"

    @override
    def __str__(self) -> str:
        """
        Get the TCP Timestamps option log string.
        """

        return f"timestamps {self.tsval}/{self.tsecr}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP Timestamps option as a memoryview.
        """

        struct.pack_into(
            TCP__OPTION__TIMESTAMPS__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len,
            self.tsval,
            self.tsecr,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the TCP Timestamps option before parsing it.
        """

        # RFC 7323 §3 — Timestamps is fixed-shape: 1-byte kind +
        # 1-byte length + 4-byte TS Value + 4-byte TS Echo Reply
        # = 10 octets total.
        if (value := buffer[1]) != TCP__OPTION__TIMESTAMPS__LEN:
            raise TcpIntegrityError(
                f"The TCP Timestamps option length value must be {TCP__OPTION__TIMESTAMPS__LEN} bytes. Got: {value!r}"
            )

        # RFC 7323 §3 / RFC 9293 §3.2 — option length MUST NOT
        # exceed the buffer available (defense-in-depth).
        if (value := buffer[1]) > len(buffer):
            raise TcpIntegrityError(
                "The TCP Timestamps option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the TCP Timestamps option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Timestamps option must be {TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(TcpOptionType.TIMESTAMPS), (
            f"The TCP Timestamps option type must be {TcpOptionType.TIMESTAMPS!r}. "
            f"Got: {TcpOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        _, _, tsval, tsecr = struct.unpack_from(TCP__OPTION__TIMESTAMPS__STRUCT, buffer)

        return cls(
            tsval=tsval,
            tsecr=tsecr,
        )
