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
This module contains the TCP Mss (Maximum Segment Size) option support code.

net_proto/protocols/tcp/options/tcp__option__mss.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.tcp.options.tcp__option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Mss (Maximum Segment Size) option [RFC 9293 §3.7.1].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 2   |   Length = 4  |             Value             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP__OPTION__MSS__LEN = 4
TCP__OPTION__MSS__STRUCT = "! BB H"


@dataclass(frozen=True, kw_only=False, slots=True)
class TcpOptionMss(TcpOption):
    """
    The TCP Mss (Maximum Segment Size) option support class.
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.MSS,
    )
    len: int = field(
        repr=False,
        init=False,
        default=TCP__OPTION__MSS__LEN,
    )

    mss: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the TCP Mss option fields.
        """

        assert is_uint16(self.mss), f"The 'mss' field must be a 16-bit unsigned integer. Got: {self.mss!r}"

    @override
    def __str__(self) -> str:
        """
        Get the TCP Mss option log string.
        """

        return f"mss {self.mss}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP Mss option as a memoryview.
        """

        struct.pack_into(
            TCP__OPTION__MSS__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len,
            self.mss,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the TCP Mss option before parsing it.
        """

        # RFC 9293 §3.2 / RFC 6691 — MSS is fixed-shape: 1-byte
        # kind + 1-byte length + 16-bit MSS value = 4 octets total.
        if (value := buffer[1]) != TCP__OPTION__MSS__LEN:
            raise TcpIntegrityError(
                f"The TCP Mss option length value must be {TCP__OPTION__MSS__LEN} bytes. Got: {value!r}"
            )

        # RFC 9293 §3.2 — option length MUST NOT exceed the
        # buffer available (defense-in-depth; the equality check
        # above already implies this).
        if (value := buffer[1]) > len(buffer):
            raise TcpIntegrityError(
                "The TCP Mss option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the TCP Mss option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Mss option must be {TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(
            TcpOptionType.MSS
        ), f"The TCP Mss option type must be {TcpOptionType.MSS!r}. Got: {TcpOptionType.from_int(value)!r}"

        cls._validate_integrity(buffer)

        return cls(mss=int.from_bytes(buffer[2:4]))
