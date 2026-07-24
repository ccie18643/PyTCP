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
This module contains the TCP Wscale (Window Scale) option support code.

net_proto/protocols/tcp/options/tcp__option__wscale.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.tcp.options.tcp__option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Wscale option [RFC 7323 §2].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 3   |   Length = 3  |     Value     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP__OPTION__WSCALE__LEN = 3
TCP__OPTION__WSCALE__STRUCT = "! BB B"
TCP__OPTION__WSCALE__MAX_VALUE = 14


@dataclass(frozen=True, kw_only=False, slots=True)
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
        Ensure integrity of the TCP Wscale option fields.
        """

        assert is_uint8(self.wscale), (
            f"The 'wscale' field must be an 8-bit unsigned integer less than "
            f"or equal to {TCP__OPTION__WSCALE__MAX_VALUE}. Got: {self.wscale!r}"
        )

        assert self.wscale <= TCP__OPTION__WSCALE__MAX_VALUE, (
            f"The 'wscale' field must be an 8-bit unsigned integer less than "
            f"or equal to {TCP__OPTION__WSCALE__MAX_VALUE}. Got: {self.wscale!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the TCP Wscale option log string.
        """

        return f"wscale {self.wscale}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP Wscale option as a memoryview.
        """

        struct.pack_into(
            TCP__OPTION__WSCALE__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len,
            self.wscale,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the TCP Wscale option before parsing it.
        """

        # RFC 7323 §2 — Window Scale is fixed-shape: 1-byte kind +
        # 1-byte length + 1-byte shift count = 3 octets total.
        if (value := buffer[1]) != TCP__OPTION__WSCALE__LEN:
            raise TcpIntegrityError(
                f"The TCP Wscale option length value must be {TCP__OPTION__WSCALE__LEN} bytes. Got: {value!r}"
            )

        # RFC 7323 §2 / RFC 9293 §3.2 — option length MUST NOT
        # exceed the buffer available (defense-in-depth).
        if (value := buffer[1]) > len(buffer):
            raise TcpIntegrityError(
                "The TCP Wscale option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # NOTE: RFC 7323 §2.3 ("If a Window Scale option is
        # received with a shift.cnt value larger than 14, the TCP
        # SHOULD log the error but MUST use 14 instead of the
        # specified value") is honoured in `from_buffer` via the
        # `min(buffer[2], MAX_VALUE)` clamp — the over-14 case is
        # explicitly NOT an integrity violation but a tolerated
        # spec deviation.

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the TCP Wscale option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Wscale option must be {TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(
            TcpOptionType.WSCALE
        ), f"The TCP Wscale option type must be {TcpOptionType.WSCALE!r}. Got: {TcpOptionType.from_int(value)!r}"

        cls._validate_integrity(buffer)

        # Correct the received Wscale option value to maximum allowed
        # if it exceeds the limit.
        wscale = min(buffer[2], TCP__OPTION__WSCALE__MAX_VALUE)

        return cls(wscale=wscale)
