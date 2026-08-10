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
This module contains the unknown TCP option support code.

net_proto/protocols/tcp/options/tcp__option__unknown.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.tcp.options.tcp__option import (
    TCP__OPTION__LEN,
    TCP__OPTION__STRUCT,
    TcpOption,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError


@dataclass(frozen=True, kw_only=True, slots=True)
class TcpOptionUnknown(TcpOption):
    """
    The TCP unknown option support class.
    """

    type: TcpOptionType = field(
        repr=True,
        init=True,
        default=TcpOptionType.from_int(255),
    )
    len: int = field(
        repr=True,
        init=False,
    )

    data: Buffer

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the TCP unknown option fields.
        """

        assert isinstance(
            self.type, TcpOptionType
        ), f"The 'type' field must be a TcpOptionType. Got: {type(self.type)!r}"

        assert (
            int(self.type) not in TcpOptionType.get_known_values()
        ), f"The 'type' field must not be a known TcpOptionType. Got: {self.type!r}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", TCP__OPTION__LEN + len(self.data))

        assert is_uint8(self.len), f"The 'len' field must be an 8-bit unsigned integer. Got: {self.len!r}"

    @override
    def __str__(self) -> str:
        """
        Get the unknown TCP option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the unknown TCP option as a memoryview.
        """

        struct.pack_into(
            TCP__OPTION__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len,
        )

        buffer[TCP__OPTION__LEN:] = self.data

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the unknown TCP option before parsing it.
        """

        # RFC 9293 §3.2 (Case-2 TLV) — the option length byte
        # bounds the option within the TCP header region. For
        # unknown codepoints PyTCP preserves the wire bytes
        # verbatim (RFC 9293 §3.2 "Future options can be defined
        # ... TCP implementations MUST be able to receive them"),
        # so the only structural check is "length fits buffer".
        if (value := buffer[1]) > len(buffer):
            raise TcpIntegrityError(
                "The unknown TCP option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the unknown TCP option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= TCP__OPTION__LEN, (
            f"The minimum length of the unknown TCP option must be {TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (
            value := buffer[0]
        ) not in TcpOptionType.get_known_values(), (
            f"The unknown TCP option type must not be known. Got: {TcpOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            type=TcpOptionType(buffer[0]),
            data=buffer[TCP__OPTION__LEN : buffer[1]],
        )
