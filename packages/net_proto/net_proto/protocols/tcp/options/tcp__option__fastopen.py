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
This module contains the TCP Fast Open (TFO) option support code.

net_proto/protocols/tcp/options/tcp__option__fastopen.py

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

# The TCP Fast Open option [RFC 7413].
#
#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Type = 34  |   Length = N  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  Cookie (variable, 0 or 4..16)                ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Length = 2 (empty cookie, the 'cookie request' form a client
# sends to a server it has not yet received a cookie from), or
# Length = 6..18 (a 4..16 byte cookie, the 'cookie response' form
# the server returns and the 'cookie use' form the client sends on
# subsequent connections to the same server).

TCP__OPTION__FASTOPEN__LEN_MIN = 2
TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN = 4
TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX = 16
TCP__OPTION__FASTOPEN__STRUCT = "! BB"


@dataclass(frozen=True, kw_only=True, slots=True)
class TcpOptionFastOpen(TcpOption):
    """
    The TCP Fast Open option support class.
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.FASTOPEN,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    cookie: bytes

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the TCP Fast Open option fields.
        """

        assert isinstance(self.cookie, bytes), f"The 'cookie' field must be 'bytes'. Got: {type(self.cookie)!r}"

        cookie_len = len(self.cookie)
        assert cookie_len == 0 or (
            TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN <= cookie_len <= TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX
        ), (
            f"The 'cookie' field must be empty or "
            f"{TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN}..{TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX} bytes. "
            f"Got: {cookie_len} bytes."
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", TCP__OPTION__FASTOPEN__LEN_MIN + cookie_len)

    @override
    def __str__(self) -> str:
        """
        Get the TCP Fast Open option log string.
        """

        if not self.cookie:
            return "fastopen request"
        return f"fastopen {self.cookie.hex()}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP Fast Open option as a memoryview.
        """

        buffer = bytearray(len(self))
        struct.pack_into(
            TCP__OPTION__FASTOPEN__STRUCT,
            buffer,
            0,
            int(self.type),
            self.len,
        )
        buffer[TCP__OPTION__FASTOPEN__LEN_MIN:] = self.cookie

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the TCP Fast Open option before parsing it.
        """

        # RFC 7413 §2 — TCP Fast Open has a 2-byte (Kind + Length)
        # header at minimum; the request form is exactly 2 octets
        # (empty cookie), the response/use form is 6..18 octets
        # (4..16-byte cookie).
        if (value := buffer[1]) < TCP__OPTION__FASTOPEN__LEN_MIN:
            raise TcpIntegrityError(
                f"The TCP Fast Open option length value must be at least "
                f"{TCP__OPTION__FASTOPEN__LEN_MIN} bytes. Got: {value!r}"
            )

        # RFC 9293 §3.2 — option length MUST NOT exceed the
        # buffer available.
        if (value := buffer[1]) > len(buffer):
            raise TcpIntegrityError(
                "The TCP Fast Open option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # RFC 7413 §2 — "A Fast Open Cookie is between 4 and 16
        # bytes (inclusive) in length"; cookie_len = 0 is the
        # request-form (cookie not yet known).
        cookie_len = buffer[1] - TCP__OPTION__FASTOPEN__LEN_MIN
        if cookie_len != 0 and not (
            TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN <= cookie_len <= TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX
        ):
            raise TcpIntegrityError(
                f"The TCP Fast Open option cookie length must be 0 or "
                f"{TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN}..{TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX} bytes. "
                f"Got: {cookie_len}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the TCP Fast Open option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Fast Open option must be {TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(TcpOptionType.FASTOPEN), (
            f"The TCP Fast Open option type must be {TcpOptionType.FASTOPEN!r}. "
            f"Got: {TcpOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        option_len = buffer[1]
        cookie = bytes(buffer[TCP__OPTION__FASTOPEN__LEN_MIN:option_len])

        return cls(cookie=cookie)
