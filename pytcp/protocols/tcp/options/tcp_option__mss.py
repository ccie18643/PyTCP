#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains the TCP Mss (Maximum Segment Size) option support code.

pytcp/protocols/tcp/options/tcp_option__mss.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import is_uint16
from pytcp.protocols.tcp.options.tcp_option import TcpOption, TcpOptionType
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Mss (Maximum Segment Size) option [RFC 793].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 1   |   Length = 1  |             Value             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


TCP__OPTION_MSS__LEN = 4


@dataclass(frozen=True, kw_only=True)
class TcpOptionMss(TcpOption):
    """
    The TCP Mss (Maximum Segment Size) option support class.
    """

    type: TcpOptionType = field(
        repr=False, init=False, default=TcpOptionType.MSS
    )
    len: int = field(repr=False, init=False, default=TCP__OPTION_MSS__LEN)

    mss: int

    @override
    def __post_init__(self) -> None:
        """
        Validate the TCP Mss option fields.
        """

        assert is_uint16(
            self.mss
        ), f"The 'mss' field must be a 16-bit unsigned integer. Got: {self.mss}"

    @override
    def __str__(self) -> str:
        """
        Get the TCP Mss option log string.
        """

        return f"mss {self.mss}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the TCP Mss option as bytes.
        """

        return struct.pack(
            "! BB H",
            int(self.type),
            self.len,
            self.mss,
        )

    @staticmethod
    def from_bytes(_bytes: bytes) -> TcpOptionMss:
        """
        Initialize the TCP Mss option from bytes.
        """

        assert len(_bytes) >= 2
        assert _bytes[0] == int(TcpOptionType.MSS)

        if _bytes[1] != TCP__OPTION_MSS__LEN:
            raise TcpIntegrityError("Invalid Mss option length (I).")

        if _bytes[1] > len(_bytes):
            raise TcpIntegrityError("Invalid Mss option length (II).")

        return TcpOptionMss(mss=int.from_bytes(_bytes[2:4]))
