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
This module contains the IPv4 Eol (End of Option List) option support code.

pytcp/protocols/tcp/options/ip4_option__eol.py

ver 3.0.0
"""


from __future__ import annotations

from dataclasses import dataclass, field
from typing import override

from pytcp.protocols.ip4.options.ip4_option import Ip4Option, Ip4OptionType

# The Ip4 Eol (End of Option List) option [RFC 793].

# +-+-+-+-+-+-+-+-+
# |    Type = 0   |
# +-+-+-+-+-+-+-+-+


IP4__OPTION_EOL__LEN = 1


@dataclass(frozen=True, kw_only=True)
class Ip4OptionEol(Ip4Option):
    """
    The IPv4 Eol (End of Option List) option support.
    """

    type: Ip4OptionType = field(
        repr=False,
        init=False,
        default=Ip4OptionType.EOL,
    )
    len: int = field(
        repr=False,
        init=False,
        default=IP4__OPTION_EOL__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Validate the IPv4 Eol option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the the IPv4 Eol option log string.
        """

        return "eol"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the IPv4 Eol option as bytes.
        """

        return bytes(self.type)

    @staticmethod
    def from_bytes(_bytes: bytes) -> Ip4OptionEol:
        """
        Initialize the IPv4 Eol option from bytes.
        """

        assert len(_bytes) >= 1
        assert _bytes[0] == int(Ip4OptionType.EOL)

        return Ip4OptionEol()
