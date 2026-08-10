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
This module contains the IPv4 Nop (No Operation) option support code.

net_proto/protocols/ip4/options/ip4__option__nop.py

ver 3.0.10
"""

from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.protocols.ip4.options.ip4__option import Ip4Option, Ip4OptionType

# The IPv4 Nop (No Operation) option [RFC 791].

# +-+-+-+-+-+-+-+-+
# |    Type = 1   |
# +-+-+-+-+-+-+-+-+


IP4__OPTION__NOP__LEN = 1
IP4__OPTION__NOP__STRUCT = "! B"


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip4OptionNop(Ip4Option):
    """
    The IPv4 Nop (No Operation) option support class.
    """

    type: Ip4OptionType = field(
        repr=False,
        init=False,
        default=Ip4OptionType.NOP,
    )
    len: int = field(
        repr=False,
        init=False,
        default=IP4__OPTION__NOP__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv4 Nop option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 Nop option log string.
        """

        return "nop"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 Nop option as a memoryview.
        """

        return memoryview(bytearray(bytes(self.type)))

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv4 Nop option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= IP4__OPTION__NOP__LEN, (
            f"The minimum length of the IPv4 Nop option must be {IP4__OPTION__NOP__LEN} byte. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(
            Ip4OptionType.NOP
        ), f"The IPv4 Nop option type must be {Ip4OptionType.NOP!r}. Got: {Ip4OptionType.from_int(value)!r}"

        return cls()
