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
This module contains the DHCPv4 Pad option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__pad.py

ver 3.0.8
"""

from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Pad option [RFC 2132].

# +-+-+-+-+-+-+-+-+
# |    Code = 0   |
# +-+-+-+-+-+-+-+-+


DHCP4__OPTION__PAD__LEN = 1
DHCP4__OPTION__PAD__STRUCT = "! B"


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4OptionPad(Dhcp4Option):
    """
    The DHCPv4 Pad option support.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.PAD,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__PAD__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Pad option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Pad option log string.
        """

        return "pad"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Pad option as a memoryview.
        """

        return memoryview(bytearray(bytes(self.type)))

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Pad option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= DHCP4__OPTION__PAD__LEN, (
            f"The minimum length of the DHCPv4 Pad option must be {DHCP4__OPTION__PAD__LEN} byte. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(
            Dhcp4OptionType.PAD
        ), f"The DHCPv4 Pad option type must be {Dhcp4OptionType.PAD!r}. Got: {Dhcp4OptionType.from_int(value)!r}"

        return cls()
