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
This module contains the DHCPv4 End option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__end.py

ver 3.0.8
"""

from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 End (End of Option List) option [RFC 2132].

# +-+-+-+-+-+-+-+-+
# |   Code = 255  |
# +-+-+-+-+-+-+-+-+


DHCP4__OPTION__END__LEN = 1
DHCP4__OPTION__END__STRUCT = "! B"


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4OptionEnd(Dhcp4Option):
    """
    The DHCPv4 End option support.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.END,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__END__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 End option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 End option log string.
        """

        return "end"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 End option as a memoryview.
        """

        return memoryview(bytearray(bytes(self.type)))

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 End option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= DHCP4__OPTION__END__LEN, (
            f"The minimum length of the DHCPv4 End option must be {DHCP4__OPTION__END__LEN} byte. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(
            Dhcp4OptionType.END
        ), f"The DHCPv4 End option type must be {Dhcp4OptionType.END!r}. Got: {Dhcp4OptionType.from_int(value)!r}"

        return cls()
