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
This module contains the IPv6 Destination Options Pad1 option support code.

net_proto/protocols/ip6_dest_opts/options/ip6_dest_opts__option__pad1.py

ver 3.0.10
"""

from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option import (
    Ip6DestOptsOption,
    Ip6DestOptsOptionType,
)

# The IPv6 Destination Options Pad1 option [RFC 8200 §4.2].
#
# +-+-+-+-+-+-+-+-+
# |       0       |
# +-+-+-+-+-+-+-+-+
#
# Single 0x00 byte; no length, no data. Used to pad an option block
# to a 1-byte boundary.

IP6_DEST_OPTS__OPTION__PAD1__LEN = 1
IP6_DEST_OPTS__OPTION__PAD1__STRUCT = "! B"


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip6DestOptsOptionPad1(Ip6DestOptsOption):
    """
    The IPv6 Destination Options Pad1 option support class.
    """

    type: Ip6DestOptsOptionType = field(
        repr=False,
        init=False,
        default=Ip6DestOptsOptionType.PAD1,
    )
    len: int = field(
        repr=False,
        init=False,
        default=IP6_DEST_OPTS__OPTION__PAD1__LEN,
    )

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv6 Dest Opts Pad1 option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 Dest Opts Pad1 option log string.
        """

        return "pad1"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 Dest Opts Pad1 option as a memoryview.
        """

        return memoryview(bytearray(bytes(self.type)))

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv6 Dest Opts Pad1 option from buffer.
        """

        assert (value := len(buffer)) >= IP6_DEST_OPTS__OPTION__PAD1__LEN, (
            f"The minimum length of the IPv6 Dest Opts Pad1 option must be "
            f"{IP6_DEST_OPTS__OPTION__PAD1__LEN} byte. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip6DestOptsOptionType.PAD1), (
            f"The IPv6 Dest Opts Pad1 option type must be {Ip6DestOptsOptionType.PAD1!r}. "
            f"Got: {Ip6DestOptsOptionType.from_int(value)!r}"
        )

        return cls()
