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
This module contains the IPv4 Router Alert option support code.

net_proto/protocols/ip4/options/ip4__option__router_alert.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.ip4.ip4__errors import Ip4IntegrityError
from net_proto.protocols.ip4.options.ip4__option import Ip4Option, Ip4OptionType

# The IPv4 Router Alert option [RFC 2113].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Type = 148   |   Length = 4  |          Value (16-bit)       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP4__OPTION__ROUTER_ALERT__LEN = 4
IP4__OPTION__ROUTER_ALERT__STRUCT = "! BB H"
IP4__OPTION__ROUTER_ALERT__VALUE__EXAMINE = 0


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip4OptionRouterAlert(Ip4Option):
    """
    The IPv4 Router Alert option support class.
    """

    type: Ip4OptionType = field(
        repr=False,
        init=False,
        default=Ip4OptionType.ROUTER_ALERT,
    )
    len: int = field(
        repr=False,
        init=False,
        default=IP4__OPTION__ROUTER_ALERT__LEN,
    )

    value: int = IP4__OPTION__ROUTER_ALERT__VALUE__EXAMINE

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv4 Router Alert option fields.
        """

        assert is_uint16(self.value), f"The 'value' field must be a 16-bit unsigned integer. Got: {self.value!r}"

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 Router Alert option log string.
        """

        if self.value == IP4__OPTION__ROUTER_ALERT__VALUE__EXAMINE:
            return "router_alert"
        return f"router_alert value={self.value}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 Router Alert option as a memoryview.
        """

        struct.pack_into(
            IP4__OPTION__ROUTER_ALERT__STRUCT,
            buffer := bytearray(IP4__OPTION__ROUTER_ALERT__LEN),
            0,
            int(self.type),
            self.len,
            self.value,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv4 Router Alert option before parsing it.
        """

        # RFC 2113 §2.1 — the Router Alert option is fixed-size: 1
        # type byte + 1 length byte + 2 value bytes = 4. Any other
        # length value is malformed.
        if (value := buffer[1]) != IP4__OPTION__ROUTER_ALERT__LEN:
            raise Ip4IntegrityError(
                f"The IPv4 Router Alert option length value must be {IP4__OPTION__ROUTER_ALERT__LEN} "
                f"bytes. Got: {value!r}"
            )

        # RFC 2113 §2.1 / RFC 791 §3.1 — option length MUST NOT
        # exceed the buffer available (defense-in-depth; in practice
        # the equality check above already covers this since len=4
        # and any buffer < 4 bytes would have failed the parent
        # options walk).
        if (value := buffer[1]) > len(buffer):
            raise Ip4IntegrityError(
                "The IPv4 Router Alert option length value must be less than or equal to the "
                f"length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv4 Router Alert option from buffer.
        """

        assert (value := len(buffer)) >= IP4__OPTION__ROUTER_ALERT__LEN, (
            f"The minimum length of the IPv4 Router Alert option must be "
            f"{IP4__OPTION__ROUTER_ALERT__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip4OptionType.ROUTER_ALERT), (
            f"The IPv4 Router Alert option type must be {Ip4OptionType.ROUTER_ALERT!r}. "
            f"Got: {Ip4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(value=int.from_bytes(buffer[2:4]))
