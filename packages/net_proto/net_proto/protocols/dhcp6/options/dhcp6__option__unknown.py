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
This module contains the unknown DHCPv6 option support code.

Per RFC 8415 §16 a client MUST discard options it does not
understand without affecting processing of the rest of the
message; PyTCP preserves the wire bytes so a Phase-2 relay /
forwarder can re-emit them faithfully, and so operator-visible
logs surface the unknown codepoint.

net_proto/protocols/dhcp6/options/dhcp6__option__unknown.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    DHCP6__OPTION__STRUCT,
    Dhcp6Option,
    Dhcp6OptionType,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6OptionUnknown(Dhcp6Option):
    """
    The DHCPv6 unknown option support class.
    """

    type: Dhcp6OptionType = field(
        repr=True,
        init=True,
        default=Dhcp6OptionType.from_int(65535),
    )
    len: int = field(
        repr=True,
        init=False,
    )

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 unknown option fields.
        """

        assert isinstance(
            self.type, Dhcp6OptionType
        ), f"The 'type' field must be a Dhcp6OptionType. Got: {type(self.type)!r}"

        assert (
            int(self.type) not in Dhcp6OptionType.get_known_values()
        ), f"The 'type' field must not be a known Dhcp6OptionType. Got: {self.type!r}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", DHCP6__OPTION__LEN + len(self.data))

        assert is_uint16(
            self.len - DHCP6__OPTION__LEN
        ), f"The 'len' field must be a 16-bit unsigned integer. Got: {self.len!r}"

    @override
    def __str__(self) -> str:
        """
        Get the unknown DHCPv6 option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the unknown DHCPv6 option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
        )

        buffer[DHCP6__OPTION__LEN:] = self.data

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the unknown DHCPv6 option before parsing it.
        """

        if (value := DHCP6__OPTION__LEN + int.from_bytes(buffer[2:4])) > len(buffer):
            raise Dhcp6IntegrityError(
                "The unknown DHCPv6 option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the unknown DHCPv6 option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the unknown DHCPv6 option must be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (
            value := int.from_bytes(buffer[0:2])
        ) not in Dhcp6OptionType.get_known_values(), (
            f"The unknown DHCPv6 option type must not be known. Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        Dhcp6OptionUnknown._validate_integrity(buffer)

        return cls(
            type=Dhcp6OptionType.from_int(int.from_bytes(buffer[0:2])),
            data=bytes(
                buffer[DHCP6__OPTION__LEN : DHCP6__OPTION__LEN + int.from_bytes(buffer[2:4])]
            ),  # NOTE: Conversion: memoryview -> bytes
        )
