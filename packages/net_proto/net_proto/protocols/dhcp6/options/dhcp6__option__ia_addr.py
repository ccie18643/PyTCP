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
This module contains the DHCPv6 IA Address option support code.

net_proto/protocols/dhcp6/options/dhcp6__option__ia_addr.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    Dhcp6Option,
    Dhcp6OptionType,
)

# The DHCPv6 IA Address option [RFC 8415 §21.6].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |       OPTION_IAADDR = 5       |           option-len          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          IPv6-address                         |
# |                          (16 octets)                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       preferred-lifetime                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         valid-lifetime                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                         IAaddr-options                        .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP6__OPTION__IA_ADDR__STRUCT = "! HH 16s I I"
# Address (16) + preferred-lifetime (4) + valid-lifetime (4).
DHCP6__OPTION__IA_ADDR__DATA__MIN_LEN = 24


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6OptionIaAddr(Dhcp6Option):
    """
    The DHCPv6 IA Address option support class.
    """

    type: Dhcp6OptionType = field(
        repr=False,
        init=False,
        default=Dhcp6OptionType.IA_ADDR,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    address: Ip6Address
    preferred_lifetime: int
    valid_lifetime: int
    # RFC 8415 §21.6 — the IAaddr-options sub-block (e.g. a Status Code
    # option) is preserved as opaque bytes; the DHCPv6 client parses it
    # with Dhcp6Options.from_buffer when it needs the nested options.
    options: bytes = b""

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 IA Address option fields.
        """

        assert isinstance(
            self.address, Ip6Address
        ), f"The 'address' field must be an Ip6Address. Got: {type(self.address)!r}"

        assert is_uint32(
            self.preferred_lifetime
        ), f"The 'preferred_lifetime' field must be a 32-bit unsigned integer. Got: {self.preferred_lifetime}"

        assert is_uint32(
            self.valid_lifetime
        ), f"The 'valid_lifetime' field must be a 32-bit unsigned integer. Got: {self.valid_lifetime}"

        assert isinstance(
            self.options, (bytes, bytearray)
        ), f"The 'options' field must be bytes. Got: {type(self.options)!r}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", DHCP6__OPTION__LEN + DHCP6__OPTION__IA_ADDR__DATA__MIN_LEN + len(self.options))

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv6 IA Address option log string.
        """

        return f"ia_addr {self.address} pref {self.preferred_lifetime} valid {self.valid_lifetime}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 IA Address option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__IA_ADDR__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
            bytes(self.address),
            self.preferred_lifetime,
            self.valid_lifetime,
        )
        buffer[DHCP6__OPTION__LEN + DHCP6__OPTION__IA_ADDR__DATA__MIN_LEN :] = self.options

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv6 IA Address option before parsing it.
        """

        option_len = int.from_bytes(buffer[2:4])

        if option_len < DHCP6__OPTION__IA_ADDR__DATA__MIN_LEN:
            raise Dhcp6IntegrityError(
                "The DHCPv6 IA Address option must carry the 24-octet address + lifetimes "
                f"(RFC 8415 §21.6). Got: {option_len!r}"
            )

        if (value := DHCP6__OPTION__LEN + option_len) > len(buffer):
            raise Dhcp6IntegrityError(
                "The DHCPv6 IA Address option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 IA Address option from buffer.
        """

        assert (value := len(buffer)) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the DHCPv6 IA Address option must " f"be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := int.from_bytes(buffer[0:2])) == int(Dhcp6OptionType.IA_ADDR), (
            f"The DHCPv6 IA Address option type must be {Dhcp6OptionType.IA_ADDR!r}. "
            f"Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        option_len = int.from_bytes(buffer[2:4])
        options_offset = DHCP6__OPTION__LEN + DHCP6__OPTION__IA_ADDR__DATA__MIN_LEN

        return cls(
            address=Ip6Address(buffer[DHCP6__OPTION__LEN : DHCP6__OPTION__LEN + 16]),
            preferred_lifetime=int.from_bytes(buffer[DHCP6__OPTION__LEN + 16 : DHCP6__OPTION__LEN + 20]),
            valid_lifetime=int.from_bytes(buffer[DHCP6__OPTION__LEN + 20 : DHCP6__OPTION__LEN + 24]),
            options=bytes(buffer[options_offset : DHCP6__OPTION__LEN + option_len]),
        )
