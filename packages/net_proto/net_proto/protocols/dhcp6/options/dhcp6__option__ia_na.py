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
This module contains the DHCPv6 Identity Association for Non-temporary
Addresses (IA_NA) option support code.

net_proto/protocols/dhcp6/options/dhcp6__option__ia_na.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    Dhcp6Option,
    Dhcp6OptionType,
)

# The DHCPv6 IA_NA option [RFC 8415 §21.4].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |        OPTION_IA_NA = 3       |           option-len          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        IAID (4 octets)                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                               T1                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                               T2                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                         IA_NA-options                         .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP6__OPTION__IA_NA__STRUCT = "! HH I I I"
# IAID (4) + T1 (4) + T2 (4).
DHCP6__OPTION__IA_NA__DATA__MIN_LEN = 12


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6OptionIaNa(Dhcp6Option):
    """
    The DHCPv6 IA_NA option support class.
    """

    type: Dhcp6OptionType = field(
        repr=False,
        init=False,
        default=Dhcp6OptionType.IA_NA,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    iaid: int
    t1: int
    t2: int
    # RFC 8415 §21.4 — the IA_NA-options sub-block (typically one or
    # more IA Address options, optionally a Status Code option) is
    # preserved as opaque bytes; the DHCPv6 client parses it with
    # Dhcp6Options.from_buffer to extract the assigned addresses.
    options: bytes = b""

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 IA_NA option fields.
        """

        assert is_uint32(self.iaid), f"The 'iaid' field must be a 32-bit unsigned integer. Got: {self.iaid}"

        assert is_uint32(self.t1), f"The 't1' field must be a 32-bit unsigned integer. Got: {self.t1}"

        assert is_uint32(self.t2), f"The 't2' field must be a 32-bit unsigned integer. Got: {self.t2}"

        assert isinstance(
            self.options, (bytes, bytearray)
        ), f"The 'options' field must be bytes. Got: {type(self.options)!r}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", DHCP6__OPTION__LEN + DHCP6__OPTION__IA_NA__DATA__MIN_LEN + len(self.options))

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv6 IA_NA option log string.
        """

        return f"ia_na iaid {self.iaid} t1 {self.t1} t2 {self.t2}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 IA_NA option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__IA_NA__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
            self.iaid,
            self.t1,
            self.t2,
        )
        buffer[DHCP6__OPTION__LEN + DHCP6__OPTION__IA_NA__DATA__MIN_LEN :] = self.options

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv6 IA_NA option before parsing it.
        """

        option_len = int.from_bytes(buffer[2:4])

        if option_len < DHCP6__OPTION__IA_NA__DATA__MIN_LEN:
            raise Dhcp6IntegrityError(
                "The DHCPv6 IA_NA option must carry the 12-octet IAID + T1 + T2 "
                f"(RFC 8415 §21.4). Got: {option_len!r}"
            )

        if (value := DHCP6__OPTION__LEN + option_len) > len(buffer):
            raise Dhcp6IntegrityError(
                "The DHCPv6 IA_NA option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 IA_NA option from buffer.
        """

        assert (value := len(buffer)) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the DHCPv6 IA_NA option must " f"be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := int.from_bytes(buffer[0:2])) == int(Dhcp6OptionType.IA_NA), (
            f"The DHCPv6 IA_NA option type must be {Dhcp6OptionType.IA_NA!r}. "
            f"Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        option_len = int.from_bytes(buffer[2:4])
        options_offset = DHCP6__OPTION__LEN + DHCP6__OPTION__IA_NA__DATA__MIN_LEN

        return cls(
            iaid=int.from_bytes(buffer[DHCP6__OPTION__LEN : DHCP6__OPTION__LEN + 4]),
            t1=int.from_bytes(buffer[DHCP6__OPTION__LEN + 4 : DHCP6__OPTION__LEN + 8]),
            t2=int.from_bytes(buffer[DHCP6__OPTION__LEN + 8 : DHCP6__OPTION__LEN + 12]),
            options=bytes(buffer[options_offset : DHCP6__OPTION__LEN + option_len]),
        )
