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
This module contains the ICMPv6 ND Recursive DNS Server (RDNSS)
option support code (RFC 8106 §5.1).

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option__rdnss.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    ICMP6__ND__OPTION__LEN,
    Icmp6NdOption,
    Icmp6NdOptionType,
)

# The ICMPv6 ND Recursive DNS Server option [RFC 8106 §5.1].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Type = 25  |    Length     |           Reserved            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Lifetime                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# :            Addresses of IPv6 Recursive DNS Servers            :
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Fixed portion = type(1) + length(1) + reserved(2) + lifetime(4) = 8 bytes.
# Each server is 16 bytes (IPv6 address). Total = 8 + 16N bytes; length-
# field (in 8-byte units) = 1 + 2N where N is the server count.
ICMP6__ND__OPTION__RDNSS__FIXED_LEN = 8
ICMP6__ND__OPTION__RDNSS__STRUCT__FIXED = "! BB H L"
ICMP6__ND__OPTION__RDNSS__SERVER_LEN = 16


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOptionRdnss(Icmp6NdOption):
    """
    The ICMPv6 ND Recursive DNS Server option support class
    (RFC 8106 §5.1). Carried in Router Advertisement messages
    to advertise zero or more recursive DNS server addresses
    with a single shared lifetime.
    """

    type: Icmp6NdOptionType = field(
        repr=False,
        init=False,
        default=Icmp6NdOptionType.RDNSS,
    )
    len: int = field(
        repr=True,
        init=False,
    )

    lifetime: int
    addresses: tuple[Ip6Address, ...] = ()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the ICMPv6 ND RDNSS option fields.

        The 'len' attribute is computed from the address count
        per RFC 8106 §5.1 and stored on the frozen dataclass via
        'object.__setattr__' (codebase convention).
        """

        assert is_uint32(
            self.lifetime
        ), f"The 'lifetime' field must be a 32-bit unsigned integer. Got: {self.lifetime!r}"

        for address in self.addresses:
            assert isinstance(
                address, Ip6Address
            ), f"Every entry in 'addresses' must be an Ip6Address. Got: {type(address)!r}"

        # Total wire bytes = 8 + 16N; length-field = bytes / 8.
        wire_len = ICMP6__ND__OPTION__RDNSS__FIXED_LEN + len(self.addresses) * ICMP6__ND__OPTION__RDNSS__SERVER_LEN
        object.__setattr__(self, "len", wire_len)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 ND RDNSS option log string.
        """

        servers = ", ".join(str(a) for a in self.addresses)
        return f"rdnss (lifetime {self.lifetime}, servers [{servers}])"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ICMPv6 ND RDNSS option as a memoryview.
        """

        buffer = bytearray(len(self))
        struct.pack_into(
            ICMP6__ND__OPTION__RDNSS__STRUCT__FIXED,
            buffer,
            0,
            int(self.type),
            self.len >> 3,
            0,
            self.lifetime,
        )
        offset = ICMP6__ND__OPTION__RDNSS__FIXED_LEN
        for address in self.addresses:
            buffer[offset : offset + ICMP6__ND__OPTION__RDNSS__SERVER_LEN] = bytes(address)
            offset += ICMP6__ND__OPTION__RDNSS__SERVER_LEN

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the ICMPv6 ND RDNSS option before parsing it.
        """

        encoded_len = buffer[1] << 3
        if encoded_len < ICMP6__ND__OPTION__RDNSS__FIXED_LEN:
            raise Icmp6IntegrityError(
                "The ICMPv6 ND RDNSS option length value must be at least "
                f"{ICMP6__ND__OPTION__RDNSS__FIXED_LEN} bytes. Got: {encoded_len!r}"
            )

        if encoded_len > len(buffer):
            raise Icmp6IntegrityError(
                f"The ICMPv6 ND RDNSS option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {encoded_len!r}"
            )

        # length = 1 + 2N → (length - 1) must be even.
        length_units = buffer[1]
        if (length_units - 1) % 2 != 0:
            raise Icmp6IntegrityError(
                "The ICMPv6 ND RDNSS option length-field must be of the form "
                f"1 + 2*N (where N is the server count). Got: {length_units!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the ICMPv6 ND RDNSS option from buffer.
        """

        assert (value := len(buffer)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the ICMPv6 ND RDNSS option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Icmp6NdOptionType.RDNSS), (
            f"The ICMPv6 ND RDNSS option type must be {Icmp6NdOptionType.RDNSS!r}. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        _type, length_units, _reserved, lifetime = struct.unpack(
            ICMP6__ND__OPTION__RDNSS__STRUCT__FIXED,
            buffer[:ICMP6__ND__OPTION__RDNSS__FIXED_LEN],
        )
        encoded_len = length_units << 3
        server_count = (encoded_len - ICMP6__ND__OPTION__RDNSS__FIXED_LEN) // ICMP6__ND__OPTION__RDNSS__SERVER_LEN
        addresses = tuple(
            Ip6Address(
                bytes(
                    buffer[
                        ICMP6__ND__OPTION__RDNSS__FIXED_LEN
                        + i * ICMP6__ND__OPTION__RDNSS__SERVER_LEN : ICMP6__ND__OPTION__RDNSS__FIXED_LEN
                        + (i + 1) * ICMP6__ND__OPTION__RDNSS__SERVER_LEN
                    ]
                )
            )
            for i in range(server_count)
        )

        return cls(
            lifetime=lifetime,
            addresses=addresses,
        )
