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
This module contains the DHCPv6 Client Identifier option support code.

net_proto/protocols/dhcp6/options/dhcp6__option__client_id.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    DHCP6__OPTION__STRUCT,
    Dhcp6Option,
    Dhcp6OptionType,
)

# The DHCPv6 Client Identifier option [RFC 8415 §21.2].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      OPTION_CLIENTID = 1      |           option-len          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                              DUID                             .
# .                       (variable length)                       .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# RFC 8415 §11.1 — a DUID is a 2-octet type code followed by no more
# than 128 octets of identifier, so the opaque client-id payload is
# 1..130 octets. PyTCP treats the DUID as opaque (§11.1: "Clients and
# servers MUST treat DUIDs as opaque values").
DHCP6__OPTION__CLIENT_ID__MIN_LEN = 1
DHCP6__OPTION__CLIENT_ID__MAX_LEN = 130


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp6OptionClientId(Dhcp6Option):
    """
    The DHCPv6 Client Identifier option support class.
    """

    type: Dhcp6OptionType = field(
        repr=False,
        init=False,
        default=Dhcp6OptionType.CLIENT_ID,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    duid: bytes

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 Client Identifier option fields.
        """

        assert isinstance(self.duid, (bytes, bytearray)), f"The 'duid' field must be bytes. Got: {type(self.duid)!r}"

        assert DHCP6__OPTION__CLIENT_ID__MIN_LEN <= len(self.duid) <= DHCP6__OPTION__CLIENT_ID__MAX_LEN, (
            f"The 'duid' field length must be {DHCP6__OPTION__CLIENT_ID__MIN_LEN}.."
            f"{DHCP6__OPTION__CLIENT_ID__MAX_LEN} bytes. Got: {len(self.duid)} bytes"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", DHCP6__OPTION__LEN + len(self.duid))

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv6 Client Identifier option log string.
        """

        return f"client_id {self.duid.hex()}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 Client Identifier option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
        )
        buffer[DHCP6__OPTION__LEN:] = self.duid

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv6 Client Identifier option before parsing it.
        """

        if (value := int.from_bytes(buffer[2:4])) < DHCP6__OPTION__CLIENT_ID__MIN_LEN:
            raise Dhcp6IntegrityError(
                "The DHCPv6 Client Identifier option DUID minimum length is "
                f"{DHCP6__OPTION__CLIENT_ID__MIN_LEN} (RFC 8415 §11.1). Got: {value!r}"
            )

        if (value := DHCP6__OPTION__LEN + int.from_bytes(buffer[2:4])) > len(buffer):
            raise Dhcp6IntegrityError(
                "The DHCPv6 Client Identifier option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 Client Identifier option from buffer.
        """

        assert (value := len(buffer)) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the DHCPv6 Client Identifier option must "
            f"be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := int.from_bytes(buffer[0:2])) == int(Dhcp6OptionType.CLIENT_ID), (
            f"The DHCPv6 Client Identifier option type must be {Dhcp6OptionType.CLIENT_ID!r}. "
            f"Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            bytes(buffer[DHCP6__OPTION__LEN : DHCP6__OPTION__LEN + int.from_bytes(buffer[2:4])])
        )  # Note: Conversion: memoryview -> bytes
