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
This module contains the DHCPv4 Client Identifier option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__client_id.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Client Identifier option [RFC 2132].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Code = 61  |    Len = N    |        Client Identifier     ...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__CLIENT_ID__STRUCT = "! BB"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionClientId(Dhcp4Option):
    """
    The DHCPv4 Client Identifier option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.CLIENT_ID,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    client_id: Buffer

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Client Identifier option fields.
        """

        assert isinstance(
            self.client_id, (bytes, bytearray)
        ), f"The 'client_id' field must be bytes. Got: {type(self.client_id)!r}"

        # RFC 2132 §9.14 — "The code for this option is 61, and
        # its minimum length is 2." The Length field is the data
        # length (the byte count following the 2-byte Type/Length
        # header), which is `len(self.client_id)` in PyTCP. The
        # 2-byte minimum reflects the wire format `Type |
        # Identifier` — a 1-byte type code + at least one
        # identifier byte.
        assert (
            len(self.client_id) >= 2
        ), f"The 'client_id' field minimum length is 2 (RFC 2132 §9.14). Got: {len(self.client_id)} bytes"

        # The wire-format length byte is a single octet, so the
        # data must fit in 255 bytes. Catch over-uint8 input at
        # construction rather than letting struct.pack_into raise
        # deep inside __buffer__.
        assert (
            len(self.client_id) <= 255
        ), f"The 'client_id' field encoded length must fit in a uint8. Got: {len(self.client_id)} bytes"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", DHCP4__OPTION__LEN + len(self.client_id))

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Client Identifier option log string.
        """

        return f"client_id {':'.join(f'{b:02x}' for b in self.client_id)}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Client Identifier option as a memoryview.
        """

        buffer = bytearray(len(self))

        struct.pack_into(
            DHCP4__OPTION__CLIENT_ID__STRUCT,
            buffer,
            0,
            int(self.type),
            len(self.client_id),
        )
        buffer[DHCP4__OPTION__LEN:] = bytes(self.client_id)

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Client Identifier option before parsing it.
        """

        # RFC 2132 §9.14 — "The code for this option is 61, and
        # its minimum length is 2." Reject wire frames whose
        # Length byte is below the spec minimum BEFORE the
        # constructor's tighter dataclass assert fires, so the
        # failure surfaces as a typed integrity error rather
        # than a bare AssertionError that slips past the IP RX
        # handler's PacketValidationError catch.
        if (value := buffer[1]) < 2:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Client Identifier option minimum length is 2 (RFC 2132 §9.14). " f"Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Client Identifier option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Client Identifier option from buffer.
        """

        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Client Identifier option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.CLIENT_ID), (
            f"The DHCPv4 Client Identifier option type must be {Dhcp4OptionType.CLIENT_ID!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(bytes(buffer[2 : 2 + buffer[1]]))  # Note: Conversion: memoryview -> bytes
