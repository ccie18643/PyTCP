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
This module contains the DHCPv4 Router option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__router.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Ip4Address
from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Router option [RFC 2132].

#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Code = 3   |   Length = 4n |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Router IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Router IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                              ...                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__ROUTER__STRUCT = "! BB"
DHCP4__OPTION__ROUTER__ELEMENT__LEN = 4
DHCP4__OPTION__ROUTER__ELEMENT__STRUCT = "! 4s"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionRouter(Dhcp4Option):
    """
    The DHCPv4 Router option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.ROUTER,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    routers: list[Ip4Address]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv4 Router option fields.
        """

        assert isinstance(self.routers, list), f"The 'routers' field must be a list. Got: {type(self.routers)!r}"

        assert all(isinstance(item, Ip4Address) for item in self.routers), (
            f"The 'routers' field must be a list of Ip4Address elements. "
            f"Got: {[type(element) for element in self.routers]!r}"
        )

        # RFC 2132 §3.5 — "The minimum length for the router
        # option is 4 octets" — the option data must carry at
        # least one IPv4 address.
        assert len(self.routers) >= 1, (
            f"The 'routers' field must carry at least 1 router IP (RFC 2132 §3.5 minimum "
            f"length 4 octets). Got: {len(self.routers)}"
        )

        # The wire-format length byte is a single octet; with
        # 4 bytes per IPv4 address, the option can carry at most
        # 63 routers (63 × 4 = 252; 64 × 4 = 256 > uint8). Catch
        # over-uint8 input at construction rather than letting
        # struct.pack_into raise deep inside __buffer__.
        assert len(self.routers) <= 63, (
            f"The 'routers' field must carry at most 63 router IPs (RFC 2132 §3.5 length "
            f"is a single octet). Got: {len(self.routers)}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self, "len", DHCP4__OPTION__LEN + len(self.routers) * 4)

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Router option log string.
        """

        return f"router {[str(router) for router in self.routers]}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Router option as a memoryview.
        """

        buffer = bytearray(len(self))

        struct.pack_into(
            DHCP4__OPTION__ROUTER__STRUCT,
            buffer,
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
        )

        for index, router in enumerate(self.routers):
            struct.pack_into(
                DHCP4__OPTION__ROUTER__ELEMENT__STRUCT,
                buffer,
                DHCP4__OPTION__LEN + index * DHCP4__OPTION__ROUTER__ELEMENT__LEN,
                bytes(router),
            )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv4 Router option before parsing it.
        """

        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Router option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # RFC 2132 §3.5 — "The minimum length for the router option
        # is 4 octets". Reject wire frames whose Length byte is
        # below the spec minimum BEFORE the constructor's tighter
        # dataclass assert fires, so the failure surfaces as a
        # typed integrity error rather than a bare AssertionError
        # that slips past the IP RX handler's PacketValidationError
        # catch.
        if (value := buffer[1]) < 4:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Router option minimum length is 4 octets (RFC 2132 §3.5). " f"Got: {value!r}"
            )

        if (value := buffer[1] % 4) != 0:
            raise Dhcp4IntegrityError(
                f"The DHCPv4 Router option length value (less header) must be a multiple of 4. Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Router option from buffer.
        """

        assert (
            value := len(buffer)
        ) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Router option must be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Dhcp4OptionType.ROUTER), (
            f"The DHCPv4 Router option type must be {Dhcp4OptionType.ROUTER!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            [Ip4Address(buffer[i : i + 4]) for i in range(2, buffer[1] + 2, 4)],
        )
