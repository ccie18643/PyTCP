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
This module contains the IPv6 HBH Router Alert option support code.

net_proto/protocols/ip6_hbh/options/ip6_hbh__option__router_alert.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhIntegrityError
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import (
    IP6_HBH__OPTION__LEN,
    Ip6HbhOption,
    Ip6HbhOptionType,
)

# The IPv6 HBH Router Alert option [RFC 2711].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Option Type  |  Opt Data Len |        Value (16 bits)        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Type=0x05 (top-2-bits=00 -> skip-if-unknown), Opt Data Len=2,
# Value is a 16-bit code identifying the consumer that should
# notice the packet (RFC 2711 §2 well-known values: 0=MLD,
# 1=RSVP, 2=Active Networks; full registry at IANA).

IP6_HBH__OPTION__ROUTER_ALERT__LEN = 4
IP6_HBH__OPTION__ROUTER_ALERT__OPT_DATA_LEN = 2
IP6_HBH__OPTION__ROUTER_ALERT__STRUCT = "! BBH"

IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD = 0
IP6_HBH__OPTION__ROUTER_ALERT__VALUE__RSVP = 1
IP6_HBH__OPTION__ROUTER_ALERT__VALUE__ACTIVE_NETWORKS = 2


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip6HbhOptionRouterAlert(Ip6HbhOption):
    """
    The IPv6 HBH Router Alert option support class.
    """

    type: Ip6HbhOptionType = field(
        repr=False,
        init=False,
        default=Ip6HbhOptionType.ROUTER_ALERT,
    )
    len: int = field(
        repr=False,
        init=False,
        default=IP6_HBH__OPTION__ROUTER_ALERT__LEN,
    )

    value: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv6 HBH Router Alert option fields.
        """

        assert is_uint16(self.value), f"The 'value' field must be a 16-bit unsigned integer. Got: {self.value!r}"

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 HBH Router Alert option log string.
        """

        match self.value:
            case 0:
                name = "MLD"
            case 1:
                name = "RSVP"
            case 2:
                name = "Active Networks"
            case _:
                name = str(self.value)

        return f"router-alert ({name})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 HBH Router Alert option as a memoryview.
        """

        struct.pack_into(
            IP6_HBH__OPTION__ROUTER_ALERT__STRUCT,
            buffer := bytearray(IP6_HBH__OPTION__ROUTER_ALERT__LEN),
            0,
            int(self.type),
            IP6_HBH__OPTION__ROUTER_ALERT__OPT_DATA_LEN,
            self.value,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv6 HBH Router Alert option before
        parsing it. Hostile-wire defense-in-depth so the Opt Data
        Len mismatch does not leak as a bare AssertionError past
        the IPv6 chain walker's PacketValidationError catch.
        """

        # RFC 2711 §2.1 — Router Alert is fixed-shape: 1-byte type
        # + 1-byte Opt Data Len + 2-byte value = 4 octets total;
        # Opt Data Len MUST be 2.
        if (value := buffer[1]) != IP6_HBH__OPTION__ROUTER_ALERT__OPT_DATA_LEN:
            raise Ip6HbhIntegrityError(
                f"The IPv6 HBH Router Alert option Opt Data Len must be "
                f"{IP6_HBH__OPTION__ROUTER_ALERT__OPT_DATA_LEN}. Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv6 HBH Router Alert option from buffer.
        """

        assert (value := len(buffer)) >= IP6_HBH__OPTION__ROUTER_ALERT__LEN, (
            f"The minimum length of the IPv6 HBH Router Alert option must be "
            f"{IP6_HBH__OPTION__ROUTER_ALERT__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip6HbhOptionType.ROUTER_ALERT), (
            f"The IPv6 HBH Router Alert option type must be {Ip6HbhOptionType.ROUTER_ALERT!r}. "
            f"Got: {Ip6HbhOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(value=int.from_bytes(buffer[IP6_HBH__OPTION__LEN:IP6_HBH__OPTION__ROUTER_ALERT__LEN]))
