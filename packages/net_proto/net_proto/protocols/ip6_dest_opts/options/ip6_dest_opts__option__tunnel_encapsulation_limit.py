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
This module contains the IPv6 Dest Opts Tunnel Encapsulation Limit
option support code.

net_proto/protocols/ip6_dest_opts/options/ip6_dest_opts__option__tunnel_encapsulation_limit.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__errors import Ip6DestOptsIntegrityError
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option import (
    Ip6DestOptsOption,
    Ip6DestOptsOptionType,
)

# The IPv6 Dest Opts Tunnel Encapsulation Limit option [RFC 2473 §4.1.1].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Option Type  |  Opt Data Len |   Tun Encap   |
# |     = 0x04    |     = 0x01    |     Limit     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Type=0x04 (top-2-bits=00 -> skip-if-unknown), Opt Data Len=1,
# Value is an 8-bit unsigned remaining-encapsulation-depth count.

IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__LEN = 3
IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__OPT_DATA_LEN = 1
IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__STRUCT = "! BBB"


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip6DestOptsOptionTunnelEncapsulationLimit(Ip6DestOptsOption):
    """
    The IPv6 Dest Opts Tunnel Encapsulation Limit option support class.
    """

    type: Ip6DestOptsOptionType = field(
        repr=False,
        init=False,
        default=Ip6DestOptsOptionType.TUNNEL_ENCAPSULATION_LIMIT,
    )
    len: int = field(
        repr=False,
        init=False,
        default=IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__LEN,
    )

    value: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the Tunnel Encapsulation Limit option fields.
        """

        assert is_uint8(self.value), f"The 'value' field must be an 8-bit unsigned integer. Got: {self.value!r}"

    @override
    def __str__(self) -> str:
        """
        Get the Tunnel Encapsulation Limit option log string.
        """

        return f"tunnel-encap-limit ({self.value})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the Tunnel Encapsulation Limit option as a memoryview.
        """

        struct.pack_into(
            IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__STRUCT,
            buffer := bytearray(IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__LEN),
            0,
            int(self.type),
            IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__OPT_DATA_LEN,
            self.value,
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv6 Dest Opts Tunnel Encapsulation
        Limit option before parsing it. Hostile-wire defense-in-
        depth so the Opt Data Len mismatch does not leak as a bare
        AssertionError past the IPv6 chain walker's
        PacketValidationError catch.
        """

        # RFC 2473 §4.1.1 — the Tunnel Encapsulation Limit option
        # is fixed-shape: 1-byte type + 1-byte Opt Data Len +
        # 1-byte limit = 3 octets total; Opt Data Len MUST be 1.
        if (value := buffer[1]) != IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__OPT_DATA_LEN:
            raise Ip6DestOptsIntegrityError(
                f"The IPv6 Dest Opts Tunnel Encap Limit option Opt Data Len must be "
                f"{IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__OPT_DATA_LEN}. Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the Tunnel Encapsulation Limit option from buffer.
        """

        assert (value := len(buffer)) >= IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__LEN, (
            f"The minimum length of the IPv6 Dest Opts Tunnel Encap Limit option must be "
            f"{IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip6DestOptsOptionType.TUNNEL_ENCAPSULATION_LIMIT), (
            f"The IPv6 Dest Opts Tunnel Encap Limit option type must be "
            f"{Ip6DestOptsOptionType.TUNNEL_ENCAPSULATION_LIMIT!r}. "
            f"Got: {Ip6DestOptsOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(value=buffer[2])
