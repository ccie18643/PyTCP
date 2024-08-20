#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains the IPv6 packet header.

pytcp/protocols/ip6/ip6__header.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from abc import ABC
from dataclasses import dataclass, field
from typing import override

from pytcp.lib.int_checks import (
    UINT_16__MAX,
    is_uint2,
    is_uint6,
    is_uint8,
    is_uint16,
    is_uint20,
)
from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.proto_struct import ProtoStruct
from pytcp.protocols.ip6.ip6__enums import Ip6Next

# The IPv6 packet header [RFC 2460].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|   DSCP    |ECN|           Flow Label                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Payload Length        |  Next Header  |   Hop Limit   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                         Source Address                        +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                      Destination Address                      +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP6__HEADER__LEN = 40
IP6__HEADER__STRUCT = "! L HBB 16s 16s"
IP6__PAYLOAD__MAX_LEN = UINT_16__MAX


@dataclass(frozen=True, kw_only=True)
class Ip6Header(ProtoStruct):
    """
    The IPv6 packet header.
    """

    ver: int = field(
        repr=False,
        init=False,
        default=6,
    )
    dscp: int
    ecn: int
    flow: int
    dlen: int
    next: Ip6Next
    hop: int
    src: Ip6Address
    dst: Ip6Address

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the Ip6 header fields.
        """

        assert is_uint6(
            self.dscp
        ), f"The 'dscp' field must be a 6-bit unsigned integer. Got: {self.dscp!r}"

        assert is_uint2(
            self.ecn
        ), f"The 'ecn' field must be a 2-bit unsigned integer. Got: {self.ecn!r}"

        assert is_uint20(
            self.flow
        ), f"The 'flow' field must be a 20-bit unsigned integer. Got: {self.flow!r}"

        assert is_uint16(
            self.dlen
        ), f"The 'dlen' field must be a 16-bit unsigned integer. Got: {self.dlen!r}"

        assert isinstance(
            self.next, Ip6Next
        ), f"The 'next' field must be an Ip6Next. Got: {type(self.next)!r}"

        assert is_uint8(
            self.hop
        ), f"The 'hop' field must be an 8-bit unsigned integer. Got: {self.hop!r}"

        assert isinstance(
            self.src, Ip6Address
        ), f"The 'src' field must be an Ip6Address. Got: {type(self.src)!r}"

        assert isinstance(
            self.dst, Ip6Address
        ), f"The 'dst' field must be an Ip6Address. Got: {type(self.dst)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 packet header.
        """

        return IP6__HEADER__LEN

    @override
    def __bytes__(self) -> bytes:
        """
        Get the IPv6 header as bytes.
        """

        return struct.pack(
            IP6__HEADER__STRUCT,
            self.ver << 28 | self.dscp << 22 | self.ecn << 20 | self.flow,
            self.dlen,
            int(self.next),
            self.hop,
            bytes(self.src),
            bytes(self.dst),
        )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Ip6Header:
        """
        Initialize the IPv6 header from bytes.
        """

        ver__dscp__ecn__flow, dlen, next, hop, src, dst = struct.unpack(
            IP6__HEADER__STRUCT, _bytes[:IP6__HEADER__LEN]
        )

        return Ip6Header(
            dscp=(ver__dscp__ecn__flow >> 22) & 0b00111111,
            ecn=(ver__dscp__ecn__flow >> 20) & 0b00000011,
            flow=ver__dscp__ecn__flow & 0b00000000_00001111_11111111_11111111,
            dlen=dlen,
            next=Ip6Next.from_int(next),
            hop=hop,
            src=Ip6Address(src),
            dst=Ip6Address(dst),
        )


class Ip6HeaderProperties(ABC):
    """
    Properties used to access the IPv6 header fields.
    """

    _header: Ip6Header

    @property
    def ver(self) -> int:
        """
        Get the IPv6 header 'ver' field.
        """

        return self._header.ver

    @property
    def dscp(self) -> int:
        """
        Get the IPv6 header 'dscp' field.
        """

        return self._header.dscp

    @property
    def ecn(self) -> int:
        """
        Get the IPv6 header 'ecn' field.
        """

        return self._header.ecn

    @property
    def flow(self) -> int:
        """
        Get the IPv6 header 'flow' field.
        """

        return self._header.flow

    @property
    def dlen(self) -> int:
        """
        Get the IPv6 header 'dlen' field.
        """

        return self._header.dlen

    @property
    def next(self) -> Ip6Next:
        """
        Get the IPv6 header 'next' field.
        """

        return self._header.next

    @property
    def hop(self) -> int:
        """
        Get the IPv6 header 'hop' field.
        """

        return self._header.hop

    @property
    def src(self) -> Ip6Address:
        """
        Get the IPv6 header 'src' field.
        """

        return self._header.src

    @property
    def dst(self) -> Ip6Address:
        """
        Get the IPv6 header 'dst' field.
        """

        return self._header.dst
