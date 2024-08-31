#!/usr/bin/env python3

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
This module contains the IPv6 Ext Frag header class.

pytcp/protocols/ip6_ext_frag/ip6_ext_frag__header.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from abc import ABC
from dataclasses import dataclass
from typing import override

from pytcp.lib.int_checks import is_8_byte_alligned, is_uint13, is_uint32
from pytcp.lib.proto_struct import ProtoStruct
from pytcp.protocols.ip6.ip6__enums import Ip6Next

# The IPv6 packet Fragmentation Extension header [RFC 2460].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Next header   |       0       |         Offset          |0|0|M|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                               Id                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP6_EXT_FRAG__HEADER__LEN = 8
IP6_EXT_FRAG__HEADER__STRUCT = "! BBH L"


@dataclass(frozen=True, kw_only=True)
class Ip6ExtFragHeader(ProtoStruct):
    """
    The IPv6 Ext Frag header.
    """

    next: Ip6Next
    offset: int
    flag_mf: bool
    id: int

    @override
    def __post_init__(self) -> None:
        """
        Validate the IPv6 Ext Frag header fields.
        """

        assert isinstance(
            self.next, Ip6Next
        ), f"The 'next' field must be an Ip6Next. Got: {type(self.next)!r}"

        assert is_uint13(
            self.offset
        ), f"The 'offset' field must be a 13-bit unsigned integer. Got: {self.offset!r}"

        assert is_8_byte_alligned(
            self.offset
        ), f"The 'offset' field must be 8-byte aligned. Got: {self.offset!r}"

        assert isinstance(
            self.flag_mf, bool
        ), f"The 'flag_mf' field must be a boolean. Got: {type(self.flag_mf)!r}"

        assert is_uint32(
            self.id
        ), f"The 'id' field must be a 32-bit unsigned integer. Got: {self.id!r}"

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 Ext Frag header length.
        """

        return IP6_EXT_FRAG__HEADER__LEN

    @override
    def __bytes__(self) -> bytes:
        """
        Get the IPv6 Ext Frag header as bytes.
        """

        return struct.pack(
            IP6_EXT_FRAG__HEADER__STRUCT,
            int(self.next),
            0,
            self.offset | self.flag_mf,
            self.id,
        )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> Ip6ExtFragHeader:
        """
        Initialize the IPv6 Ext Frag header from bytes.
        """

        next, _, offset__flag_mf, id = struct.unpack(
            IP6_EXT_FRAG__HEADER__STRUCT, _bytes[:IP6_EXT_FRAG__HEADER__LEN]
        )

        return Ip6ExtFragHeader(
            next=Ip6Next.from_int(next),
            offset=offset__flag_mf & 0b11111111_11111000,
            flag_mf=bool(offset__flag_mf & 0b00000000_00000001),
            id=id,
        )


class Ip6ExtFragHeaderProperties(ABC):
    """
    Properties used to access the IPv6 Ext Frag header fields.
    """

    _header: Ip6ExtFragHeader

    @property
    def next(self) -> Ip6Next:
        """
        Get the IPv6 Ext Frag 'next' field.
        """

        return self._header.next

    @property
    def offset(self) -> int:
        """
        Get the IPv6 Ext Frag 'offset' field.
        """

        return self._header.offset

    @property
    def flag_mf(self) -> bool:
        """
        Get the IPv6 Ext Frag 'flag_mf' field.
        """

        return self._header.flag_mf

    @property
    def id(self) -> int:
        """
        Get the IPv6 Ext Frag 'id' field.
        """

        return self._header.id
