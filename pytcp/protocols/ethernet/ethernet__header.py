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
This module contains the Ethernet II packet header class.

pytcp/protocols/ethernet/ethernet__header.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from abc import ABC
from dataclasses import dataclass
from typing import override

from net_addr import MacAddress
from pytcp.lib.proto_struct import ProtoStruct
from pytcp.protocols.ethernet.ethernet__enums import EthernetType

# The Ethernet II packet header [DIX].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +    Destination MAC Address    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      Source MAC Address       +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           EthernetType        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ETHERNET__HEADER__LEN = 14
ETHERNET__HEADER__STRUCT = "! 6s 6s H"


@dataclass(frozen=True, kw_only=True)
class EthernetHeader(ProtoStruct):
    """
    The Ethernet header.
    """

    dst: MacAddress
    src: MacAddress
    type: EthernetType

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the Ethernet header fields.
        """

        assert isinstance(
            self.dst, MacAddress
        ), f"The 'dst' field must be a MacAddress. Got: {type(self.dst)!r}"

        assert isinstance(
            self.src, MacAddress
        ), f"The 'src' field must be a MacAddress. Got: {type(self.src)!r}"

        assert isinstance(
            self.type, EthernetType
        ), f"The 'type' field must be an EthernetType. Got: {type(self.type)!r}"

    @override
    def __len__(self) -> int:
        """
        Get the Ethernet header length.
        """

        return ETHERNET__HEADER__LEN

    @override
    def __bytes__(self) -> bytes:
        """
        Get the Ethernet header as bytes.
        """

        return struct.pack(
            ETHERNET__HEADER__STRUCT,
            bytes(self.dst),
            bytes(self.src),
            int(self.type),
        )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes, /) -> EthernetHeader:
        """
        Initialize the Ethernet header from bytes.
        """

        dst, src, type = struct.unpack(
            ETHERNET__HEADER__STRUCT, _bytes[:ETHERNET__HEADER__LEN]
        )

        return EthernetHeader(
            dst=MacAddress(dst),
            src=MacAddress(src),
            type=EthernetType.from_int(type),
        )


class EthernetHeaderProperties(ABC):
    """
    Properties used to access Ethernet header fields.
    """

    _header: EthernetHeader

    @property
    def dst(self) -> MacAddress:
        """
        Get the Ethernet header 'dst' field.
        """

        return self._header.dst

    @dst.setter
    def dst(self, /, mac_address: MacAddress) -> None:
        """
        Set the Ethernet header 'dst' field.
        """

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self._header, "dst", mac_address)

    @property
    def src(self) -> MacAddress:
        """
        Get the Ethernet header 'src' field.
        """

        return self._header.src

    @src.setter
    def src(self, /, mac_address: MacAddress) -> None:
        """
        Set the Ethernet header 'src' field.
        """

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self._header, "src", mac_address)

    @property
    def type(self) -> EthernetType:
        """
        Get the Ethernet header 'type' field.
        """

        return self._header.type
