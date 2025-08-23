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
This module contains the Ethernet 802.3 header class.

pytcp/protocols/ethernet_802_3/ethernet_802_3__header.py

ver 3.0.3
"""


import struct
from abc import ABC
from dataclasses import dataclass
from typing import Self, override

from net_addr import MacAddress
from pytcp.lib.int_checks import is_uint16
from pytcp.lib.proto_struct import ProtoStruct

# The Ethernet 802.3 packet header [IEEE].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +    Destination MAC Address    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      Source MAC Address       +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Dlen             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ETHERNET_802_3__HEADER__LEN = 14
ETHERNET_802_3__HEADER__STRUCT = "! 6s 6s H"
ETHERNET_802_3__PACKET__MAX_LEN = 1514
ETHERNET_802_3__PAYLOAD__MAX_LEN = (
    ETHERNET_802_3__PACKET__MAX_LEN - ETHERNET_802_3__HEADER__LEN
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Ethernet8023Header(ProtoStruct):
    """
    The Ethernet 802.3 packet header.
    """

    dst: MacAddress
    src: MacAddress
    dlen: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the Ethernet 802.3 header fields.
        """

        assert isinstance(
            self.dst, MacAddress
        ), f"The 'dst' field must be a MacAddress. Got: {type(self.dst)!r}"

        assert isinstance(
            self.src, MacAddress
        ), f"The 'src' field must be a MacAddress. Got: {type(self.src)!r}"

        assert (
            is_uint16(self.dlen)
            and self.dlen <= ETHERNET_802_3__PAYLOAD__MAX_LEN
        ), (
            "The 'dlen' field must be a 16-bit unsigned integer lower than or "
            f"equal to {ETHERNET_802_3__PAYLOAD__MAX_LEN}. Got: {self.dlen!r}"
        )

    @override
    def __len__(self) -> int:
        """
        Get the Ethernet 802.3 header length.
        """

        return ETHERNET_802_3__HEADER__LEN

    @override
    def __bytes__(self) -> bytes:
        """
        Get the Ethernet 802.3 header as bytes.
        """

        return struct.pack(
            ETHERNET_802_3__HEADER__STRUCT,
            bytes(self.dst),
            bytes(self.src),
            self.dlen,
        )

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Initialize the Ethernet 802.3 header from bytes.
        """

        dst, src, dlen = struct.unpack(
            ETHERNET_802_3__HEADER__STRUCT, _bytes[:ETHERNET_802_3__HEADER__LEN]
        )

        return cls(
            dst=MacAddress(dst),
            src=MacAddress(src),
            dlen=dlen,
        )


class EthernetHeader8023Properties(ABC):
    """
    Properties used to access Ethernet 802.3 header fields.
    """

    _header: Ethernet8023Header

    @property
    def dst(self) -> MacAddress:
        """
        Get the Ethernet 802.3 header 'dst' field.
        """

        return self._header.dst

    @dst.setter
    def dst(self, /, mac_address: MacAddress) -> None:
        """
        Set the Ethernet 802.3 header 'dst' field.
        """

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self._header, "dst", mac_address)

    @property
    def src(self) -> MacAddress:
        """
        Get the Ethernet 802.3 header 'src' field.
        """

        return self._header.src

    @src.setter
    def src(self, /, mac_address: MacAddress) -> None:
        """
        Set the Ethernet 802.3 header 'src' field.
        """

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(self._header, "src", mac_address)

    @property
    def dlen(self) -> int:
        """
        Get the Ethernet 802.3 header 'dlen' field.
        """

        return self._header.dlen
