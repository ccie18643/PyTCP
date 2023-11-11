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
Module contains packet structure information for the Ethernet protccol.

pytcp/protocols/ethernet/ps.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING, TypeAlias

from pytcp.lib.enum import ProtoEnum
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.proto import Proto

if TYPE_CHECKING:
    from pytcp.protocols.arp.fpa import ArpAssembler
    from pytcp.protocols.ip4.fpa import Ip4Assembler, Ip4FragAssembler
    from pytcp.protocols.ip6.fpa import Ip6Assembler
    from pytcp.protocols.raw.fpa import RawAssembler

    EthernetPayload: TypeAlias = (
        ArpAssembler
        | Ip4Assembler
        | Ip4FragAssembler
        | Ip6Assembler
        | RawAssembler
    )

# Ethernet packet header.

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +    Destination MAC Address    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      Source MAC Address       +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           EthernetType           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ETHERNET_HEADER_LEN = 14


class EthernetType(ProtoEnum):
    """
    Ethernet packet type enum.
    """

    ARP = 0x0806
    IP4 = 0x0800
    IP6 = 0x86DD
    RAW = 0xFFFF

    @staticmethod
    def _extract(frame: bytes) -> int:
        return int(struct.unpack("! H", frame[12:14])[0])


class Ethernet(Proto):
    """
    Base class for Ethernet packet parser and assembler.
    """

    _dst: MacAddress
    _src: MacAddress
    _type: EthernetType

    def __str__(self) -> str:
        """
        Get packet log string.
        """

        return (
            f"ETHER {self._src} > {self._dst}, 0x{int(self._type):0>4x} "
            f"({self._type}), plen {len(self)}"
        )

    def __repr__(self) -> str:
        """
        Get the packet representation string.
        """

        return (
            "Ethernet("
            f"src={repr(self._src)}, "
            f"dst={repr(self._dst)}, "
            f"type={repr(self._type)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the packet in raw form.
        """

        return struct.pack(
            "! 6s 6s H",
            bytes(self._dst),
            bytes(self._src),
            int(self._type),
        )

    @property
    def dst(self) -> MacAddress:
        """
        Getter for '_dst' attribute.
        """

        return self._dst

    @dst.setter
    def dst(self, mac_address: MacAddress) -> None:
        """
        Setter for the '_dst' attribute.
        """

        self._dst = mac_address

    @property
    def src(self) -> MacAddress:
        """
        Getter for '_src' attribute.
        """

        return self._src

    @src.setter
    def src(self, mac_address: MacAddress) -> None:
        """
        Setter for the '_src' attribute.
        """

        self._src = mac_address

    @property
    def type(self) -> EthernetType:
        """
        Getter for '_type' attribute.
        """

        return self._type
