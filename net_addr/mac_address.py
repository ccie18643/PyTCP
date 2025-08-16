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
This module contains Ethernet MAC address manipulation class.

net_addr/mac_address.py

ver 3.0.3
"""


from __future__ import annotations

import re
from typing import override

from net_addr.address import Address
from net_addr.errors import MacAddressFormatError


class MacAddress(Address):
    """
    Ethernet MAC address support class.
    """

    __slots__ = ()

    def __init__(
        self,
        address: (
            MacAddress | str | bytes | bytearray | memoryview | int | None
        ) = None,
        /,
    ) -> None:
        """
        Create a new MAC address object.
        """

        if address is None:
            self._address = 0
            return

        if isinstance(address, int):
            if 0 <= address <= 0xFFFF_FFFF_FFFF:
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == 6:
                self._address = int.from_bytes(address)
                return

        if isinstance(address, str):
            if re.search(
                r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", address.strip()
            ):
                self._address = int.from_bytes(
                    bytes.fromhex(
                        re.sub(r":|-|\.", "", address.lower().strip())
                    ),
                )
                return

        if isinstance(address, MacAddress):
            self._address = int(address)
            return

        raise MacAddressFormatError(address)

    @override
    def __str__(self) -> str:
        """
        Get the MAC address log string.
        """

        return ":".join([f"{_:0>2x}" for _ in bytes(self)])

    @override
    def __bytes__(self) -> bytes:
        """
        Get the MAC address as bytes.
        """

        return int(self._address).to_bytes(6)

    @property
    def is_unicast(self) -> bool:
        """
        Check if MAC address is unicast.
        """

        return (
            (self._address & 0x0100_0000_0000) == 0x0000_0000_0000
        ) and not self.is_unspecified

    @property
    def is_multicast(self) -> bool:
        """
        Check if MAC address is multicast.
        """

        return (
            (self._address & 0x0100_0000_0000) == 0x0100_0000_0000
        ) and not self.is_broadcast

    @property
    def is_multicast__ip4(self) -> bool:
        """
        Check if MAC address is a IPv4 multicast MAC.
        """

        return (self._address & 0xFFFF_FF00_0000) == 0x0100_5E00_0000

    @property
    def is_multicast__ip6(self) -> bool:
        """
        Check if MAC address is a MAC for IPv6 multicast MAC.
        """

        return (self._address & 0xFFFF_0000_0000) == 0x3333_0000_0000

    @property
    def is_multicast__ip6__solicited_node(self) -> bool:
        """
        Check if address is IPv6 solicited node multicast MAC.
        """

        return (self._address & 0xFFFF_FF00_0000) == 0x3333_FF00_0000

    @property
    def is_broadcast(self) -> bool:
        """
        Check if MAC address is a broadcast.
        """

        return self._address == 0xFFFF_FFFF_FFFF
