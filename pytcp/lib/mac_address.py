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

# pylint: disable = missing-class-docstring

"""
Module contains Ethernet MAC address manipulation class.

pytcp/lib/mac_address.py

ver 2.7
"""


from __future__ import annotations

import re
import struct


class MacIp4AddressFormatError(Exception):
    pass


class MacAddress:
    """
    Ethernet MAC address support class.
    """

    def __init__(
        self, address: MacAddress | str | bytes | bytearray | memoryview | int
    ) -> None:
        """
        Class constructor.
        """

        if isinstance(address, int):
            if address in range(281474976710656):
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == 6:
                v_1, v_2, v_3 = struct.unpack("!HHH", address)
                self._address = (v_1 << 32) + (v_2 << 16) + v_3
                return

        if isinstance(address, str):
            if re.search(
                r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", address.strip()
            ):
                v_1, v_2, v_3 = struct.unpack(
                    "!HHH",
                    bytes.fromhex(
                        re.sub(r":|-|\.", "", address.lower().strip())
                    ),
                )
                self._address = (v_1 << 32) + (v_2 << 16) + v_3
                return

        if isinstance(address, MacAddress):
            self._address = int(address)
            return

        raise MacIp4AddressFormatError(address)

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """
        return ":".join([f"{_:0>2x}" for _ in bytes(self)])

    def __repr__(self) -> str:
        """
        The '__repr__()' dunder.
        """
        return f"MacAddress('{str(self)}')"

    def __bytes__(self) -> bytes:
        """
        The '__bytes__() dunder.
        """
        return struct.pack(
            "!HHH",
            (self._address >> 32) & 0xFFFF,
            (self._address >> 16) & 0xFFFF,
            self._address & 0xFFFF,
        )

    def __int__(self) -> int:
        """
        The '__int__()' dunder.
        """
        return self._address

    def __eq__(self, other: object) -> bool:
        """
        The '__eq__()' dunder.
        """
        return repr(self) == repr(other)

    def __hash__(self) -> int:
        """
        The '__hash__' dunder.
        """
        return self._address

    @property
    def is_unspecified(self) -> bool:
        """
        Check if address is unspecified.
        """
        return self._address == 0

    @property
    def is_unicast(self) -> bool:
        """
        Check if address is unicast.
        """
        return (
            self._address != 0  # unspecified
            and self._address
            not in range(1101088686080, 1101105463296)  # IPv4 multicast
            and self._address
            not in range(56294136348672, 56298431315968)  # IPv6 multicast
            and self._address != 281474976710655  # broadcast
        )

    @property
    def is_multicast_ip4(self) -> bool:
        """
        Check if address is a MAC for IPv4 multicast.
        """
        return self._address in range(1101088686080, 1101105463296)

    @property
    def is_multicast_ip6(self) -> bool:
        """
        Check if address is a MAC for IPv6 multicast.
        """
        return self._address in range(56294136348672, 56298431315968)

    @property
    def is_multicast_ip6_solicited_node(self) -> bool:
        """
        Check if address is a MAC for IPv6 solicited node multicast.
        """
        return self._address in range(56298414538752, 56298431315968)

    @property
    def is_broadcast(self) -> bool:
        """
        Check if address is a broadcast MAC.
        """
        return self._address == 281474976710655
