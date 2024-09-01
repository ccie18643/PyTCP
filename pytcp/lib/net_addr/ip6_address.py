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
Module contains IPv6 address support class.

pytcp/lib/net_addr/ip6_address.py

ver 3.0.2
"""


from __future__ import annotations

import re
import socket
import struct
from typing import override

from .errors import Ip6AddressFormatError
from .ip_address import IpAddress
from .mac_address import MacAddress

IP6_ADDRESS_LEN = 16

IP6_REGEX = (
    r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
    r":((:[0-9a-fA-F]{1,4}){1,7}|:))"
)


class Ip6Address(IpAddress):
    """
    IPv6 address support class.
    """

    def __init__(
        self,
        address: (
            Ip6Address | str | bytes | bytearray | memoryview | int | None
        ) = None,
    ) -> None:
        """
        Class constructor.
        """

        self._address: int
        self._version: int = 6

        if address is None:
            self._address = 0
            return

        if isinstance(address, int):
            if address & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF == address:
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == 16:
                v_1, v_2, v_3, v_4 = struct.unpack("!LLLL", address)
                self._address = (v_1 << 96) + (v_2 << 64) + (v_3 << 32) + v_4
                return

        if isinstance(address, str):
            if re.search(IP6_REGEX, address):
                try:
                    v_1, v_2, v_3, v_4 = struct.unpack(
                        "!LLLL", socket.inet_pton(socket.AF_INET6, address)
                    )
                    self._address = (
                        (v_1 << 96) + (v_2 << 64) + (v_3 << 32) + v_4
                    )
                    return
                except OSError:
                    pass

        if isinstance(address, Ip6Address):
            self._address = int(address)
            return

        raise Ip6AddressFormatError(address)

    @override
    def __str__(self) -> str:
        """
        String representation
        """

        return socket.inet_ntop(socket.AF_INET6, bytes(self))

    @override
    def __bytes__(self) -> bytes:
        """
        Bytes representation
        """

        return struct.pack(
            "!LLLL",
            (self._address >> 96) & 0xFFFFFFFF,
            (self._address >> 64) & 0xFFFFFFFF,
            (self._address >> 32) & 0xFFFFFFFF,
            self._address & 0xFFFFFFFF,
        )

    @property
    @override
    def is_loopback(self) -> bool:
        """
        Check if IPv6 address is loopback.
        """

        return self._address == 1  # ::1/128

    @property
    @override
    def is_global(self) -> bool:
        """
        Check if IPv6 address is global.
        """

        return (
            self._address & 0xE000_0000_0000_0000_0000_0000_0000_0000
            == 0x2000_0000_0000_0000_0000_0000_0000_0000
        )  # 2000::/3

    @property
    @override
    def is_private(self) -> bool:
        """
        Check if IPv6 address is private.
        """

        return (
            self._address & 0xFE00_0000_0000_0000_0000_0000_0000_0000
            == 0xFC00_0000_0000_0000_0000_0000_0000_0000
        )  # fc00::/7

    @property
    @override
    def is_link_local(self) -> bool:
        """
        Check if IPv6 address is link local.
        """

        return (
            self._address & 0xFFC0_0000_0000_0000_0000_0000_0000_0000
            == 0xFE80_0000_0000_0000_0000_0000_0000_0000
        )  # fe80::/10

    @property
    @override
    def is_multicast(self) -> bool:
        """
        Check if IPv6 address is multicast.
        """

        return (
            self._address & 0xFF00_0000_0000_0000_0000_0000_0000_0000
            == 0xFF00_0000_0000_0000_0000_0000_0000_0000
        )  # ff00::/8

    @property
    def is_multicast__all_nodes(self) -> bool:
        """
        Check if address is IPv6 all nodes multicast address.
        """

        return (
            self._address == 0xFF02_0000_0000_0000_0000_0000_0000_0001
        )  # ff02::1/128

    @property
    def is_multicast__all_routers(self) -> bool:
        """
        Check if address is IPv6 all routers multicast address.
        """

        return (
            self._address == 0xFF02_0000_0000_0000_0000_0000_0000_0002
        )  # ff02::2/128

    @property
    @override
    def is_solicited_node_multicast(self) -> bool:
        """
        Check if address is IPv6 solicited node multicast address.
        """

        return (
            self._address & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00_0000
            == 0xFF02_0000_0000_0000_0000_0001_FF00_0000
        )  # ff02::1:ff00:0/104

    @property
    @override
    def solicited_node_multicast(self) -> Ip6Address:
        """
        Create IPv6 solicited node multicast address.
        """

        return Ip6Address(
            self._address & 0xFFFFFF | int(Ip6Address("ff02::1:ff00:0"))
        )

    @property
    @override
    def multicast_mac(self) -> MacAddress:
        """
        Create IPv6 multicast MAC address.
        """

        assert self.is_multicast
        return MacAddress(
            int(MacAddress(0x333300000000)) | self._address & 0xFFFFFFFF
        )

    @property
    @override
    def unspecified(self) -> Ip6Address:
        """
        Return unspecified IPv6 Address.
        """

        return Ip6Address()
