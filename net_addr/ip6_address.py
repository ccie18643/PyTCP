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
This module contains IPv6 address support class.

net_addr/ip6_address.py

ver 3.0.3
"""


import re
import socket
from typing import Self, override

from net_addr.errors import Ip6AddressFormatError
from net_addr.ip_address import IpAddress
from net_addr.ip_version import IpVersion
from net_addr.mac_address import MacAddress

IP6__ADDRESS_LEN = 16
IP6__MASK = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF
IP6__REGEX = (
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

    __slots__ = ("_address",)

    _version: IpVersion = IpVersion.IP6

    def __init__(
        self,
        address: (
            Self | str | bytes | bytearray | memoryview | int | None
        ) = None,
        /,
    ) -> None:
        """
        Create a new IPv6 address object.
        """

        if address is None:
            self._address = 0
            return

        if isinstance(address, int):
            if address & IP6__MASK == address:
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == 16:
                self._address = int.from_bytes(address)
                return

        if isinstance(address, str):
            if re.search(IP6__REGEX, address):
                try:
                    self._address = int.from_bytes(
                        socket.inet_pton(socket.AF_INET6, address)
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
        Get the IPv6 address log string.
        """

        return socket.inet_ntop(socket.AF_INET6, bytes(self))

    @override
    def __bytes__(self) -> bytes:
        """
        Get the IPv6 address as bytes.
        """

        return self._address.to_bytes(16)

    @property
    @override
    def multicast_mac(self) -> MacAddress:
        """
        Get the IPv6 multicast MAC address.
        """

        assert self.is_multicast, (
            "The IPv6 address must be a multicast address to get a multicast "
            f"MAC address. Got: {self}"
        )

        return MacAddress(
            int(MacAddress(0x3333_0000_0000)) | self._address & 0x0000_FFFF_FFFF
        )

    @property
    def solicited_node_multicast(self) -> Self:
        """
        Create IPv6 solicited node multicast address.
        """

        assert self.is_unicast or self.is_unspecified, (
            "The IPv6 address must be a unicast or unspecified address "
            f"to get a solicited node multicast address. Got: {self}"
        )

        cls = type(self)

        return cls(
            self._address & 0x0000_0000_0000_0000_0000_0000_00FF_FFFF
            | int(cls("ff02::1:ff00:0"))
        )

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
    def is_loopback(self) -> bool:
        """
        Check if the IPv6 address is a loopback address.
        """

        return self._address == 1  # ::1/128

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
    def is_multicast__solicited_node(self) -> bool:
        """
        Check if address is IPv6 solicited node multicast address.
        """

        return (
            self._address & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00_0000
            == 0xFF02_0000_0000_0000_0000_0001_FF00_0000
        )  # ff02::1:ff00:0/104

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
