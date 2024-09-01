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
Module contains IP address base class.

pytcp/lib/ip_address.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ip6_address import Ip6Address
    from .mac_address import MacAddress


class IpAddress(ABC):
    """
    IP address support base class.
    """

    def __int__(self) -> int:
        """
        Integer representation.
        """

        return self._address

    def __eq__(
        self,
        other: object,
    ) -> bool:
        """
        The '__eq__()' dunder.
        """

        return repr(self) == repr(other)

    def __repr__(self) -> str:
        """
        The '__repr()__' dunder.
        """

        return f"Ip{self._version}Address('{str(self)}')"

    def __hash__(self) -> int:
        """
        The '__hash__()' dunder.
        """

        return self._address

    @property
    def version(self) -> int:
        """
        Getter for '_version' attribute.
        """

        return self._version

    @property
    def is_ip6(self) -> bool:
        """
        Check if the IP version is 6.
        """

        return self._version == 6

    @property
    def is_ip4(self) -> bool:
        """
        Check if the IP version is 4.
        """

        return self._version == 4

    @property
    def is_unspecified(self) -> bool:
        """
        Check if address is a unspecified.
        """

        return self._address == 0

    @property
    def is_unicast(self) -> bool:
        """
        Check if address is a unicast address.
        """

        return any(
            (
                self.is_global,
                self.is_private,
                self.is_link_local,
                self.is_loopback,
            )
        )

    @abstractmethod
    def __init__(
        self,
        address: int,
    ) -> None:
        """
        Class constructor placeholder.
        """

        if TYPE_CHECKING:
            self._address: int
            self._version: int

    @abstractmethod
    def __str__(self) -> str:
        """
        The '__str__()' dunder placeholder.
        """

    @abstractmethod
    def __bytes__(self) -> bytes:
        """
        The '__bytes__()' dunder placeholder.
        """

    @property
    @abstractmethod
    def is_loopback(self) -> bool:
        """
        The 'is_loopback' property placeholder.
        """

    @property
    @abstractmethod
    def is_global(self) -> bool:
        """
        The 'is_global' property placeholder.
        """

    @property
    @abstractmethod
    def is_private(self) -> bool:
        """
        The 'is_private' property placeholder.
        """

    @property
    @abstractmethod
    def is_link_local(self) -> bool:
        """
        The 'is_link_local' property placeholder.
        """

    @property
    @abstractmethod
    def is_multicast(self) -> bool:
        """
        The 'is_multicast' property placeholder.
        """

    @property
    @abstractmethod
    def unspecified(self) -> IpAddress:
        """
        The 'unspecified' property placeholder.
        """

    if TYPE_CHECKING:

        @property
        def is_solicited_node_multicast(self) -> bool:
            """
            The 'is_solicited_node_multicast' property placeholder.
            """

            raise NotImplementedError

        @property
        def is_invalid(self) -> bool:
            """
            The 'is_invalid' property placeholder.
            """

            raise NotImplementedError

        @property
        def solicited_node_multicast(self) -> Ip6Address:
            """
            The 'solicited_node_multicast' property placeholder.
            """

            raise NotImplementedError

        @property
        def multicast_mac(self) -> MacAddress:
            """
            The 'multicast_mac' property placeholder.
            """

            raise NotImplementedError
