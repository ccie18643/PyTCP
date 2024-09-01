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
Module contains IP network base class.

pytcp/lib/ip_network.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from .ip_address import IpAddress
from .ip_host import IpHost

if TYPE_CHECKING:
    from .ip4_address import Ip4Address
    from .ip6_host import Ip6Host
    from .ip_mask import IpMask
    from .mac_address import MacAddress


class IpNetwork(ABC):
    """
    IP network support base class.
    """

    @abstractmethod
    def __init__(self) -> None:
        """
        Class constructor placeholder.
        """

        self._address: IpAddress
        self._mask: IpMask
        self._version: int

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """

        return str(self._address) + "/" + str(len(self._mask))

    def __repr__(self) -> str:
        """
        The '__repr__()' dunder.
        """

        return f"Ip{self._version}Network('{str(self)}')"

    def __eq__(
        self,
        other: object,
    ) -> bool:
        """
        The '__eq__()' dunder.
        """

        return repr(self) == repr(other)

    def __hash__(self) -> int:
        """
        The '__hash__()' dunder.
        """

        return hash(self._address) ^ hash(self._mask)

    def __contains__(
        self,
        other: object,
    ) -> bool:
        """
        The '__contains__()' dunder for the 'in' operator.
        """

        if isinstance(other, IpAddress):
            return (
                isinstance(other, IpAddress)
                and self._version == other.version
                and int(self.address) <= int(other) <= int(self.last)
            )

        if isinstance(other, IpHost):
            return (
                isinstance(other, IpHost)
                and self._version == other.version
                and int(self.address) <= int(other.address) <= int(self.last)
            )

        return False

    @property
    def version(self) -> int:
        """
        Getter for the '_version' attribute.
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
    @abstractmethod
    def address(self) -> IpAddress:
        """
        The 'address' property placeholder.
        """

    @property
    @abstractmethod
    def mask(self) -> IpMask:
        """
        The 'mask' property placeholder.
        """

    @property
    @abstractmethod
    def last(self) -> IpAddress:
        """
        The 'last' property placeholder.
        """

    if TYPE_CHECKING:

        @property
        def broadcast(self) -> Ip4Address:
            """
            The 'broadcast' property placeholder.
            """

            raise NotImplementedError

        def eui64(self, mac_address: MacAddress) -> Ip6Host:
            """
            The 'eui64' property placeholder.
            """

            raise NotImplementedError
