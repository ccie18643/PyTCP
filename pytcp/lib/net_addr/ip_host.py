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
Module contains IP host base class.

pytcp/lib/ip_host.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from .ip_address import IpAddress

if TYPE_CHECKING:
    from .ip_network import IpNetwork


class IpHost(ABC):
    """
    IP host support base class.
    """

    @abstractmethod
    def __init__(self) -> None:
        """
        Class constructor placeholder.
        """

        self._address: IpAddress
        self._network: IpNetwork
        self._version: int
        self._gateway: IpAddress | None

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """

        return str(self._address) + "/" + str(len(self._network.mask))

    def __repr__(self) -> str:
        """
        The '__repr__()' dunder.
        """

        return f"Ip{self._version}Host('{str(self)}')"

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

        return hash(self._address) ^ hash(self._network)

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
    def network(self) -> IpNetwork:
        """
        The 'network' property placeholder.
        """

    @property
    @abstractmethod
    def gateway(self) -> IpAddress | None:
        """
        The 'gateway' property getter placeholder.
        """

    @gateway.setter
    @abstractmethod
    def gateway(
        self,
        address: IpAddress | None,
    ) -> None:
        """
        The 'gateway' property setter placeholder.
        """
