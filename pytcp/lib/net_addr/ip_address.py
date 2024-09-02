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

    _address: int
    _version: int

    def __int__(self) -> int:
        """
        Get the IP address as int.
        """

        return self._address

    def __eq__(
        self,
        other: object,
    ) -> bool:
        """
        Compare IP address with another object.
        """

        return repr(self) == repr(other)

    def __repr__(self) -> str:
        """
        Get the IP address representation string.
        """

        return f"{self.__class__.__name__}('{str(self)}')"

    def __hash__(self) -> int:
        """
        Get the IP address hash.
        """

        return self._address

    @property
    def version(self) -> int:
        """
        Get the IP address version.
        """

        return self._version

    @property
    @abstractmethod
    def unspecified(self) -> IpAddress:
        """
        Get the unspecified IP address for current address family.
        """

        raise NotImplementedError

    @property
    def is_ip6(self) -> bool:
        """
        Check if the IP address version is 6.
        """

        return self._version == 6

    @property
    def is_ip4(self) -> bool:
        """
        Check if the IP address version is 4.
        """

        return self._version == 4

    @property
    def is_unspecified(self) -> bool:
        """
        Check if the IP address is an unspecified address.
        """

        return self._address == 0

    @property
    def is_unicast(self) -> bool:
        """
        Check if IP address is an unicast address.
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
    def __str__(self) -> str:
        """
        Get the IP address log string.
        """

        raise NotImplementedError

    @abstractmethod
    def __bytes__(self) -> bytes:
        """
        Get the IP address as bytes.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def is_loopback(self) -> bool:
        """
        Check if IP address is a loopback address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def is_global(self) -> bool:
        """
        Check if IP address is a global address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def is_private(self) -> bool:
        """
        Check if IP address is a private address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def is_link_local(self) -> bool:
        """
        Check if IP address is a link local address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def is_multicast(self) -> bool:
        """
        Check if IP address is a multicast address.
        """

        raise NotImplementedError

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
