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

net_addr/ip_address.py

ver 3.0.2
"""


from __future__ import annotations

from abc import abstractmethod
from enum import Enum
from typing import TYPE_CHECKING

from .address import Address

if TYPE_CHECKING:
    from .mac_address import MacAddress


class IpVersion(Enum):
    """
    Enum for IP protocol version.
    """

    IP4 = 4
    IP6 = 6

    def __int__(self) -> int:
        """
        Convert the IP version to an integer.
        """

        return self.value


class IpAddress(Address):
    """
    IP address support base class.
    """

    _version: IpVersion

    @property
    def version(self) -> IpVersion:
        """
        Get the IP address version.
        """

        return self._version

    @property
    @abstractmethod
    def multicast_mac(self) -> MacAddress:
        """
        The 'multicast_mac' property placeholder.
        """

        raise NotImplementedError

    @property
    def is_ip6(self) -> bool:
        """
        Check if the IP address version is 6.
        """

        return self._version == IpVersion.IP6

    @property
    def is_ip4(self) -> bool:
        """
        Check if the IP address version is 4.
        """

        return self._version == IpVersion.IP4

    @property
    def is_unicast(self) -> bool:
        """
        Check if the IP address is an unicast address.
        """

        return any(
            (
                self.is_global,
                self.is_private,
                self.is_link_local,
                self.is_loopback,
            )
        )

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
