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
This module contains IP address base class.

net_addr/ip_address.py

ver 3.0.4
"""


from abc import ABC, abstractmethod

from net_addr.address import Address
from net_addr.ip import Ip
from net_addr.mac_address import MacAddress


class IpAddress(Address, Ip, ABC):
    """
    IP address support base class.
    """

    __slots__ = ()

    @property
    @abstractmethod
    def multicast_mac(self) -> MacAddress:
        """
        The 'multicast_mac' property placeholder.
        """

        raise NotImplementedError

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
