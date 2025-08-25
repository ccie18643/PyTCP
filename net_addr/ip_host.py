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
This module contains IP host base class.

net_addr/ip_host.py

ver 3.0.3
"""


from abc import ABC, abstractmethod

from net_addr.ip4_address import Ip4Address
from net_addr.ip4_host_origin import Ip4HostOrigin
from net_addr.ip4_network import Ip4Network
from net_addr.ip6_address import Ip6Address
from net_addr.ip6_host_origin import Ip6HostOrigin
from net_addr.ip6_network import Ip6Network
from net_addr.ip_address import IpVersion


class IpHost[
    A: (Ip6Address, Ip4Address),
    N: (Ip6Network, Ip4Network),
    O: (Ip6HostOrigin, Ip4HostOrigin),
](ABC):
    """
    IP host support base class.
    """

    __slots__ = (
        "_version",
        "_address",
        "_network",
        "_gateway",
        "_origin",
        "_expiration_time",
    )

    _version: IpVersion
    _address: A
    _network: N
    _gateway: A | None
    _origin: O
    _expiration_time: int

    def __str__(self) -> str:
        """
        Get the IP host address log string.
        """

        return str(self._address) + "/" + str(len(self._network.mask))

    def __repr__(self) -> str:
        """
        Get the IP host address string representation.
        """

        return f"{type(self).__name__}('{str(self)}')"

    def __eq__(self, other: object) -> bool:
        """
        Compare the IP host address with another object.
        """

        return other is self or (
            isinstance(other, type(self))
            and self._address == other._address
            and self._network.mask == other._network.mask
        )

    def __hash__(self) -> int:
        """
        Get the IP host address hash.
        """

        return hash(repr(self))

    @abstractmethod
    def _validate_gateway(self, address: A | None, /) -> None:
        """
        Validate the IP host address gateway.
        """

        raise NotImplementedError

    @property
    def version(self) -> IpVersion:
        """
        Get the IP host address version.
        """

        return self._version

    @property
    def is_ip6(self) -> bool:
        """
        Check if the IP host address version is 6.
        """

        return self._version == IpVersion.IP6

    @property
    def is_ip4(self) -> bool:
        """
        Check if the IP host address version is 4.
        """

        return self._version == IpVersion.IP4

    @property
    def address(self) -> A:
        """
        Get the IP host address '_address' attribute.
        """

        return self._address

    @property
    def network(self) -> N:
        """
        Get the IP host address '_network' attribute.
        """

        return self._network

    @property
    def origin(self) -> O:
        """
        Get the IP host address '_origin' attribute.
        """

        return self._origin

    @origin.setter
    def origin(self, origin: O, /) -> None:
        """
        Set the IP host address '_origin' attribute.
        """

        self._origin = origin

    @property
    def expiration_time(self) -> int:
        """
        Get the IP host address '_expiration_time' attribute.
        """

        return self._expiration_time

    @expiration_time.setter
    def expiration_time(self, time: int, /) -> None:
        """
        Set the IP host address '_expiration_time' attribute.
        """

        self._expiration_time = time

    @property
    def gateway(self) -> A | None:
        """
        Get the IP host address '_gateway' attribute.
        """

        return self._gateway

    @gateway.setter
    def gateway(self, address: A | None, /) -> None:
        """
        Set the IPv4 host address '_gateway' attribute.
        """

        self._validate_gateway(address)

        self._gateway = address
