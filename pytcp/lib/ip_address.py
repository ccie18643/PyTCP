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
Module contains base class for IP address manipulation.

pytcp/lib/ip_address.py

ver 2.7
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pytcp.lib.ip4_address import Ip4Address
    from pytcp.lib.ip6_address import Ip6Address, Ip6Host
    from pytcp.lib.mac_address import MacAddress


class IpAddressFormatError(Exception):
    pass


class IpMaskFormatError(Exception):
    pass


class IpNetworkFormatError(Exception):
    pass


class IpHostFormatError(Exception):
    pass


class IpHostGatewayError(Exception):
    pass


class IpAddress(ABC):
    """
    IP address support base class.
    """

    def __int__(self) -> int:
        """
        Integer representation.
        """
        return self._address

    def __eq__(self, other: object) -> bool:
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
    def __init__(self, address: int) -> None:
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


class IpMask(ABC):
    """
    IP network support base class.
    """

    @abstractmethod
    def __init__(self, address: int) -> None:
        """
        Class constructor placeholder.
        """
        if TYPE_CHECKING:
            self._mask: int
            self._version: int

    def __str__(self) -> str:
        """
        The '__str__()' dunder.
        """
        return f"/{len(self)}"

    def __repr__(self) -> str:
        """
        The '__str__()' dunder.
        """
        return f"Ip{self._version}Mask('{str(self)}')"

    def __int__(self) -> int:
        """
        The '__int__()' dunder.
        """
        return self._mask

    def __eq__(self, other: object) -> bool:
        """
        The '__eq__()' dunder.
        """
        return repr(self) == repr(other)

    def __hash__(self) -> int:
        """
        The '__hash__()' dunder.
        """
        return self._mask

    def __len__(self) -> int:
        """
        The '__len__()' dunder that returns the bit length of mask.
        """
        return f"{self._mask:b}".count("1")

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

    @abstractmethod
    def __bytes__(self) -> bytes:
        """
        The '__bytes__()' dunder placeholder.
        """


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

    def __eq__(self, other: object) -> bool:
        """
        The '__eq__()' dunder.
        """
        return repr(self) == repr(other)

    def __hash__(self) -> int:
        """
        The '__hash__()' dunder.
        """
        return hash(self._address) ^ hash(self._mask)

    def __contains__(self, other: object) -> bool:
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

    def __eq__(self, other: object) -> bool:
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
