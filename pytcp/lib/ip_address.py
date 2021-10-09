#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# lib/ip_address.py - module contains base class for address manipulation
#


from __future__ import annotations

from abc import ABC, abstractmethod, abstractproperty
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lib.ip4_address import Ip4Address
    from lib.ip6_address import Ip6Address, Ip6Host
    from lib.mac_address import MacAddress


class IpAddressFormatError(Exception):
    pass


class IpMaskFormatError(Exception):
    pass


class IpNetworkFormatError(Exception):
    pass


class IpHostFormatError(Exception):
    pass


class IpAddress(ABC):
    """IP address support base class"""

    def __int__(self) -> int:
        """Integer representation"""

        return self._address

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return repr(self) == repr(other)

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip{self._version}Address('{str(self)}')"

    def __hash__(self) -> int:
        """Hash"""

        return self._address

    @property
    def version(self) -> int:
        """Getter for _version"""

        return self._version

    @property
    def is_ip6(self) -> bool:
        """Check if the IP version is 6"""

        return self._version == 6

    @property
    def is_ip4(self) -> bool:
        """Check if the IP version is 4"""

        return self._version == 4

    @property
    def is_unspecified(self) -> bool:
        """Check if IPv6 address is a unspecified"""

        return self._address == 0

    @property
    def is_unicast(self) -> bool:
        """Check if address is IPv6 unicast address"""

        return any((self.is_global, self.is_private, self.is_link_local, self.is_loopback))

    @abstractmethod
    def __init__(self, address: int) -> None:

        if TYPE_CHECKING:
            self._address: int
            self._version: int

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass

    @abstractproperty
    def is_loopback(self) -> bool:
        pass

    @abstractproperty
    def is_global(self) -> bool:
        pass

    @abstractproperty
    def is_private(self) -> bool:
        pass

    @abstractproperty
    def is_link_local(self) -> bool:
        pass

    @abstractproperty
    def is_multicast(self) -> bool:
        pass

    @abstractproperty
    def unspecified(self) -> IpAddress:
        pass

    if TYPE_CHECKING:

        @property
        def is_solicited_node_multicast(self) -> bool:
            pass

        @property
        def is_invalid(self) -> bool:
            pass

        @property
        def solicited_node_multicast(self) -> Ip6Address:
            pass

        @property
        def multicast_mac(self) -> MacAddress:
            pass


class IpMask(ABC):
    """IP network support base class"""

    def __str__(self) -> str:
        """String representation"""

        return f"/{len(self)}"

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip{self._version}Mask('{str(self)}')"

    def __int__(self) -> int:
        """Integer representation"""

        return self._mask

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return repr(self) == repr(other)

    def __hash__(self) -> int:
        """Hash"""

        return self._mask

    def __len__(self) -> int:
        """Bit length representation"""

        return f"{self._mask:b}".count("1")

    @property
    def version(self) -> int:
        """IP mask version"""

        return self._version

    @property
    def is_ip6(self) -> bool:
        """Check if the IP version is 6"""

        return self._version == 6

    @property
    def is_ip4(self) -> bool:
        """Check if the IP version is 4"""

        return self._version == 4

    @abstractmethod
    def __init__(self, address: int) -> None:

        if TYPE_CHECKING:
            self._mask: int
            self._version: int

    @abstractmethod
    def __bytes__(self) -> bytes:
        pass


class IpNetwork(ABC):
    """IP network support base class"""

    def __str__(self) -> str:
        """String representation"""

        return str(self._address) + "/" + str(len(self._mask))

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip{self._version}Network('{str(self)}')"

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return repr(self) == repr(other)

    def __hash__(self) -> int:
        """Hash"""

        return hash(self._address) ^ hash(self._mask)

    def __contains__(self, other: object) -> bool:
        """Contains for 'in' operator"""

        if isinstance(other, IpAddress):
            return isinstance(other, IpAddress) and self._version == other.version and int(self.address) <= int(other) <= int(self.last)

        if isinstance(other, IpHost):
            return isinstance(other, IpHost) and self._version == other.version and int(self.address) <= int(other.address) <= int(self.last)

        return False

    @property
    def version(self) -> int:
        """IP network version"""

        return self._version

    @property
    def is_ip6(self) -> bool:
        """Check if the IP version is 6"""

        return self._version == 6

    @property
    def is_ip4(self) -> bool:
        """Check if the IP version is 4"""

        return self._version == 4

    @abstractmethod
    def __init__(self) -> None:
        """Class constructor"""

        self._address: IpAddress
        self._mask: IpMask
        self._version: int

    @abstractproperty
    def address(self) -> IpAddress:
        pass

    @abstractproperty
    def mask(self) -> IpMask:
        pass

    @abstractproperty
    def last(self) -> IpAddress:
        pass

    if TYPE_CHECKING:

        @property
        def broadcast(self) -> Ip4Address:
            pass

        def eui64(self, mac_address: MacAddress) -> Ip6Host:
            pass


class IpHost(ABC):
    """IP host support base class"""

    def __str__(self) -> str:
        """String representation"""

        return str(self._address) + "/" + str(len(self._network.mask))

    def __repr__(self) -> str:
        """Object representation"""

        return f"Ip{self._version}Host('{str(self)}')"

    def __eq__(self, other: object) -> bool:
        """Equal operator"""

        return repr(self) == repr(other)

    def __hash__(self) -> int:
        """Hash"""

        return hash(self._address) ^ hash(self._network)

    @property
    def version(self) -> int:
        """IP network version"""

        return self._version

    @property
    def is_ip6(self) -> bool:
        """Check if the IP version is 6"""

        return self._version == 6

    @property
    def is_ip4(self) -> bool:
        """Check if the IP version is 4"""

        return self._version == 4

    @abstractproperty
    def address(self) -> IpAddress:
        pass

    @abstractproperty
    def network(self) -> IpNetwork:
        pass

    @abstractmethod
    def __init__(self) -> None:
        """Class constructor"""

        self._address: IpAddress
        self._network: IpNetwork
        self._version: int

        self.gateway: IpAddress | None
