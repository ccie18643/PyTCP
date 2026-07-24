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
This module contains IP interface address base class.

net_addr/ip_ifaddr.py

ver 3.0.9
"""

from abc import ABC, abstractmethod
from typing import ClassVar, Self, override

from net_addr.base import Base
from net_addr.errors import IfAddrSanityError, NetAddrError
from net_addr.ip import Ip
from net_addr.ip4_address import Ip4Address
from net_addr.ip4_network import Ip4Network
from net_addr.ip6_address import Ip6Address
from net_addr.ip6_network import Ip6Network


class IfAddr[
    A: (Ip6Address, Ip4Address),
    N: (Ip6Network, Ip4Network),
](Base, Ip, ABC):
    """
    IP interface address support base class.
    """

    __slots__ = (
        "_address",
        "_network",
    )

    _address: A
    _network: N

    # The concrete interface-address type's free-message sanity
    # error (net_addr raises only NetAddrError subclasses).
    # Concrete subclasses override with the version-specific
    # Sanity error; the default is a NetAddrError-subclass
    # safety net so a subclass that omits the override still
    # honours the §7.1 contract rather than raising
    # AttributeError.
    _sanity_error: ClassVar[type[NetAddrError]] = IfAddrSanityError

    @abstractmethod
    def __init__(
        self,
        host: Self | tuple[A, N] | str,
        /,
    ) -> None:
        """
        Initialize the IP interface address object. Concrete
        subclasses bind the version-specific address / network /
        mask types and the accepted input forms.
        """

        raise NotImplementedError

    @override
    def __str__(self) -> str:
        """
        Get the IP interface address log string.
        """

        return f"{self._address}/{len(self._network.mask)}"

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Compare the IP interface address with another object.
        """

        return other is self or (
            isinstance(other, type(self)) and self._address == other._address and self._network == other._network
        )

    @override
    def __hash__(self) -> int:
        """
        Get the IP interface address hash value.
        """

        return hash((type(self), self._address, self._network))

    def __lt__(self, other: object, /) -> bool:
        """
        Order the interface address by host address then
        network. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (self._address, self._network) < (other._address, other._network)

    def __le__(self, other: object, /) -> bool:
        """
        Order the interface address by host address then
        network. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (self._address, self._network) <= (other._address, other._network)

    def __gt__(self, other: object, /) -> bool:
        """
        Order the interface address by host address then
        network. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (self._address, self._network) > (other._address, other._network)

    def __ge__(self, other: object, /) -> bool:
        """
        Order the interface address by host address then
        network. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (self._address, self._network) >= (other._address, other._network)

    @override
    def __format__(self, format_spec: str, /) -> str:
        """
        Render the interface address. An empty spec or 'pl'
        yields the canonical 'address/prefixlen' form; 'nm'
        yields 'address/netmask'; 'hm' yields
        'address/hostmask'. A trailing-'s' spec applies
        str-style width / alignment.
        """

        match format_spec:
            case "" | "pl":
                return str(self)
            case "nm":
                return f"{self._address}/{type(self._address)(int(self._network.mask))}"
            case "hm":
                return f"{self._address}/{self._network.hostmask}"

        if format_spec[-1:] == "s":
            return format(str(self), format_spec)

        raise type(self)._sanity_error(
            f"Unknown format code {format_spec!r} for object of type {type(self).__name__!r}"
        )

    @property
    def address(self) -> A:
        """
        Get the IP interface host address.
        """

        return self._address

    @property
    def network(self) -> N:
        """
        Get the IP interface network.
        """

        return self._network
