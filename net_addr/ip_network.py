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
This module contains IP network base class.

net_addr/ip_network.py

ver 3.0.3
"""


from abc import ABC, abstractmethod

from .ip4_address import Ip4Address
from .ip4_mask import Ip4Mask
from .ip6_address import Ip6Address
from .ip6_mask import Ip6Mask
from .ip_address import IpAddress, IpVersion


class IpNetwork[A: (Ip6Address, Ip4Address), M: (Ip6Mask, Ip4Mask)](ABC):
    """
    IP network support base class.
    """

    __slots__ = (
        "_version",
        "_address",
        "_mask",
    )

    _version: IpVersion
    _address: A
    _mask: M

    def __str__(self) -> str:
        """
        Get the IP network log string.
        """

        return str(self._address) + "/" + str(len(self._mask))

    def __repr__(self) -> str:
        """
        Get the IP network representation string.
        """

        return f"{self.__class__.__name__}('{str(self)}')"

    def __eq__(self, other: object, /) -> bool:
        """
        Compare IP network with another object.
        """

        return other is self or (
            isinstance(other, type(self))
            and self._address == other._address
            and self._mask == other._mask
        )

    def __hash__(self) -> int:
        """
        Get the IP network hash.
        """

        return hash(repr(self))

    def __contains__(self, other: object, /) -> bool:
        """
        Check if the IP network contains the IP address or host.
        """

        from .ip4_host import Ip4Host
        from .ip6_host import Ip6Host

        if isinstance(other, (Ip6Address, Ip4Address)):
            return self._version == other.version and int(self.address) <= int(
                other
            ) <= int(self.last)

        if isinstance(other, (Ip4Host, Ip6Host)):
            return self._version == other.version and int(self.address) <= int(
                other.address
            ) <= int(self.last)

        return False

    @property
    def version(self) -> IpVersion:
        """
        Getter the IP network version.
        """

        return self._version

    @property
    def is_ip6(self) -> bool:
        """
        Check if the IP network version is 6.
        """

        return self._version == IpVersion.IP6

    @property
    def is_ip4(self) -> bool:
        """
        Check if the IP network version is 4.
        """

        return self._version == IpVersion.IP4

    @property
    def address(self) -> A:
        """
        Get the IP network '_address' attribute.
        """

        return self._address

    @property
    def mask(self) -> M:
        """
        Get the IP network '_mask' attribute.
        """

        return self._mask

    @property
    @abstractmethod
    def last(self) -> IpAddress:
        """
        Get the IP network last address.
        """

        raise NotImplementedError
