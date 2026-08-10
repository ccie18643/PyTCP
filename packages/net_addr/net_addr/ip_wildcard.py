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
This module contains IP wildcard base class.

net_addr/ip_wildcard.py

ver 3.0.9
"""

from abc import ABC, abstractmethod
from typing import override

from net_addr.base import Base
from net_addr.ip import Ip
from net_addr.ip4_address import Ip4Address
from net_addr.ip6_address import Ip6Address


class IpWildcard(Base, Ip, ABC):
    """
    IP wildcard support base class.

    A wildcard is an arbitrary per-bit mask used for ACL /
    firewall matching (a 1 bit means 'don't care', a 0 bit
    means 'must match'). Unlike a netmask it is NOT constrained
    to contiguous bits; the network hostmask is merely the
    special case where the wildcard equals the inverted
    netmask.
    """

    __slots__ = ("_wildcard",)

    _wildcard: int

    def __len__(self) -> int:
        """
        Get the number of wildcarded (don't-care) bits.
        """

        return self._wildcard.bit_count()

    @abstractmethod
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IP wildcard as a memoryview.
        """

        raise NotImplementedError

    def __int__(self) -> int:
        """
        Get the IP wildcard as integer.
        """

        return self._wildcard

    def __or__(self, other: object, /) -> Ip4Address | Ip6Address:
        """
        Get the canonical wildcard representative of an address:
        every don't-care bit (wildcard=1) forced high, every
        care bit unchanged, so '(a | w) == (b | w)' is the
        ACL-equivalence test. A non-address or cross-version
        operand returns 'NotImplemented' so Python falls back
        to the reflected operand and ultimately raises
        TypeError if unsupported.
        """

        if isinstance(other, Ip4Address) and self.version == other.version:
            return Ip4Address(int(other) | self._wildcard)

        if isinstance(other, Ip6Address) and self.version == other.version:
            return Ip6Address(int(other) | self._wildcard)

        return NotImplemented

    def __ror__(self, other: object, /) -> Ip4Address | Ip6Address:
        """
        Get the canonical wildcard representative of an address
        (reflected operand form; bitwise OR is commutative).
        """

        return self.__or__(other)

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Compare the IP wildcard with another object.
        """

        return other is self or (isinstance(other, type(self)) and self._wildcard == other._wildcard)

    @override
    def __hash__(self) -> int:
        """
        Get the IP wildcard hash value.
        """

        return hash((type(self), self._wildcard))
