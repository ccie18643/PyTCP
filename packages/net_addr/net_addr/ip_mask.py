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
This module contains IP mask base class.

net_addr/ip_mask.py

ver 3.0.9
"""

from abc import ABC, abstractmethod
from typing import override

from net_addr.base import Base
from net_addr.ip import Ip
from net_addr.ip4_address import Ip4Address
from net_addr.ip6_address import Ip6Address


class IpMask(Base, Ip, ABC):
    """
    IP mask support base class.
    """

    __slots__ = ("_mask",)

    _mask: int

    def __len__(self) -> int:
        """
        Get the IP mask prefix length.
        """

        return self._mask.bit_count()

    @override
    def __str__(self) -> str:
        """
        Get the IP mask log string.
        """

        return f"/{len(self)}"

    @abstractmethod
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IP mask as a memoryview.
        """

        raise NotImplementedError

    def __int__(self) -> int:
        """
        Get the IP mask as integer.
        """

        return self._mask

    def __and__(self, other: object, /) -> Ip4Address | Ip6Address:
        """
        Get the network address of an address under this mask:
        every host bit (mask=0) cleared, every network bit
        unchanged, so '(a & m) == (b & m)' is the same-subnet
        test. A non-address or cross-version operand returns
        'NotImplemented' so Python falls back to the reflected
        operand and ultimately raises TypeError if unsupported.
        """

        if isinstance(other, Ip4Address) and self.version == other.version:
            return Ip4Address(int(other) & self._mask)

        if isinstance(other, Ip6Address) and self.version == other.version:
            return Ip6Address(int(other) & self._mask)

        return NotImplemented

    def __rand__(self, other: object, /) -> Ip4Address | Ip6Address:
        """
        Get the network address of an address under this mask
        (reflected operand form; bitwise AND is commutative).
        """

        return self.__and__(other)

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Compare the IP mask with another object.
        """

        return other is self or (isinstance(other, type(self)) and self._mask == other._mask)

    @override
    def __hash__(self) -> int:
        """
        Get the IP mask hash value.
        """

        return hash((type(self), self._mask))

    @staticmethod
    def _is_contiguous_mask(value: int, bits: int, /) -> bool:
        """
        Check that a candidate mask value is made of consecutive
        high-order one bits (validated before assignment, so an
        invalid candidate never reaches '_mask').
        """

        inverted = (~value) & ((1 << bits) - 1)
        return inverted & (inverted + 1) == 0
