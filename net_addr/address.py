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
This module contains network address base class.

net_addr/address.py

ver 3.0.4
"""


from abc import ABC, abstractmethod
from typing import Self, override

from net_addr.base import Base


class Address(Base, ABC):
    """
    Network address support base class.
    """

    __slots__ = ("_address",)

    _address: int

    def __int__(self) -> int:
        """
        Get the network address as integer.
        """

        return self._address

    @abstractmethod
    def __bytes__(self) -> bytes:
        """
        Get the network address bytes representation.
        """

        raise NotImplementedError

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Compare the network address with another object.
        """

        return (
            other is self
            or isinstance(other, type(self))
            and self._address == other._address
        )

    __hash__ = Base.__hash__

    @property
    def unspecified(self) -> Self:
        """
        Get the unspecified network address.
        """

        return type(self)()

    @property
    def is_unspecified(self) -> bool:
        """
        Check if the network address is unspecified.
        """

        return self._address == 0
