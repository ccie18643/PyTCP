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
This module contains the base class for all NetAddr objects.

net_addr/net_addr.py

ver 3.0.4
"""


from abc import ABC, abstractmethod


class Base(ABC):
    """
    NetAddr base class.
    """

    __slots__ = ()

    @abstractmethod
    def __str__(self) -> str:
        """
        Get the network object log string.
        """

        raise NotImplementedError

    def __repr__(self) -> str:
        """
        Get the network object representation string.
        """

        return f"{type(self).__name__}('{str(self)}')"

    @abstractmethod
    def __eq__(self, other: object, /) -> bool:
        """
        Check if two network objects are equal.
        """

        raise NotImplementedError

    def __hash__(self) -> int:
        """
        Get the network object hash value.
        """

        return hash(repr(self))
