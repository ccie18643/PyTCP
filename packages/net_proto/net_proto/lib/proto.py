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
This module contains the base class for all protocol classes.

net_proto/lib/proto.py

ver 3.0.8
"""

from abc import ABC, abstractmethod
from typing import override


class Proto(ABC):
    """
    Base class for all protocol classes.
    """

    @abstractmethod
    def __len__(self) -> int:
        """
        Get the packet length.
        """

        raise NotImplementedError

    @override
    @abstractmethod
    def __str__(self) -> str:
        """
        Get the packet log string.
        """

        raise NotImplementedError

    @override
    @abstractmethod
    def __repr__(self) -> str:
        """
        Get the packet representation string.
        """

        raise NotImplementedError

    @abstractmethod
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the packet as a memoryview.
        """

        raise NotImplementedError

    @override
    def __eq__(self, other: object) -> bool:
        """
        Compare two packets.
        """

        if not isinstance(other, Proto):
            return NotImplemented
        return self is other or (type(self) is type(other) and repr(self) == repr(other))

    @override
    def __hash__(self) -> int:
        """
        Get the packet hash.
        """

        return hash(repr(self))
