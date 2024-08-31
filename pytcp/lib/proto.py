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
Module contains the base class for all of the protocol classes.

pytcp/lib/proto.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC, abstractmethod


class Proto(ABC):
    """
    Base class for all of the protocol classes.
    """

    @abstractmethod
    def __len__(self) -> int:
        """
        Get the packet length.
        """

        raise NotImplementedError

    @abstractmethod
    def __str__(self) -> str:
        """
        Get the packet log string.
        """

        raise NotImplementedError

    @abstractmethod
    def __repr__(self) -> str:
        """
        Get the packet representation string.
        """

        raise NotImplementedError

    @abstractmethod
    def __bytes__(self) -> bytes:
        """
        Get the packet as bytes.
        """

        raise NotImplementedError

    def __eq__(self, other: object) -> bool:
        """
        Compare two packets.
        """

        return isinstance(other, self.__class__) and repr(self) == repr(other)

    def __hash__(self) -> int:
        """
        Get the packet hash.
        """

        return hash(repr(self))
