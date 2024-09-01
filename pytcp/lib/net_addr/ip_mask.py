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
Module contains IP mask base class.

pytcp/lib/ip_mask.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING


class IpMask(ABC):
    """
    IP network support base class.
    """

    @abstractmethod
    def __init__(
        self,
        address: int,
    ) -> None:
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

    def __eq__(
        self,
        other: object,
    ) -> bool:
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
