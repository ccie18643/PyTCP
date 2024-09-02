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

pytcp/lib/net_addr/ip_mask.py

ver 3.0.2
"""


from __future__ import annotations

from abc import ABC, abstractmethod


class IpMask(ABC):
    """
    IP mask support base class.
    """

    _mask: int
    _version: int

    def __len__(self) -> int:
        """
        Get the IP mask bit-length.
        """

        return f"{self._mask:b}".count("1")

    def __str__(self) -> str:
        """
        Get the IP mask log string.
        """

        return f"/{len(self)}"

    @abstractmethod
    def __repr__(self) -> str:
        """
        Get the IP mask string representation.
        """

        raise NotImplementedError

    @abstractmethod
    def __bytes__(self) -> bytes:
        """
        Get the IP mask as bytes.
        """

    def __int__(self) -> int:
        """
        Get the IP mask as integer.
        """

        return self._mask

    def __eq__(self, other: object) -> bool:
        """
        Compare the IP mask with another object.
        """

        return repr(self) == repr(other)

    def __hash__(self) -> int:
        """
        Get the IP mask hash.
        """

        return hash(repr(self))

    def _validate_bits(self, /, bytes_len: int) -> bool:
        """
        Validate that mask is made of consecutive bits.
        """

        bit_mask = f"{self._mask:0{bytes_len}b}"

        try:
            return not bit_mask[bit_mask.index("0") :].count("1")

        except ValueError:
            return True

    @property
    def version(self) -> int:
        """
        Get the IP mask version.
        """

        return self._version

    @property
    def is_ip6(self) -> bool:
        """
        Check if the IP mask version is 6.
        """

        return self._version == 6

    @property
    def is_ip4(self) -> bool:
        """
        Check if the IP mask version is 4.
        """

        return self._version == 4
