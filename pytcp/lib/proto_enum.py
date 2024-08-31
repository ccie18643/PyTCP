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

# pylint: disable=redefined-builtin

"""
Module contains the ProtoEnum class.

pytcp/lib/enum.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING, Self

from aenum import extend_enum  # type: ignore

if TYPE_CHECKING:
    from enum import Enum
else:
    from aenum import Enum


class ProtoEnum(Enum):
    """
    Static enum used to represent protocol values.
    """

    def __int__(self) -> int:
        """
        Get the enum value as an integer.
        """

        return int(self.value)

    def __str__(self) -> str:
        """
        Get the enum value as a string.
        """

        return self.name.replace("_", " ").title()

    def __contains__(
        self,
        value: object,
    ) -> bool:
        """
        Check if the provided value is a valid core enum value.
        """

        return value in self.get_known_values()

    @classmethod
    def from_int(cls, /, value: int) -> Self:
        """
        Extract the enum value from the provided int.
        """

        if value not in cls:
            extend_enum(cls, f"UNKNOWN_{value}", value)

        return cls(value)

    @classmethod
    def _from_bytes(cls, *, bytes: bytes, size: int) -> Self:
        """
        Extract the enum value from the provided bytes.
        """

        return cls.from_int((int.from_bytes(bytes[:size])))

    @classmethod
    def get_known_values(cls) -> list[int]:
        """
        Get the list of known values.
        """

        return [int(value) for value in cls if value.is_unknown is False]

    @property
    def is_unknown(self) -> bool:
        """
        Check if the provided value is unknown.
        """

        return self.name.startswith("UNKNOWN_")


class ProtoEnumByte(ProtoEnum):
    """
    Static enum used to represent protocol values stored in 8 bits.
    """

    def __bytes__(self) -> bytes:
        """
        Get the enum value as bytes.
        """

        return int(self).to_bytes(1)

    @classmethod
    def from_bytes(cls, /, bytes: bytes) -> Self:
        """
        Extract the enum value from the provided bytes.
        """

        return cls._from_bytes(bytes=bytes, size=1)


class ProtoEnumWord(ProtoEnum):
    """
    Static enum used to represent protocol values stored in 16 bits.
    """

    def __bytes__(self) -> bytes:
        """
        Get the enum value as bytes.
        """

        return int(self).to_bytes(2)

    @classmethod
    def from_bytes(cls, /, bytes: bytes) -> Self:
        """
        Extract the enum value from the provided bytes.
        """

        return cls._from_bytes(bytes=bytes, size=2)
