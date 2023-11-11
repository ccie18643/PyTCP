#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
Module contains the StaticEnum and ExtendableEnum classes.

pytcp/lib/enum.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from aenum import extend_enum  # type: ignore

if TYPE_CHECKING:
    from enum import Enum
else:
    from aenum import Enum

from typing import Self


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

        match self.name:
            case "IP4":
                return "IPv4"
            case "IP6":
                return "IPv6"
            case "RAW":
                return "Raw Data"
            case "ARP":
                return "ARP"
            case _:
                return self.name.capitalize()

    def __contains__(self, value: object) -> bool:
        """
        Check if the provided value is a valid core enum value.
        """

        return value in self.get_core_values()

    @staticmethod
    def _extract(frame: bytes) -> int:
        """
        Extract the enum value from the provided frame.
        """

        raise NotImplementedError

    @classmethod
    def from_frame(cls, /, frame: bytes) -> Self:
        """
        Create the enum object from the provided frame.
        """

        if (value := cls._extract(frame)) not in cls:
            extend_enum(cls, f"UNKNOWN_{value}", value)

        return cls(value)

    @classmethod
    def get_core_values(cls) -> list[int]:
        """
        Get the list of core values.
        """

        return [int(value) for value in cls if value.is_unknown is False]

    @property
    def is_unknown(self) -> bool:
        """
        Check if the provided value is unknown.
        """

        return self.name.startswith("UNKNOWN_")
