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
This module contains the ProtoEnum base classes.

net_proto/lib/proto_enum.py

ver 3.0.9
"""

from enum import Enum
from typing import Self, override

from net_addr import Buffer


class ProtoEnum(Enum):
    """
    Static enum used to represent protocol values.
    """

    def __int__(self) -> int:
        """
        Get the enum value as an integer.
        """

        return int(self.value)

    @override
    def __str__(self) -> str:
        """
        Get the enum value as a string.
        """

        return self.name.replace("_", " ").title()

    def __contains__(self, value: object, /) -> bool:
        """
        Check if the provided value is a known enum value.
        """

        return value in self.get_known_values()

    @classmethod
    def _register_unknown(cls, value: int, /) -> Self:
        """
        Build, cache and return an 'UNKNOWN_<value>' pseudo-member
        for an unrecognised wire codepoint, idempotently.
        Registering it in '_value2member_map_' makes every later
        'cls(value)' resolve to the same object (identity-stable)
        — the native stdlib-'enum' replacement for the former
        'aenum.extend_enum'.
        """

        cached = cls._value2member_map_.get(value)
        if isinstance(cached, cls):
            return cached

        member = object.__new__(cls)
        member._name_ = f"UNKNOWN_{value}"
        member._value_ = value
        cls._value2member_map_[value] = member

        return member

    @classmethod
    def from_int(cls, value: int, /) -> Self:
        """
        Resolve a wire codepoint to its enum member. A known value
        returns its canonical member; an unrecognised value is
        materialised as a cached 'UNKNOWN_<value>' member.

        Deliberately tolerant — unlike the strict 'cls(value)',
        which still raises for an unknown value (a contract several
        parsers rely on to reject invalid codes). This mirrors the
        former aenum behaviour exactly: only 'from_int' extends.
        'ValueError' is the unknown-value case on a member-bearing
        enum; 'TypeError' is the stdlib refusing 'cls(value)' on a
        member-less enum (the abstract code bases, e.g.
        'Icmp6Code', are declared empty — aenum allowed this).
        """

        try:
            return cls(value)
        except ValueError, TypeError:
            return cls._register_unknown(value)

    @classmethod
    def _from_bytes(cls, data: Buffer, /, size: int) -> Self:
        """
        Extract the enum value from the provided bytes.
        """

        return cls.from_int(int.from_bytes(data[:size]))

    @classmethod
    def get_known_values(cls) -> list[int]:
        """
        Get the list of known values.
        """

        return [int(value) for value in cls if not value.is_unknown]

    @property
    def is_unknown(self) -> bool:
        """
        Check if this enum member represents an unknown (dynamically added) value.
        """

        return self.name.startswith("UNKNOWN_")


class ProtoEnumByte(ProtoEnum):
    """
    Static enum used to represent the protocol values stored in 8 bits.
    """

    def __bytes__(self) -> bytes:
        """
        Get the enum value as bytes.
        """

        return int(self).to_bytes(1)

    @classmethod
    def from_bytes(cls, data: Buffer, /) -> Self:
        """
        Extract the enum value from the provided bytes.
        """

        return cls._from_bytes(data, size=1)


class ProtoEnumWord(ProtoEnum):
    """
    Static enum used to represent the protocol values stored in 16 bits.
    """

    def __bytes__(self) -> bytes:
        """
        Get the enum value as bytes.
        """

        return int(self).to_bytes(2)

    @classmethod
    def from_bytes(cls, data: Buffer, /) -> Self:
        """
        Extract the enum value from the provided bytes.
        """

        return cls._from_bytes(data, size=2)
