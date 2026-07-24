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
This module contains the base classes for all protocol option classes.

net_proto/lib/proto_option.py

ver 3.0.8
"""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.proto_enum import ProtoEnumByte
from net_proto.lib.proto_struct import ProtoStruct


class ProtoOptionType(ProtoEnumByte):
    """
    Static enum used to represent protocol option types.
    """


@dataclass(frozen=True, kw_only=True, slots=True)
class ProtoOption(ProtoStruct):
    """
    Base class for all protocol option classes.
    """

    type: ProtoOptionType
    len: int

    @override
    def __len__(self) -> int:
        """
        Get the option length.
        """

        return self.len


class ProtoOptions(ABC):
    """
    Base class for all protocol options classes.
    """

    _options: list[ProtoOption]

    def __init__(self, *options: ProtoOption) -> None:
        """
        Initialize the options.
        """

        self._options = list(options)

    def __len__(self) -> int:
        """
        Get the options length.
        """

        return sum(len(option) for option in self._options)

    @override
    def __str__(self) -> str:
        """
        Get the options log string.
        """

        return ", ".join(str(option) for option in self._options)

    @override
    def __repr__(self) -> str:
        """
        Get the options representation string.
        """

        return f"{type(self).__name__}(options={self._options!r})"

    def __buffer__(self, _: int) -> memoryview:
        """
        Get the options as a memoryview.
        """

        buffer = bytearray()

        for option in self._options:
            buffer += bytearray(option)

        return memoryview(buffer)

    def __bool__(self) -> bool:
        """
        Check if the options are present.
        """

        return bool(self._options)

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Check if the options are equal.
        """

        if not isinstance(other, ProtoOptions):
            return NotImplemented
        return type(self) is type(other) and self._options == other._options

    def __contains__(self, option: object, /) -> bool:
        """
        Check if the options contain the provided option.
        """

        return option in self._options

    def __iter__(self) -> Iterator[ProtoOption]:
        """
        Get the options iterator.
        """

        return iter(self._options)

    def __getitem__(self, index: int, /) -> ProtoOption:
        """
        Get the option by index.
        """

        return self._options[index]

    def index(self, option: ProtoOption, /) -> int:
        """
        Get the index of the provided option.
        """

        return self._options.index(option)

    @classmethod
    @abstractmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Extract the options from the provided buffer.
        """

        raise NotImplementedError
