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
Module contains base class for all of the option classes.

pytcp/lib/proto_option.py

ver 3.0.3
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterable

from pytcp.lib.proto_enum import ProtoEnumByte
from pytcp.lib.proto_struct import ProtoStruct


class ProtoOptionType(ProtoEnumByte):
    """
    Static enum used to represent protocol option types.
    """


@dataclass(frozen=True, kw_only=True)
class ProtoOption(ProtoStruct):
    """
    Base class for all of the protocol option classes.
    """

    type: ProtoOptionType
    len: int

    def __len__(self) -> int:
        """
        Get the option length.
        """

        return self.len


class ProtoOptions(ABC):
    """
    Base class for all of the protocol options classes.
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

    def __str__(self) -> str:
        """
        Get the options log string.
        """

        return ", ".join(str(option) for option in self._options)

    def __repr__(self) -> str:
        """
        Get the options representation string.
        """

        return f"{self.__class__.__name__}(options={self._options!r})"

    def __bytes__(self) -> bytes:
        """
        Get the options as bytes.
        """

        return b"".join(bytes(option) for option in self._options)

    def __bool__(self) -> bool:
        """
        Check if the options are present.
        """

        return bool(self._options)

    def __eq__(self, other: object, /) -> bool:
        """
        Check if the options are equal.
        """

        return (
            isinstance(other, self.__class__)
            and self._options == other._options
        )

    def __contains__(self, option: ProtoOption, /) -> bool:
        """
        Check if the options contain the provided option.
        """

        return option in self._options

    def __iter__(self) -> Iterable[ProtoOption]:
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
        Get the option index.
        """

        return self._options.index(option)

    @staticmethod
    @abstractmethod
    def from_bytes(_bytes: bytes, /) -> ProtoOptions:
        """
        Extract the options from the provided bytes.
        """

        raise NotImplementedError
