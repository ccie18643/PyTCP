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
This module contains the base class for the protocol headers.

net_proto/lib/proto_struct.py

ver 3.0.8
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Self

from net_proto.lib.buffer import Buffer


@dataclass(frozen=True, kw_only=True, slots=True)
class ProtoStruct(ABC):
    """
    Base class for all protocol structures.
    """

    @abstractmethod
    def __post_init__(self) -> None:
        """
        Ensure integrity of the protocol structure fields.
        """

        raise NotImplementedError

    @abstractmethod
    def __len__(self) -> int:
        """
        Get the protocol structure length.
        """

        raise NotImplementedError

    @abstractmethod
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the protocol structure as a memoryview.
        """

        raise NotImplementedError

    @classmethod
    @abstractmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Create the protocol structure from the provided buffer.
        """

        raise NotImplementedError
