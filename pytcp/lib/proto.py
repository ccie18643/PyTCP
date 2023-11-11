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
Module contains the base class for all of the protocol classes.

pytcp/lib/protocol.py

ver 2.7
"""


from __future__ import annotations

from abc import ABC, abstractmethod

from pytcp.lib.tracker import Tracker


class Proto(ABC):
    """
    Base class for all of the protocol classes.
    """

    @abstractmethod
    def __init__(self) -> None:
        """
        Create protocol object.
        """

        raise NotImplementedError

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
        Get the packet in raw form.
        """

        raise NotImplementedError

    def __eq__(self, other: object) -> bool:
        """
        Compare two ARP packets.
        """

        return isinstance(other, Proto) and repr(self) == repr(other)

    def __hash__(self) -> int:
        """
        Get the packet hash.
        """

        return hash(repr(self))


class ProtoParser(Proto):
    """
    Base class for all of the protocol parser classes.
    """

    _frame: memoryview

    @abstractmethod
    def _validate_sanity(self) -> None:
        """
        Validate packet sanity.
        """

        raise NotImplementedError

    @abstractmethod
    def _parse(self) -> None:
        """
        Parse packet.
        """

        raise NotImplementedError

    @abstractmethod
    def _validate_integrity(self) -> None:
        """
        Validate packet integrity.
        """

        raise NotImplementedError

    @property
    def frame(self) -> memoryview:
        """
        Get the packet frame.
        """

        return self._frame


class ProtoAssembler(Proto):
    """
    Base class for all of the protocol assembler classes.
    """

    _tracker: Tracker

    @property
    def tracker(self) -> Tracker:
        """
        Get the '_tracker' property.
        """

        return self._tracker
