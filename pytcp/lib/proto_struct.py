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
Module contains base class for protocol header.

pytcp/lib/proto_struct.py

ver 3.0.0
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ProtoStruct(ABC):
    """
    The packet elements structure base.
    """

    @abstractmethod
    def __post_init__(self) -> None:
        """
        Validate the lacket header fields.
        """

        raise NotImplementedError

    @abstractmethod
    def __len__(self) -> int:
        """
        Get the packet header length.
        """

        raise NotImplementedError

    @abstractmethod
    def __bytes__(self) -> bytes:
        """
        Get the packet header as bytes.
        """

        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def from_bytes(_bytes: bytes) -> ProtoStruct:
        """
        Create an ICMPv4 message from bytes.
        """

        raise NotImplementedError
