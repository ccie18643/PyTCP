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
This module contains the Ethernet II protccol base class.

pytcp/protocols/ethernet/ethernet__base.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING, TypeAlias, override

from pytcp.lib.proto import Proto
from pytcp.protocols.ethernet.ethernet__header import EthernetHeaderProperties

if TYPE_CHECKING:
    from pytcp.protocols.arp.arp__assembler import ArpAssembler
    from pytcp.protocols.ip4.ip4__assembler import (
        Ip4Assembler,
        Ip4FragAssembler,
    )
    from pytcp.protocols.ip6.ip6__assembler import Ip6Assembler
    from pytcp.protocols.raw.raw__assembler import RawAssembler

    from .ethernet__header import EthernetHeader

    EthernetPayload: TypeAlias = (
        ArpAssembler
        | Ip4Assembler
        | Ip4FragAssembler
        | Ip6Assembler
        | RawAssembler
    )


class Ethernet(Proto, EthernetHeaderProperties):
    """
    The Ethernet protocol base class.
    """

    _header: EthernetHeader
    _payload: EthernetPayload | memoryview

    @override
    def __len__(self) -> int:
        """
        Get the Ethernet packet length.
        """

        return len(self._header) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the Ethernet packet log string.
        """

        return (
            f"ETHER {self._header.src} > {self._header.dst}, type {self._header.type}, "
            f"len {len(self)} ({len(self._header)}+{len(self) - len(self._header)})"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the Ethernet packet representation string.
        """

        return f"{self.__class__.__name__}(header={self._header}, payload={self._payload!r})"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the Ethernet packet as bytes.
        """

        return bytes(self._header) + bytes(self._payload)

    @property
    def header(self) -> EthernetHeader:
        """
        Get the Ethernet packet '_header' attribute.
        """

        return self._header
