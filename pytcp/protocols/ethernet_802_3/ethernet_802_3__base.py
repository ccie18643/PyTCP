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
This module contains the Ethernet 802.3 protocol base class.

pytcp/protocols/ethernet_802_3/ethernet_802_3__base.py

ver 3.0.0
"""


from __future__ import annotations

from typing import TYPE_CHECKING, TypeAlias, override

from pytcp.lib.proto import Proto
from pytcp.protocols.ethernet_802_3.ethernet_802_3__header import (
    EthernetHeader8023Properties,
)

if TYPE_CHECKING:
    from pytcp.protocols.ethernet_802_3.ethernet_802_3__header import (
        Ethernet8023Header,
    )
    from pytcp.protocols.raw.raw__assembler import RawAssembler

    Ethernet8023Payload: TypeAlias = RawAssembler


class Ethernet8023(Proto, EthernetHeader8023Properties):
    """
    The Ethernet 802.3 protocol base.
    """

    _header: Ethernet8023Header
    _payload: Ethernet8023Payload | memoryview

    @override
    def __len__(self) -> int:
        """
        Get the Ethernet 802.3 packet length.
        """

        return len(self._header) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the Ethernet 802.3 packet log string.
        """

        return (
            f"ETHER_802.3 {self._header.src} > {self._header.dst}, dlen {self._header.dlen}, "
            f"len {len(self)} ({len(self._header)}+{len(self) - len(self._header)})"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the Ethernet 802.3 packet representation string.
        """

        return f"{self.__class__.__name__}(header={self._header}, payload={self._payload!r})"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the Ethernet 802.3 packet as bytes.
        """

        return bytes(self._header) + bytes(self._payload)

    @property
    def header(self) -> Ethernet8023Header:
        """
        Get the Ethernet 802.3 packet's '_header' attribute.
        """

        return self._header
