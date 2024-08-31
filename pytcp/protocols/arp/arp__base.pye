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
This module contains the ARP protccol base class.

pytcp/protocols/arp/arp__base.py

ver 3.0.0
"""


from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp.lib.proto import Proto
from pytcp.protocols.arp.arp__header import ArpHeaderProperties

if TYPE_CHECKING:
    from pytcp.protocols.arp.arp__header import ArpHeader


class Arp(Proto, ArpHeaderProperties):
    """
    The ARP protocol base.
    """

    _header: ArpHeader

    @override
    def __len__(self) -> int:
        """
        Get the ARP packet length.
        """

        return len(self._header)

    @override
    def __str__(self) -> str:
        """
        Get the ARP packet log string.
        """

        return (
            f"ARP {self._header.oper} {self._header.spa} / {self._header.sha}"
            f" > {self._header.tpa} / {self._header.tha}"
            f", len {len(self._header)}"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the ARP packet representation string.
        """

        return f"{self.__class__.__name__}(header={self._header!r})"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ARP packet as bytes.
        """

        return bytes(self._header)

    @property
    def header(self) -> ArpHeader:
        """
        Get the ARP packet '_header' attribute.
        """

        return self._header
