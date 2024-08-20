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
This module contains the IPv6 Ext Frag base class.

pytcp/protocols/ip6_ext_frag/ip6_ext_frag__base.py

ver 3.0.0
"""


from __future__ import annotations

from typing import TYPE_CHECKING, TypeAlias, override

from pytcp.lib.proto import Proto
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__header import (
    Ip6ExtFragHeader,
    Ip6ExtFragHeaderProperties,
)

if TYPE_CHECKING:
    from pytcp.protocols.icmp6.icmp6__assembler import Icmp6Assembler
    from pytcp.protocols.raw.raw__assembler import RawAssembler
    from pytcp.protocols.tcp.tcp__assembler import TcpAssembler
    from pytcp.protocols.udp.udp__assembler import UdpAssembler

    Ip6ExtFragPayload: TypeAlias = (
        Icmp6Assembler | TcpAssembler | UdpAssembler | RawAssembler
    )


class Ip6ExtFrag(Proto, Ip6ExtFragHeaderProperties):
    """
    The IPv6 Ext Frag base.
    """

    _header: Ip6ExtFragHeader
    _payload: memoryview | bytes

    pshdr_sum: int = 0

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 Ext Frag packet length.
        """

        return len(self._header) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 Ext Frag packet log string.
        """

        return (
            f"IPv6_FRAG id {self._header.id}{', MF' if self._header.flag_mf else ''}, "
            f"offset {self._header.offset}, next {self._header.next}, "
            f"len {len(self._header) + len(self._payload)} "
            f"({len(self._header)}+{len(self._payload)})"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the IPv6 Ext Frag packet representation string.
        """

        return (
            f"{self.__class__.__name__}(header={self._header!r}, "
            f"payload={self._payload!r})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the IPv6 packet packet as bytes.
        """

        return bytes(self._header) + self._payload

    @property
    def header(self) -> Ip6ExtFragHeader:
        """
        Get the IPv6 Ext Frag packet '_header' attribute.
        """

        return self._header

    @property
    def payload(self) -> bytes:
        """
        Get the IPv6 Ext Frag packet '_payload' attribute.
        """

        return self._payload
