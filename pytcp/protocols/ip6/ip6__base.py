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
This module contains the IPv6 packet base class.

pytcp/protocols/ip6/ip6__base.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING, TypeAlias, override

from pytcp.lib.proto import Proto
from pytcp.protocols.icmp6.icmp6__assembler import Icmp6Assembler
from pytcp.protocols.ip6.ip6__header import Ip6HeaderProperties
from pytcp.protocols.tcp.tcp__assembler import TcpAssembler
from pytcp.protocols.udp.udp__assembler import UdpAssembler
from pytcp.protocols.raw.raw__assembler import RawAssembler

if TYPE_CHECKING:
    from pytcp.protocols.ip6.ip6__header import Ip6Header
    from pytcp.protocols.ip6_frag.ip6_frag__assembler import Ip6FragAssembler

    Ip6Payload: TypeAlias = (
        Ip6FragAssembler
        | Icmp6Assembler
        | TcpAssembler
        | UdpAssembler
        | RawAssembler
    )


class Ip6(Proto, Ip6HeaderProperties):
    """
    The IPv6 protocol base.
    """

    _header: Ip6Header
    _payload: Ip6Payload | memoryview

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 packet length.
        """

        return len(self._header) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 packet log string.
        """

        return (
            f"IPv6 {self._header.src} > {self._header.dst}, "
            f"next {self._header.next}, flow {self._header.flow}, "
            f"hop {self._header.hop}, len {len(self._header) + self._header.dlen} "
            f"({len(self._header)}+{self._header.dlen})"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the IPv6 packet representation string.
        """

        return (
            f"{self.__class__.__name__}(header={self._header!r}, "
            f"payload={self._payload!r})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the IPv6 packet as bytes.
        """

        if isinstance(
            self._payload,
            (TcpAssembler, UdpAssembler, Icmp6Assembler, RawAssembler),
        ):
            self._payload.pshdr_sum = self.pshdr_sum

        return bytes(self._header) + bytes(self._payload)

    @property
    def pshdr_sum(self) -> int:
        """
        Get the IPv6 pseudo header sum used by TCP, UDP and ICMPv6
        protocols to compute their packet checksums.
        """

        pseudo_header = struct.pack(
            "! 16s 16s L BBBB",
            bytes(self._header.src),
            bytes(self._header.dst),
            self._header.dlen,
            0,
            0,
            0,
            int(self._header.next),
        )
        return sum(struct.unpack("! 5Q", pseudo_header))

    @property
    def header(self) -> Ip6Header:
        """
        Get the IPv6 packet '_header' attribute.
        """

        return self._header

    @property
    def payload_len(self) -> int:
        """
        Get the length of the IPv6 packet '_payload' attribute.
        """

        return len(self._payload)
