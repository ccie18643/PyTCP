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
This module contains the IPv4 protccol base class.

pytcp/protocols/ip4/ip4__base.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING, override

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.proto import Proto
from pytcp.protocols.ip4.ip4__header import Ip4HeaderProperties
from pytcp.protocols.ip4.options.ip4_options import Ip4OptionsProperties
from pytcp.protocols.raw.raw__assembler import RawAssembler
from pytcp.protocols.tcp.tcp__assembler import TcpAssembler
from pytcp.protocols.udp.udp__assembler import UdpAssembler

if TYPE_CHECKING:
    from pytcp.protocols.icmp4.icmp4__assembler import Icmp4Assembler
    from pytcp.protocols.ip4.ip4__header import Ip4Header
    from pytcp.protocols.ip4.options.ip4_options import Ip4Options

    type Ip4Payload = (
        Icmp4Assembler | TcpAssembler | UdpAssembler | RawAssembler
    )


class Ip4(Proto, Ip4HeaderProperties, Ip4OptionsProperties):
    """
    The IPv4 protocol base.
    """

    _header: Ip4Header
    _options: Ip4Options
    _payload: Ip4Payload | memoryview | bytes

    @override
    def __len__(self) -> int:
        """
        Get the IPv4 packet length.
        """

        return len(self._header) + len(self._options) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 packet log string.
        """

        return (
            f"IPv4 {self._header.src} > {self._header.dst}, "
            f"proto {self._header.proto}, id {self._header.id}"
            f"{', DF' if self._header.flag_df else ''}"
            f"{', MF' if self._header.flag_mf else ''}, "
            f"offset {self._header.offset}, ttl {self._header.ttl}, "
            f"len {self._header.plen} "
            f"({len(self._header)}+{len(self._options)}+{len(self._payload)})"
            f"{f', opts [{self._options}]' if self._options else ''}"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the IPv4 packet representation string.
        """

        return (
            f"{self.__class__.__name__}(header={self._header!r}, "
            f"options={self._options!r}, payload={self._payload!r})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the IPv4 packet as bytes.
        """

        header_and_options = bytearray(
            bytes(self._header) + bytes(self._options)
        )
        header_and_options[10:12] = inet_cksum(
            data=header_and_options
        ).to_bytes(2)

        if isinstance(
            self._payload, (TcpAssembler, UdpAssembler, RawAssembler)
        ):
            self._payload.pshdr_sum = self.pshdr_sum

        return bytes(header_and_options + bytes(self._payload))

    @property
    def pshdr_sum(self) -> int:
        """
        Get the IPv4 pseudo header sum used by TCP and UDP protocols
        to compute their packet checksums.
        """

        pseudo_header = struct.pack(
            "! 4s 4s BBH",
            bytes(self._header.src),
            bytes(self._header.dst),
            0,
            int(self._header.proto),
            len(self._payload),
        )

        return sum(struct.unpack("! 3L", pseudo_header))

    @property
    def header(self) -> Ip4Header:
        """
        Get the IPv4 packet '_header' attribute.
        """

        return self._header

    @property
    def options(self) -> Ip4Options:
        """
        Get the IPv4 packet '_options' attribute.
        """

        return self._options

    @property
    def payload_len(self) -> int:
        """
        Get the length of the IPv4 packet '_payload' attribute.
        """

        return len(self._payload)
