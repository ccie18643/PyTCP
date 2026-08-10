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
This module contains the IPv6 protocol base class.

net_proto/protocols/ip6/ip6__base.py

ver 3.0.10
"""

import struct
from typing import override

from net_addr import Buffer
from net_proto.lib.proto import Proto
from net_proto.protocols.icmp6.icmp6__assembler import Icmp6Assembler
from net_proto.protocols.ip6.ip6__header import Ip6Header, Ip6HeaderProperties
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__assembler import (
    Ip6DestOptsAssembler,
)
from net_proto.protocols.ip6_frag.ip6_frag__assembler import Ip6FragAssembler
from net_proto.protocols.ip6_hbh.ip6_hbh__assembler import Ip6HbhAssembler
from net_proto.protocols.ip6_routing.ip6_routing__assembler import (
    Ip6RoutingAssembler,
)
from net_proto.protocols.raw.raw__assembler import RawAssembler
from net_proto.protocols.tcp.tcp__assembler import TcpAssembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler

type Ip6Payload = (
    Ip6HbhAssembler
    | Ip6RoutingAssembler
    | Ip6FragAssembler
    | Ip6DestOptsAssembler
    | Icmp6Assembler
    | TcpAssembler
    | UdpAssembler
    | RawAssembler
)


class Ip6[P: (Ip6Payload, Buffer)](Proto, Ip6HeaderProperties):
    """
    The IPv6 protocol base.
    """

    _header: Ip6Header
    _payload: P

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

        return f"{type(self).__name__}(header={self._header!r}, payload={self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 packet as a memoryview.
        """

        if isinstance(
            self._payload,
            (TcpAssembler, UdpAssembler, Icmp6Assembler, RawAssembler),
        ):
            self._payload.pshdr_sum = self.pshdr_sum

        buffer = bytearray(self._header)
        buffer += bytearray(self._payload)

        return memoryview(buffer)

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
    def payload(self) -> P:
        """
        Get the IPv6 packet '_payload' attribute.
        """

        return self._payload

    @property
    def payload_len(self) -> int:
        """
        Get the length of the IPv6 packet '_payload' attribute.
        """

        return len(self._payload)
