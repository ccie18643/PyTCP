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

# pylint: disable = too-many-instance-attributes

"""
Module contains Fast Packet Assembler support class for the IPv6 protocol.

pytcp/protocols/ip6/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip6_address import Ip6Address
from pytcp.protocols.ether.ps import ETHER_TYPE_IP6
from pytcp.protocols.ip6.ps import (
    IP6_HEADER_LEN,
    IP6_NEXT_EXT_FRAG,
    IP6_NEXT_ICMP6,
    IP6_NEXT_RAW,
    IP6_NEXT_TABLE,
    IP6_NEXT_TCP,
    IP6_NEXT_UDP,
)
from pytcp.protocols.raw.fpa import RawAssembler

if TYPE_CHECKING:
    from pytcp.lib.tracker import Tracker
    from pytcp.protocols.icmp6.fpa import Icmp6Assembler
    from pytcp.protocols.ip6_ext_frag.fpa import Ip6ExtFragAssembler
    from pytcp.protocols.tcp.fpa import TcpAssembler
    from pytcp.protocols.udp.fpa import UdpAssembler


class Ip6Assembler:
    """
    IPv6 packet assembler support class.
    """

    ether_type = ETHER_TYPE_IP6

    def __init__(
        self,
        *,
        src: Ip6Address = Ip6Address(0),
        dst: Ip6Address = Ip6Address(0),
        hop: int = config.IP6_DEFAULT_HOP,
        dscp: int = 0,
        ecn: int = 0,
        flow: int = 0,
        carried_packet: (
            Ip6ExtFragAssembler
            | Icmp6Assembler
            | TcpAssembler
            | UdpAssembler
            | RawAssembler
        ) = RawAssembler(),
    ) -> None:
        """
        Class constructor.
        """

        assert 0 <= hop <= 0xFF
        assert 0 <= dscp <= 0x3F
        assert 0 <= ecn <= 0x03
        assert 0 <= flow <= 0xFFFFFF
        assert carried_packet.ip6_next in {
            IP6_NEXT_ICMP6,
            IP6_NEXT_UDP,
            IP6_NEXT_TCP,
            IP6_NEXT_EXT_FRAG,
            IP6_NEXT_RAW,
        }

        self._carried_packet: (
            Ip6ExtFragAssembler
            | Icmp6Assembler
            | TcpAssembler
            | UdpAssembler
            | RawAssembler
        ) = carried_packet
        self._tracker: Tracker = self._carried_packet.tracker
        self._ver: int = 6
        self._dscp: int = dscp
        self._ecn: int = ecn
        self._flow: int = flow
        self._hop: int = hop
        self._src: Ip6Address = src
        self._dst: Ip6Address = dst
        self._next: int = self._carried_packet.ip6_next
        self._dlen: int = len(carried_packet)

    def __len__(self) -> int:
        """
        Length of the packet.
        """

        return IP6_HEADER_LEN + len(self._carried_packet)

    def __str__(self) -> str:
        """
        Packet log string.
        """

        return (
            f"IPv6 {self._src} > {self._dst}, next {self._next} "
            f"({IP6_NEXT_TABLE.get(self._next, '???')}), flow {self._flow}, "
            f"dlen {self._dlen}, hop {self._hop}"
        )

    @property
    def tracker(self) -> Tracker:
        """
        Getter for the '_tracker' attribute."""
        return self._tracker

    @property
    def dst(self) -> Ip6Address:
        """
        Getter for the '_dst' attribute.
        """
        return self._dst

    @property
    def src(self) -> Ip6Address:
        """
        Getter for the '_src' attribute.
        """
        return self._src

    @property
    def dlen(self) -> int:
        """
        Getter for the '_dlen' attribute.
        """
        return self._dlen

    @property
    def next(self) -> int:
        """
        Getter for the '_next' attribute.
        """
        return self._next

    @property
    def pshdr_sum(self) -> int:
        """
        Returns IPv6 pseudo header that is used by TCP, UDP and ICMPv6
        to compute their checksums.
        """
        pseudo_header = struct.pack(
            "! 16s 16s L BBBB",
            bytes(self._src),
            bytes(self._dst),
            self._dlen,
            0,
            0,
            0,
            self._next,
        )
        return sum(struct.unpack("! 5Q", pseudo_header))

    def assemble(self, frame: memoryview) -> None:
        """
        Assemble packet into the raw form.
        """
        struct.pack_into(
            "! BBBB HBB 16s 16s",
            frame,
            0,
            self._ver << 4 | self._dscp >> 4,
            self._dscp & 0b00000011 << 6
            | self._ecn << 4
            | ((self._flow & 0b000011110000000000000000) >> 16),
            (self._flow & 0b000000001111111100000000) >> 8,
            self._flow & 0b000000000000000011111111,
            self._dlen,
            self._next,
            self._hop,
            bytes(self._src),
            bytes(self._dst),
        )
        self._carried_packet.assemble(frame[IP6_HEADER_LEN:], self.pshdr_sum)
