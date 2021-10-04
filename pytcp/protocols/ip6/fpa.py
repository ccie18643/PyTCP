#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# protocols/ip6/fpa.py - Fast Packet Assembler support class for IPv6 protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING, Union

import config
from lib.ip6_address import Ip6Address
from protocols.ether.ps import ETHER_TYPE_IP6
from protocols.ip6.ps import (
    IP6_HEADER_LEN,
    IP6_NEXT_HEADER_EXT_FRAG,
    IP6_NEXT_HEADER_ICMP6,
    IP6_NEXT_HEADER_RAW,
    IP6_NEXT_HEADER_TABLE,
    IP6_NEXT_HEADER_TCP,
    IP6_NEXT_HEADER_UDP,
)

if TYPE_CHECKING:
    from lib.tracker import Tracker
    from protocols.icmp6.fpa import Icmp6Assembler
    from protocols.ip6_ext_frag.fpa import Ip6ExtFragAssembler
    from protocols.raw.fpa import RawAssembler
    from protocols.tcp.fpa import TcpAssembler
    from protocols.udp.fpa import UdpAssembler


class Ip6Assembler:
    """IPv6 packet assembler support class"""

    ether_type = ETHER_TYPE_IP6

    def __init__(
        self,
        carried_packet: Union[Ip6ExtFragAssembler, Icmp6Assembler, TcpAssembler, UdpAssembler, RawAssembler],
        src: Ip6Address,
        dst: Ip6Address,
        hop: int = config.IP6_DEFAULT_HOP,
        dscp: int = 0,
        ecn: int = 0,
        flow: int = 0,
    ) -> None:
        """Class constructor"""

        assert carried_packet.ip6_next in {
            IP6_NEXT_HEADER_ICMP6,
            IP6_NEXT_HEADER_UDP,
            IP6_NEXT_HEADER_TCP,
            IP6_NEXT_HEADER_EXT_FRAG,
            IP6_NEXT_HEADER_RAW,
        }

        self._carried_packet: Union[Ip6ExtFragAssembler, Icmp6Assembler, TcpAssembler, UdpAssembler, RawAssembler] = carried_packet
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
        """Length of the packet"""

        return IP6_HEADER_LEN + len(self._carried_packet)

    def __str__(self) -> str:
        """Packet log string"""

        return (
            f"IPv6 {self._src} > {self._dst}, next {self._next} ({IP6_NEXT_HEADER_TABLE.get(self._next, '???')}), flow {self._flow}"
            + f", dlen {self._dlen}, hop {self._hop}"
        )

    @property
    def tracker(self) -> Tracker:
        """Getter for _tracker"""

        return self._tracker

    @property
    def dst(self) -> Ip6Address:
        """Getter for _dst"""

        return self._dst

    @property
    def src(self) -> Ip6Address:
        """Getter for _src"""

        return self._src

    @property
    def dlen(self) -> int:
        """Getter for _dlen"""

        return self._dlen

    @property
    def next(self) -> int:
        """Getter for _next"""

        return self._next

    @property
    def pshdr_sum(self) -> int:
        """Returns IPv6 pseudo header that is used by TCP, UDP and ICMPv6 to compute their checksums"""

        pseudo_header = struct.pack("! 16s 16s L BBBB", bytes(self._src), bytes(self._dst), self._dlen, 0, 0, 0, self._next)
        return sum(struct.unpack("! 5Q", pseudo_header))

    def assemble(self, frame: memoryview) -> None:
        """Assemble packet into the raw form"""

        struct.pack_into(
            "! BBBB HBB 16s 16s",
            frame,
            0,
            self._ver << 4 | self._dscp >> 4,
            self._dscp << 6 | self._ecn << 4 | ((self._flow & 0b000011110000000000000000) >> 16),
            (self._flow & 0b000000001111111100000000) >> 8,
            self._flow & 0b000000000000000011111111,
            self._dlen,
            self._next,
            self._hop,
            bytes(self._src),
            bytes(self._dst),
        )

        self._carried_packet.assemble(frame[IP6_HEADER_LEN:], self.pshdr_sum)
