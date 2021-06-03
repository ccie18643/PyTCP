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
# ip4/fpa.py - Fast Packet Assembler support class for IPv4 protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING, Optional, Union

import config
import ether.ps
import ip4.ps
from lib.ip4_address import Ip4Address
from misc.ip_helper import inet_cksum
from misc.tracker import Tracker

if TYPE_CHECKING:
    from icmp4.fpa import Icmp4Assembler
    from tcp.fpa import TcpAssembler
    from udp.fpa import UdpAssembler


class Ip4Assembler:
    """IPv4 packet assembler support class"""

    ether_type = ether.ps.ETHER_TYPE_IP4

    def __init__(
        self,
        carried_packet: Union[Icmp4Assembler, TcpAssembler, UdpAssembler],
        src: Ip4Address,
        dst: Ip4Address,
        ttl: int = config.ip4_default_ttl,
        dscp: int = 0,
        ecn: int = 0,
        id: int = 0,
        flag_df: bool = False,
        options: Optional[list] = None,
    ) -> None:
        """Class constructor"""

        assert carried_packet.ip4_proto in {ip4.ps.IP4_PROTO_ICMP4, ip4.ps.IP4_PROTO_UDP, ip4.ps.IP4_PROTO_TCP}

        self._carried_packet = carried_packet
        self.tracker = self._carried_packet.tracker
        self.ver = 4
        self.dscp = dscp
        self.ecn = ecn
        self.id = id
        self.flag_df = flag_df
        self.flag_mf = False
        self.offset = 0
        self.ttl = ttl
        self.src = Ip4Address(src)
        self.dst = Ip4Address(dst)
        self.options = [] if options is None else options
        self.hlen = ip4.ps.IP4_HEADER_LEN + len(self.raw_options)
        self.plen = len(self)
        self.proto = self._carried_packet.ip4_proto

    def __len__(self) -> int:
        """Length of the packet"""

        return ip4.ps.IP4_HEADER_LEN + sum([len(_) for _ in self.options]) + len(self._carried_packet)

    def __str__(self) -> str:
        """Packet log string"""

        return (
            f"IPv4 {self.src} > {self.dst}, proto {self.proto} ({ip4.ps.IP4_PROTO_TABLE.get(self.proto, '???')}), id {self.id}"
            + f"{', DF' if self.flag_df else ''}{', MF' if self.flag_mf else ''}, offset {self.offset}, plen {self.plen}"
            + f", ttl {self.ttl}"
        )

    @property
    def raw_options(self) -> bytes:
        """Packet options in raw format"""

        raw_options = b""

        for option in self.options:
            raw_options += option.raw_option

        return raw_options

    @property
    def dlen(self) -> int:
        """Calculate data length"""

        return self.plen - self.hlen

    @property
    def pshdr_sum(self) -> int:
        """Create IPv4 pseudo header used by TCP and UDP to compute their checksums"""

        pseudo_header = struct.pack("! 4s 4s BBH", bytes(self.src), bytes(self.dst), 0, self.proto, self.plen - self.hlen)
        return sum(struct.unpack("! 3L", pseudo_header))

    def assemble(self, frame: bytearray, hptr: int) -> None:
        """Assemble packet into the raw form"""

        struct.pack_into(
            f"! BBH HH BBH 4s 4s {len(self.raw_options)}s",
            frame,
            hptr,
            self.ver << 4 | self.hlen >> 2,
            self.dscp << 2 | self.ecn,
            self.plen,
            self.id,
            self.flag_df << 14 | self.flag_mf << 13 | self.offset >> 3,
            self.ttl,
            self.proto,
            0,
            bytes(self.src),
            bytes(self.dst),
            self.raw_options,
        )

        struct.pack_into("! H", frame, hptr + 10, inet_cksum(frame, hptr, self.hlen))

        self._carried_packet.assemble(frame, hptr + self.hlen, self.pshdr_sum)


class FragAssembler:
    """IPv4 packet fragment assembler support class"""

    ether_type = ether.ps.ETHER_TYPE_IP4

    def __init__(
        self,
        data: bytes,
        proto: int,
        src: Ip4Address,
        dst: Ip4Address,
        ttl: int = config.ip4_default_ttl,
        dscp: int = 0,
        ecn: int = 0,
        id: int = 0,
        flag_mf: bool = False,
        offset: int = 0,
        options: Optional[list] = None,
    ):
        """Class constructor"""

        assert proto in {ip4.ps.IP4_PROTO_ICMP4, ip4.ps.IP4_PROTO_UDP, ip4.ps.IP4_PROTO_TCP}

        self.tracker = Tracker("TX")
        self.ver = 4
        self.dscp = dscp
        self.ecn = ecn
        self.id = id
        self.flag_df = False
        self.flag_mf = flag_mf
        self.offset = offset
        self.ttl = ttl
        self.src = Ip4Address(src)
        self.dst = Ip4Address(dst)
        self.options = [] if options is None else options
        self.data = data
        self.proto = proto
        self.hlen = ip4.ps.IP4_HEADER_LEN + len(self.raw_options)
        self.plen = len(self)

    def __len__(self):
        """Length of the packet"""

        return ip4.ps.IP4_HEADER_LEN + sum([len(_) for _ in self.options]) + len(self.data)

    from ip4.ps import __str__

    @property
    def raw_options(self) -> bytes:
        """Packet options in raw format"""

        raw_options = b""

        for option in self.options:
            raw_options += option.raw_option

        return raw_options

    def assemble(self, frame: bytearray, hptr: int) -> None:
        """Assemble packet into the raw form"""

        struct.pack_into(
            f"! BBH HH BBH 4s 4s {len(self.raw_options)}s {len(self.data)}s",
            frame,
            hptr,
            self.ver << 4 | self.hlen >> 2,
            self.dscp << 2 | self.ecn,
            self.plen,
            self.id,
            self.flag_df << 14 | self.flag_mf << 13 | self.offset >> 3,
            self.ttl,
            self.proto,
            0,
            bytes(self.src),
            bytes(self.dst),
            self.raw_options,
            self.data,
        )

        struct.pack_into("! H", frame, hptr + 10, inet_cksum(frame, hptr, self.hlen))


#
#   IPv4 options
#


# IPv4 option - End of Ip4Option Linst


class Ip4OptEol(ip4.ps.Ip4OptEol):
    """IP option - End of Ip4Option List"""

    @property
    def raw_option(self) -> bytes:
        """Get option in raw form"""

        return struct.pack("!B", ip4.ps.IP4_OPT_EOL)


# IPv4 option - No Operation (1)


class Ip4OptNop(ip4.ps.Ip4OptNop):
    """IP option - No Operation"""

    @property
    def raw_option(self) -> bytes:
        """Get option in raw form"""

        return struct.pack("!B", ip4.ps.IP4_OPT_NOP)
