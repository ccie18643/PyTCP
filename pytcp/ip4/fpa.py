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
from lib.tracker import Tracker
from misc.ip_helper import inet_cksum

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
        options: Optional[list[Ip4OptNop | Ip4OptEol]] = None,
    ) -> None:
        """Class constructor"""

        assert carried_packet.ip4_proto in {ip4.ps.IP4_PROTO_ICMP4, ip4.ps.IP4_PROTO_UDP, ip4.ps.IP4_PROTO_TCP}

        self._carried_packet: Union[Icmp4Assembler, TcpAssembler, UdpAssembler] = carried_packet
        self._tracker: Tracker = self._carried_packet.tracker
        self._ver: int = 4
        self._dscp: int = dscp
        self._ecn: int = ecn
        self._id: int = id
        self._flag_df: bool = flag_df
        self._flag_mf: bool = False
        self._offset: int = 0
        self._ttl: int = ttl
        self._src: Ip4Address = src
        self._dst: Ip4Address = dst
        self._options: list[Ip4OptNop | Ip4OptEol] = [] if options is None else options
        self._hlen: int = ip4.ps.IP4_HEADER_LEN + len(self._raw_options)
        self._plen: int = len(self)
        self._proto: int = self._carried_packet.ip4_proto

    def __len__(self) -> int:
        """Length of the packet"""

        return ip4.ps.IP4_HEADER_LEN + sum([len(_) for _ in self._options]) + len(self._carried_packet)

    def __str__(self) -> str:
        """Packet log string"""

        return (
            f"IPv4 {self._src} > {self._dst}, proto {self._proto} ({ip4.ps.IP4_PROTO_TABLE.get(self._proto, '???')}), id {self._id}"
            + f"{', DF' if self._flag_df else ''}{', MF' if self._flag_mf else ''}, offset {self._offset}, plen {self._plen}"
            + f", ttl {self._ttl}"
        )

    @property
    def tracker(self) -> Tracker:
        """Getter for _tracker"""

        return self._tracker

    @property
    def dst(self) -> Ip4Address:
        """Getter for _dst"""

        return self._dst

    @property
    def src(self) -> Ip4Address:
        """Getter for _src"""

        return self._src

    @property
    def hlen(self) -> int:
        """Getter for _hlen"""

        return self._hlen

    @property
    def proto(self) -> int:
        """Getter for _proto"""

        return self._proto

    @property
    def dlen(self) -> int:
        """Calculate data length"""

        return self._plen - self._hlen

    @property
    def pshdr_sum(self) -> int:
        """Create IPv4 pseudo header used by TCP and UDP to compute their checksums"""

        pseudo_header = struct.pack("! 4s 4s BBH", bytes(self._src), bytes(self._dst), 0, self._proto, self._plen - self._hlen)
        return sum(struct.unpack("! 3L", pseudo_header))

    @property
    def _raw_options(self) -> bytes:
        """Packet options in raw format"""

        raw_options = b""

        for option in self._options:
            raw_options += option.raw_option

        return raw_options

    def assemble(self, frame: memoryview) -> None:
        """Assemble packet into the raw form"""

        struct.pack_into(
            f"! BBH HH BBH 4s 4s {len(self._raw_options)}s",
            frame,
            0,
            self._ver << 4 | self._hlen >> 2,
            self._dscp << 2 | self._ecn,
            self._plen,
            self._id,
            self._flag_df << 14 | self._flag_mf << 13 | self._offset >> 3,
            self._ttl,
            self._proto,
            0,
            bytes(self._src),
            bytes(self._dst),
            self._raw_options,
        )

        struct.pack_into("! H", frame, 10, inet_cksum(frame[: self._hlen]))

        self._carried_packet.assemble(frame[self._hlen :], self.pshdr_sum)


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
        options: Optional[list[Ip4OptNop | Ip4OptEol]] = None,
    ):
        """Class constructor"""

        assert proto in {ip4.ps.IP4_PROTO_ICMP4, ip4.ps.IP4_PROTO_UDP, ip4.ps.IP4_PROTO_TCP}

        self._tracker: Tracker = Tracker("TX")
        self._ver: int = 4
        self._dscp: int = dscp
        self._ecn: int = ecn
        self._id: int = id
        self._flag_df: bool = False
        self._flag_mf: bool = flag_mf
        self._offset: int = offset
        self._ttl: int = ttl
        self._src: Ip4Address = src
        self._dst: Ip4Address = dst
        self._options: list[Ip4OptNop | Ip4OptEol] = [] if options is None else options
        self._data: bytes = data
        self._proto: int = proto
        self._hlen: int = ip4.ps.IP4_HEADER_LEN + len(self._raw_options)
        self._plen: int = len(self)

    def __len__(self) -> int:
        """Length of the packet"""

        return ip4.ps.IP4_HEADER_LEN + sum([len(_) for _ in self._options]) + len(self._data)

    @property
    def tracker(self) -> Tracker:
        """Getter for _tracker"""

        return self._tracker

    @property
    def _raw_options(self) -> bytes:
        """Packet options in raw format"""

        raw_options = b""

        for option in self._options:
            raw_options += option.raw_option

        return raw_options

    def assemble(self, frame: memoryview) -> None:
        """Assemble packet into the raw form"""

        struct.pack_into(
            f"! BBH HH BBH 4s 4s {len(self._raw_options)}s {len(self._data)}s",
            frame,
            0,
            self._ver << 4 | self._hlen >> 2,
            self._dscp << 2 | self._ecn,
            self._plen,
            self._id,
            self._flag_df << 14 | self._flag_mf << 13 | self._offset >> 3,
            self._ttl,
            self._proto,
            0,
            bytes(self._src),
            bytes(self._dst),
            bytes(self._raw_options),  # memoryview: conversion to bytes requir
            bytes(self._data),  # memoryview: conversion to bytes requir
        )

        struct.pack_into("! H", frame, 10, inet_cksum(frame[: self._hlen]))


#
#   IPv4 options
#


class Ip4OptEol:
    """IP option - End of Ip4Option List"""

    @property
    def raw_option(self) -> bytes:
        """Get option in raw form"""

        return struct.pack("!B", ip4.ps.IP4_OPT_EOL)

    def __str__(self) -> str:
        """Option log string"""

        return "eol"

    def __len__(self) -> int:
        """Option length"""

        return ip4.ps.IP4_OPT_EOL_LEN


class Ip4OptNop:
    """IP option - No Operation"""

    @property
    def raw_option(self) -> bytes:
        """Get option in raw form"""

        return struct.pack("!B", ip4.ps.IP4_OPT_NOP)

    def __str__(self) -> str:
        """Option log string"""

        return "nop"

    def __len__(self) -> int:
        """Option length"""

        return ip4.ps.IP4_OPT_NOP_LEN
