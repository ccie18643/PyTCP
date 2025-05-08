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
# pylint: disable = redefined-builtin

"""
Module contain Fast Packet Assembler support class for the IPv4 protocol.

pytcp/protocols/ip4/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp import config
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.ip_helper import inet_cksum
from pytcp.lib.tracker import Tracker
from pytcp.protocols.ether.ps import ETHER_TYPE_IP4
from pytcp.protocols.ip4.ps import (
    IP4_HEADER_LEN,
    IP4_OPT_EOL,
    IP4_OPT_EOL_LEN,
    IP4_OPT_NOP,
    IP4_OPT_NOP_LEN,
    IP4_PROTO_ICMP4,
    IP4_PROTO_RAW,
    IP4_PROTO_TABLE,
    IP4_PROTO_TCP,
    IP4_PROTO_UDP,
)
from pytcp.protocols.raw.fpa import RawAssembler

if TYPE_CHECKING:
    from pytcp.protocols.icmp4.fpa import Icmp4Assembler
    from pytcp.protocols.tcp.fpa import TcpAssembler
    from pytcp.protocols.udp.fpa import UdpAssembler


class Ip4Assembler:
    """
    IPv4 packet assembler support class.
    """

    ether_type = ETHER_TYPE_IP4

    def __init__(
        self,
        *,
        src: Ip4Address = Ip4Address(0),
        dst: Ip4Address = Ip4Address(0),
        ttl: int = config.IP4_DEFAULT_TTL,
        dscp: int = 0,
        ecn: int = 0,
        id: int = 0,
        flag_df: bool = False,
        options: list[Ip4OptNop | Ip4OptEol] | None = None,
        carried_packet: (
            Icmp4Assembler | TcpAssembler | UdpAssembler | RawAssembler
        ) = RawAssembler(),
    ) -> None:
        """
        Class constructor.
        """

        assert 0 <= ttl <= 0xFF
        assert 0 <= dscp <= 0x3F
        assert 0 <= ecn <= 0x03
        assert 0 <= id <= 0xFFFF
        assert carried_packet.ip4_proto in {
            IP4_PROTO_ICMP4,
            IP4_PROTO_UDP,
            IP4_PROTO_TCP,
            IP4_PROTO_RAW,
        }

        self._carried_packet: (
            Icmp4Assembler | TcpAssembler | UdpAssembler | RawAssembler
        ) = carried_packet
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
        self._options: list[Ip4OptNop | Ip4OptEol] = (
            [] if options is None else options
        )
        self._proto: int = self._carried_packet.ip4_proto
        self._hlen: int = IP4_HEADER_LEN + len(self._raw_options)
        self._plen: int = len(self)

    def __len__(self) -> int:
        """
        Length of the packet.
        """

        return (
            IP4_HEADER_LEN
            + sum(len(_) for _ in self._options)
            + len(self._carried_packet)
        )

    def __str__(self) -> str:
        """
        Packet log string.
        """

        log = (
            f"IPv4 {self._src} > {self._dst}, proto {self._proto} "
            f"({IP4_PROTO_TABLE.get(self._proto, '???')}), id {self._id}"
            f"{', DF' if self._flag_df else ''}"
            f"{', MF' if self._flag_mf else ''}, offset {self._offset}, "
            f"plen {self._plen}, ttl {self._ttl}"
        )

        for option in self._options:
            log += ", " + str(option)

        return log

    @property
    def tracker(self) -> Tracker:
        """
        Getter for the '_tracker' attribute.
        """
        return self._tracker

    @property
    def dst(self) -> Ip4Address:
        """
        Getter for the '_dst' attribute.
        """
        return self._dst

    @property
    def src(self) -> Ip4Address:
        """
        Getter for the '_src' attribute.
        """
        return self._src

    @property
    def hlen(self) -> int:
        """
        Getter for the '_hlen' attribute.
        """
        return self._hlen

    @property
    def proto(self) -> int:
        """
        Getter for the '_proto' attribute.
        """
        return self._proto

    @property
    def dlen(self) -> int:
        """
        Calculate data length.
        """
        return self._plen - self._hlen

    @property
    def pshdr_sum(self) -> int:
        """
        Create IPv4 pseudo header used by TCP and UDP to compute
        their checksums.
        """
        pseudo_header = struct.pack(
            "! 4s 4s BBH",
            bytes(self._src),
            bytes(self._dst),
            0,
            self._proto,
            self._plen - self._hlen,
        )
        return sum(struct.unpack("! 3L", pseudo_header))

    @property
    def _raw_options(self) -> bytes:
        """
        Packet options in raw format.
        """
        return b"".join(bytes(option) for option in self._options)

    def assemble(self, frame: memoryview) -> None:
        """
        Assemble packet into the raw form.
        """
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


class Ip4FragAssembler:
    """
    IPv4 packet fragment assembler support class.
    """

    ether_type = ETHER_TYPE_IP4

    def __init__(
        self,
        *,
        src: Ip4Address = Ip4Address(0),
        dst: Ip4Address = Ip4Address(0),
        ttl: int = config.IP4_DEFAULT_TTL,
        dscp: int = 0,
        ecn: int = 0,
        id: int = 0,
        flag_mf: bool = False,
        offset: int = 0,
        options: list[Ip4OptNop | Ip4OptEol] | None = None,
        proto: int = IP4_PROTO_RAW,
        data: bytes = b"",
    ):
        """
        Class constructor.
        """

        assert 0 <= ttl <= 0xFF
        assert 0 <= dscp <= 0x3F
        assert 0 <= ecn <= 0x03
        assert 0 <= id <= 0xFFFF
        assert proto in {
            IP4_PROTO_ICMP4,
            IP4_PROTO_UDP,
            IP4_PROTO_TCP,
            IP4_PROTO_RAW,
        }

        self._tracker: Tracker = Tracker(prefix="TX")
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
        self._options: list[Ip4OptNop | Ip4OptEol] = (
            [] if options is None else options
        )
        self._data: bytes = data
        self._proto: int = proto
        self._hlen: int = IP4_HEADER_LEN + len(self._raw_options)
        self._plen: int = len(self)

    def __len__(self) -> int:
        """
        Length of the packet.
        """
        return (
            IP4_HEADER_LEN
            + sum(len(_) for _ in self._options)
            + len(self._data)
        )

    def __str__(self) -> str:
        """
        Packet log string.
        """

        log = (
            f"IPv4 {self._src} > {self._dst}, proto {self._proto} "
            f"({IP4_PROTO_TABLE.get(self._proto, '???')}), id {self._id}"
            f"{', DF' if self._flag_df else ''}"
            f"{', MF' if self._flag_mf else ''}, offset {self._offset}, "
            f"plen {self._plen}, ttl {self._ttl}"
        )

        for option in self._options:
            log += ", " + str(option)

        return log

    @property
    def tracker(self) -> Tracker:
        """
        Getter for the '_tracker' attribute.
        """
        return self._tracker

    @property
    def dst(self) -> Ip4Address:
        """
        Getter for the '_dst' attribute.
        """
        return self._dst

    @property
    def src(self) -> Ip4Address:
        """
        Getter for the '_src' attribute.
        """
        return self._src

    @property
    def _raw_options(self) -> bytes:
        """
        Packet options in raw format.
        """
        raw_options = b""
        for option in self._options:
            raw_options += bytes(option)
        return raw_options

    def assemble(self, frame: memoryview) -> None:
        """
        Assemble packet into the raw form.
        """
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
            bytes(self._raw_options),  # memoryview: conversion to bytes require
            bytes(self._data),  # memoryview: conversion to bytes require
        )
        struct.pack_into("! H", frame, 10, inet_cksum(frame[: self._hlen]))


#
#   IPv4 options
#


class Ip4OptEol:
    """
    IP option - End of Ip4Option List.
    """

    def __str__(self) -> str:
        """
        Option log string.
        """
        return "eol"

    def __len__(self) -> int:
        """
        Option length.
        """
        return IP4_OPT_EOL_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return "Ip4OptEol()"

    def __bytes__(self) -> bytes:
        """
        Get option in raw form.
        """
        return struct.pack("!B", IP4_OPT_EOL)

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)


class Ip4OptNop:
    """
    IP option - No Operation.
    """

    def __str__(self) -> str:
        """
        Option log string.
        """
        return "nop"

    def __len__(self) -> int:
        """
        Option length.
        """
        return IP4_OPT_NOP_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return "Ip4OptNop()"

    def __bytes__(self) -> bytes:
        """
        Get option in raw form.
        """
        return struct.pack("!B", IP4_OPT_NOP)

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)
