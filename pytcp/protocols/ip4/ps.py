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
Module contains packet structure information for the IPv4 protccol.

pytcp/protocols/ip4/ps.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING, TypeAlias

from pytcp.lib.enum import ProtoEnum
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.proto import Proto

if TYPE_CHECKING:
    from pytcp.protocols.icmp4.fpa import Icmp4Assembler
    from pytcp.protocols.raw.fpa import RawAssembler
    from pytcp.protocols.tcp.fpa import TcpAssembler
    from pytcp.protocols.udp.fpa import UdpAssembler

    Ip4Payload: TypeAlias = (
        Icmp4Assembler | TcpAssembler | UdpAssembler | RawAssembler
    )

# IPv4 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |   DSCP    |ECN|          Packet length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to live |    Protocol   |         Header checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP4_HEADER_LEN = 20


class Ip4Proto(ProtoEnum):
    ICMP4 = 1
    TCP = 6
    UDP = 17
    RAW = 255

    @staticmethod
    def _extract(frame: bytes) -> int:
        return frame[9]


IP4_MIN_MTU = 576  # RFC 791

#
#   IPv4 options
#


class Ip4OptionType(ProtoEnum):
    EOL = 0
    NOP = 1

    @staticmethod
    def _extract(frame: bytes) -> int:
        return frame[0]


IP4_OPTION_LEN__EOL = 1
IP4_OPTION_LEN__NOP = 1


class Ip4(Proto):
    """
    Base class for IPv4 packet parser and assembler.
    """

    _ver: int
    _olen: int
    _hlen: int
    _dlen: int
    _plen: int
    _dscp: int
    _ecn: int
    _id: int
    _flag_df: bool
    _flag_mf: bool
    _offset: int
    _ttl: int
    _proto: Ip4Proto
    _cksum: int
    _src: Ip4Address
    _dst: Ip4Address
    _options: list[Ip4Option]

    def __str__(self) -> str:
        """
        Get packet log string.
        """

        log = (
            f"IPv4 {self._src} > {self._dst}, proto {self._proto}, id {self._id}"
            f"{', DF' if self._flag_df else ''}{', MF' if self._flag_mf else ''}, "
            f"offset {self._offset}, plen {self._plen}, ttl {self._ttl}"
        )

        for option in self._options:
            log += ", " + str(option)

        return log

    def __repr__(self) -> str:
        """
        Get the packet representation string.
        """

        return (
            "Ip4("
            f"ver={repr(self._ver)}, "
            f"hlen={repr(self._hlen)}, "
            f"dscp={repr(self._dscp)}, "
            f"ecn={repr(self._ecn)}, "
            f"plen={repr(self._plen)}, "
            f"id={repr(self._id)}, "
            f"flag_df={repr(self._flag_df)}, "
            f"flag_mf={repr(self._flag_mf)}, "
            f"offset={repr(self._offset)}, "
            f"ttl={repr(self._ttl)}, "
            f"proto={repr(self._proto)}, "
            f"cksum={repr(self._cksum)}, "
            f"src={repr(self._src)}, "
            f"dst={repr(self._dst)}, "
            f"options={repr(self._options)}, "
            f"olen={repr(self._olen)}, "
            f"dlen={repr(self._dlen)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the packet in raw form.
        """

        raw_options = b"".join(bytes(option) for option in self._options)

        return struct.pack(
            f"! BBH HH BBH 4s 4s {len(raw_options)}s",
            self._ver << 4 | self._hlen >> 2,
            self._dscp << 2 | self._ecn,
            self._plen,
            self._id,
            self._flag_df << 14 | self._flag_mf << 13 | self._offset >> 3,
            self._ttl,
            int(self._proto),
            0,
            bytes(self._src),
            bytes(self._dst),
            raw_options,
        )

    @property
    def ver(self) -> int:
        """
        Getter for '_ver' attribute.
        """

        return self._ver

    @property
    def olen(self) -> int:
        """
        Getter for '_olen' attribute.
        """

        return self._olen

    @property
    def hlen(self) -> int:
        """
        Getter for '_hlen' attribute.
        """

        return self._hlen

    @property
    def dlen(self) -> int:
        """
        Getter for '_dlen' attribute.
        """

        return self._dlen

    @property
    def plen(self) -> int:
        """
        Getter for '_plen' attribute.
        """

        return self._plen

    @property
    def dscp(self) -> int:
        """
        Getter for '_dscp' attribute.
        """

        return self._dscp

    @property
    def ecn(self) -> int:
        """
        Getter for '_ecn' attribute.
        """

        return self._ecn

    @property
    def id(self) -> int:
        """
        Getter for '_id' attribute.
        """

        return self._id

    @property
    def flag_df(self) -> bool:
        """
        Getter for '_flag_df' attribute.
        """

        return self._flag_df

    @property
    def flag_mf(self) -> bool:
        """
        Getter for '_flag_mf' attribute.
        """

        return self._flag_mf

    @property
    def offset(self) -> int:
        """
        Getter for '_offset' attribute.
        """

        return self._offset

    @property
    def ttl(self) -> int:
        """
        Getter for '_ttl' attribute.
        """

        return self._ttl

    @property
    def proto(self) -> Ip4Proto:
        """
        Getter for '_proto' attribute.
        """

        return self._proto

    @property
    def cksum(self) -> int:
        """
        Getter for '_cksum' attribute.
        """

        return self._cksum

    @property
    def src(self) -> Ip4Address:
        """
        Getter for '_src' attribute.
        """

        return self._src

    @property
    def dst(self) -> Ip4Address:
        """
        Getter for '_dst' attribute.
        """

        return self._dst

    @property
    def options(self) -> list[Ip4Option]:
        """
        Getter for '_options' attribute.
        """

        return self._options

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
            int(self._proto),
            self._plen - self._hlen,
        )

        return sum(struct.unpack("! 3L", pseudo_header))


#
#   IPv4 options.
#


class Ip4Option(Proto):
    """
    Base class for IPv4 options.
    """

    _type: Ip4OptionType
    _len: int

    def __len__(self) -> int:
        """
        Get the option length.
        """

        return self._len

    @property
    def type(self) -> Ip4OptionType:
        """
        Get the '_type' property.
        """

        return self._type

    @property
    def len(self) -> int:
        """
        Get the '_len' property.
        """

        return self._len


class Ip4OptionEol(Ip4Option):
    """
    Base class for IPv4 EOL option parser and assembler.
    """

    _type = Ip4OptionType.EOL
    _len = IP4_OPTION_LEN__EOL

    def __str__(self) -> str:
        """
        Get the option log string.
        """

        return "eol"

    def __repr__(self) -> str:
        """
        Get the option representation string.
        """

        return "Ip4OptionEol()"

    def __bytes__(self) -> bytes:
        """
        Get the option in raw form.
        """

        return struct.pack("! B", self._len)


class Ip4OptionNop(Ip4Option):
    """
    Base class for IPv4 NOP option parser and assembler.
    """

    _type = Ip4OptionType.NOP
    _len = IP4_OPTION_LEN__NOP

    def __str__(self) -> str:
        """
        Get the option log string.
        """

        return "nop"

    def __repr__(self) -> str:
        """
        Get the option representation string.
        """

        return "Ip4OptionNop()"

    def __bytes__(self) -> bytes:
        """
        Get the option in raw form.
        """

        return struct.pack("! B", self._len)


class Ip4OptionUnknown(Ip4Option):
    """
    Base class for the IPv4 unknown option.
    """

    _data: bytes

    def __str__(self) -> str:
        """
        Get the option log string.
        """

        return f"unk-{self._type}-{self._len}"

    def __repr__(self) -> str:
        """
        Get the option representation.
        """

        return (
            f"Ip4OptionUnknown("
            f"type={repr(self._type)}, "
            f"len={repr(self._len)}, "
            f"data={repr(self._data)})"
        )

    def __bytes__(self) -> bytes:
        """
        Get the option in raw form.
        """

        return struct.pack(
            f"! BB {len(self._data)}s",
            self._type,
            self._len >> 3,
            bytes(self._data),
        )

    @property
    def data(self) -> bytes:
        """
        Get the '_data' property.
        """

        return self._data
