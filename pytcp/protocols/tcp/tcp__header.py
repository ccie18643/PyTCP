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
This module contains the TCP packet header class.

pytcp/protocols/tcp/tcp__header.py

ver 3.0.2
"""


from __future__ import annotations

import struct
from abc import ABC
from dataclasses import dataclass
from typing import override

from pytcp.lib.int_checks import (
    is_4_byte_alligned,
    is_uint6,
    is_uint16,
    is_uint32,
)
from pytcp.lib.proto_struct import ProtoStruct

# The TCP packet header [RFC 793].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |       Destination Port        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Sequence Number                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Acknowledgment Number                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Hlen | Res |N|C|E|U|A|P|R|S|F|            Window             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Checksum            |         Urgent Pointer        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                            Options                            ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP__HEADER__LEN = 20
TCP__HEADER__STRUCT = "! HH L L HH HH"


@dataclass(frozen=True, kw_only=True)
class TcpHeader(ProtoStruct):
    """
    The TCP packet header.
    """

    sport: int
    dport: int
    seq: int
    ack: int
    hlen: int
    flag_ns: bool
    flag_cwr: bool
    flag_ece: bool
    flag_urg: bool
    flag_ack: bool
    flag_psh: bool
    flag_rst: bool
    flag_syn: bool
    flag_fin: bool
    win: int
    cksum: int
    urg: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the TCP header fields.
        """

        assert is_uint16(
            self.sport
        ), f"The 'sport' field must be a 16-bit unsigned integer. Got: {self.sport}"

        assert is_uint16(
            self.dport
        ), f"The 'dport' field must be a 16-bit unsigned integer. Got: {self.dport}"

        assert is_uint32(
            self.seq
        ), f"The 'seq' field must be a 32-bit unsigned integer. Got: {self.seq!r}"

        assert is_uint32(
            self.ack
        ), f"The 'ack' field must be a 32-bit unsigned integer. Got: {self.ack!r}"

        assert is_uint6(
            self.hlen
        ), f"The 'hlen' field must be a 6-bit unsigned integer. Got: {self.hlen!r}"

        assert is_4_byte_alligned(
            self.hlen
        ), f"The 'hlen' field must be 4-byte aligned. Got: {self.hlen!r}"

        assert isinstance(
            self.flag_ns, bool
        ), f"The 'flag_ns' field must be a boolean. Got: {type(self.flag_ns)!r}"

        assert isinstance(
            self.flag_cwr, bool
        ), f"The 'flag_cwr' field must be a boolean. Got: {type(self.flag_cwr)!r}"

        assert isinstance(
            self.flag_ece, bool
        ), f"The 'flag_ece' field must be a boolean. Got: {type(self.flag_ece)!r}"

        assert isinstance(
            self.flag_urg, bool
        ), f"The 'flag_urg' field must be a boolean. Got: {type(self.flag_urg)!r}"

        assert isinstance(
            self.flag_ack, bool
        ), f"The 'flag_ack' field must be a boolean. Got: {type(self.flag_ack)!r}"

        assert isinstance(
            self.flag_psh, bool
        ), f"The 'flag_psh' field must be a boolean. Got: {type(self.flag_psh)!r}"

        assert isinstance(
            self.flag_rst, bool
        ), f"The 'flag_rst' field must be a boolean. Got: {type(self.flag_rst)!r}"

        assert isinstance(
            self.flag_syn, bool
        ), f"The 'flag_syn' field must be a boolean. Got: {type(self.flag_syn)!r}"

        assert isinstance(
            self.flag_fin, bool
        ), f"The 'flag_fin' field must be a boolean. Got: {type(self.flag_fin)!r}"

        assert is_uint16(
            self.win
        ), f"The 'win' field must be a 16-bit unsigned integer. Got: {self.win!r}"

        assert is_uint16(
            self.cksum
        ), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

        assert is_uint16(
            self.urg
        ), f"The 'urg' field must be a 16-bit unsigned integer. Got: {self.urg!r}"

    @override
    def __len__(self) -> int:
        """
        Get the TCP header length.
        """

        return TCP__HEADER__LEN

    @override
    def __bytes__(self) -> bytes:
        """
        Get the TCP header as bytes.
        """

        return struct.pack(
            TCP__HEADER__STRUCT,
            self.sport,
            self.dport,
            self.seq,
            self.ack,
            self.hlen << 10
            | self.flag_ns << 8
            | self.flag_cwr << 7
            | self.flag_ece << 6
            | self.flag_urg << 5
            | self.flag_ack << 4
            | self.flag_psh << 3
            | self.flag_rst << 2
            | self.flag_syn << 1
            | self.flag_fin,
            self.win,
            0,
            self.urg,
        )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> TcpHeader:
        """
        Initialize the TCP header from bytes.
        """

        sport, dport, seq, ack, hlen__flags, win, cksum, urg = struct.unpack(
            TCP__HEADER__STRUCT, _bytes[:TCP__HEADER__LEN]
        )

        return TcpHeader(
            sport=sport,
            dport=dport,
            seq=seq,
            ack=ack,
            hlen=(hlen__flags & 0b11110000_00000000) >> 10,
            flag_ns=bool(hlen__flags & 0b00000001_00000000),
            flag_cwr=bool(hlen__flags & 0b00000000_10000000),
            flag_ece=bool(hlen__flags & 0b00000000_01000000),
            flag_urg=bool(hlen__flags & 0b00000000_00100000),
            flag_ack=bool(hlen__flags & 0b00000000_00010000),
            flag_psh=bool(hlen__flags & 0b00000000_00001000),
            flag_rst=bool(hlen__flags & 0b00000000_00000100),
            flag_syn=bool(hlen__flags & 0b00000000_00000010),
            flag_fin=bool(hlen__flags & 0b00000000_00000001),
            win=win,
            cksum=cksum,
            urg=urg,
        )


class TcpHeaderProperties(ABC):
    """
    Properties used to access the TCP header fields.
    """

    _header: TcpHeader

    @property
    def sport(self) -> int:
        """
        Get the TCP header 'sport' field.
        """

        return self._header.sport

    @property
    def dport(self) -> int:
        """
        Get the TCP header 'dport' field.
        """

        return self._header.dport

    @property
    def seq(self) -> int:
        """
        Get the TCP header 'seq' field.
        """

        return self._header.seq

    @property
    def ack(self) -> int:
        """
        Get the TCP header 'ack' field.
        """

        return self._header.ack

    @property
    def hlen(self) -> int:
        """
        Get the TCP header 'hlen' field.
        """

        return self._header.hlen

    @property
    def flag_ns(self) -> bool:
        """
        Get the TCP header 'flag_ns' field.
        """

        return self._header.flag_ns

    @property
    def flag_cwr(self) -> bool:
        """
        Get the TCP header 'flag_cwr' field.
        """

        return self._header.flag_cwr

    @property
    def flag_ece(self) -> bool:
        """
        Get the TCP header 'flag_ece' field.
        """

        return self._header.flag_ece

    @property
    def flag_urg(self) -> bool:
        """
        Get the TCP header 'flag_urg' field.
        """

        return self._header.flag_urg

    @property
    def flag_ack(self) -> bool:
        """
        Get the TCP header 'flag_ack' field.
        """

        return self._header.flag_ack

    @property
    def flag_psh(self) -> bool:
        """
        Get the TCP header 'flag_psh' field.
        """

        return self._header.flag_psh

    @property
    def flag_rst(self) -> bool:
        """
        Get the TCP header 'flag_rst' field.
        """

        return self._header.flag_rst

    @property
    def flag_syn(self) -> bool:
        """
        Get the TCP header 'flag_syn' field.
        """

        return self._header.flag_syn

    @property
    def flag_fin(self) -> bool:
        """
        Get the TCP header 'flag_fin' field.
        """

        return self._header.flag_fin

    @property
    def win(self) -> int:
        """
        Get the TCP header 'win' field.
        """

        return self._header.win

    @property
    def cksum(self) -> int:
        """
        Get the TCP header 'cksum' field.
        """

        return self._header.cksum

    @property
    def urg(self) -> int:
        """
        Get the TCP header 'urg' field.
        """

        return self._header.urg
