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
This module contains the UDP packet header class.

pytcp/protocols/udp/udp__header.py

ver 3.0.0
"""


from __future__ import annotations

import struct
from abc import ABC
from dataclasses import dataclass
from typing import override

from pytcp.lib.int_checks import is_uint16
from pytcp.lib.proto_struct import ProtoStruct

# The UDP packet header [RFC 768].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source port          |        Destination port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Packet length         |            Checksum           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

UDP__HEADER__LEN = 8
UDP__HEADER__STRUCT = "! HH HH"


@dataclass(frozen=True, kw_only=True)
class UdpHeader(ProtoStruct):
    """
    The UDP packet header.
    """

    sport: int
    dport: int
    plen: int
    cksum: int

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the UDP header fields.
        """

        assert is_uint16(
            self.sport
        ), f"The 'sport' field must be a 16-bit unsigned integer. Got: {self.sport!r}"

        assert is_uint16(
            self.dport
        ), f"The 'dport' field must be a 16-bit unsigned integer. Got: {self.dport!r}"

        assert is_uint16(
            self.plen
        ), f"The 'plen' field must be a 16-bit unsigned integer. Got: {self.plen!r}"

        assert is_uint16(
            self.cksum
        ), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum!r}"

    @override
    def __len__(self) -> int:
        """
        Get the UDP header length.
        """

        return UDP__HEADER__LEN

    @override
    def __bytes__(self) -> bytes:
        """
        Get the UDP header as bytes.
        """

        return struct.pack(
            UDP__HEADER__STRUCT,
            self.sport,
            self.dport,
            self.plen,
            0,
        )

    @override
    @staticmethod
    def from_bytes(_bytes: bytes) -> UdpHeader:
        """
        Initialize UDP header from bytes.
        """

        sport, dport, plen, cksum = struct.unpack(
            UDP__HEADER__STRUCT, _bytes[:UDP__HEADER__LEN]
        )

        return UdpHeader(
            sport=sport,
            dport=dport,
            plen=plen,
            cksum=cksum,
        )


class UdpHeaderProperties(ABC):
    """
    Properties used to access the UDP header fields.
    """

    _header: UdpHeader

    @property
    def sport(self) -> int:
        """
        Get the UDP header 'sport' field.
        """

        return self._header.sport

    @property
    def dport(self) -> int:
        """
        Get the UDP header 'dport' field.
        """

        return self._header.dport

    @property
    def plen(self) -> int:
        """
        Get the UDP header 'plen' field.
        """

        return self._header.plen

    @property
    def cksum(self) -> int:
        """
        Get the UDP header 'cksum' field.
        """

        return self._header.cksum
