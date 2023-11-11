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
from pytcp.protocols.ethernet.ps import EthernetType
from pytcp.protocols.ip4.ps import (
    IP4_HEADER_LEN,
    Ip4,
    Ip4Option,
    Ip4OptionEol,
    Ip4OptionNop,
    Ip4Proto,
)
from pytcp.protocols.raw.fpa import RawAssembler

if TYPE_CHECKING:
    from pytcp.protocols.ip4.ps import Ip4Payload


class Ip4Assembler(Ip4):
    """
    IPv4 packet assembler support class.
    """

    ethernet_type = EthernetType.IP4

    def __init__(
        self,
        *,
        ip4__src: Ip4Address = Ip4Address(0),
        ip4__dst: Ip4Address = Ip4Address(0),
        ip4__ttl: int = config.IP4_DEFAULT_TTL,
        ip4__dscp: int = 0,
        ip4__ecn: int = 0,
        ip4__id: int = 0,
        ip4__flag_df: bool = False,
        ip4__options: list[Ip4Option] | None = None,
        ip4__payload: Ip4Payload = RawAssembler(),
    ) -> None:
        """
        Class constructor.
        """

        assert 0 <= ip4__ttl <= 0xFF
        assert 0 <= ip4__dscp <= 0x3F
        assert 0 <= ip4__ecn <= 0x03
        assert 0 <= ip4__id <= 0xFFFF

        self._payload = ip4__payload
        self._tracker = self._payload.tracker
        self._ver = 4
        self._dscp = ip4__dscp
        self._ecn = ip4__ecn
        self._id = ip4__id
        self._flag_df = ip4__flag_df
        self._flag_mf = False
        self._offset = 0
        self._ttl = ip4__ttl
        self._src = ip4__src
        self._dst = ip4__dst
        self._options: list[Ip4Option] = (
            [] if ip4__options is None else ip4__options
        )
        self._proto = self._payload.ip4_proto
        self._olen = sum(len(option) for option in self._options)
        self._hlen = IP4_HEADER_LEN + self._olen
        self._dlen = len(self._payload)
        self._plen = self._hlen + self._dlen

    def __len__(self) -> int:
        """
        Get length of the packet.
        """

        return self._plen

    @property
    def tracker(self) -> Tracker:
        """
        Get the '_tracker' attribute.
        """

        return self._tracker

    def assemble(self, frame: memoryview) -> None:
        """
        Assemble packet into the raw form.
        """

        struct.pack_into(f"{self._hlen}s", frame, 0, bytes(self))
        struct.pack_into("! H", frame, 10, inet_cksum(frame[: self._hlen]))

        self._payload.assemble(frame[self._hlen :], self.pshdr_sum)


class Ip4FragAssembler(Ip4):
    """
    IPv4 packet fragment assembler support class.
    """

    ethernet_type = EthernetType.IP4

    def __init__(
        self,
        *,
        ip4__src: Ip4Address = Ip4Address(0),
        ip4__dst: Ip4Address = Ip4Address(0),
        ip4__ttl: int = config.IP4_DEFAULT_TTL,
        ip4__dscp: int = 0,
        ip4__ecn: int = 0,
        ip4__id: int = 0,
        ip4__flag_mf: bool = False,
        ip4__offset: int = 0,
        ip4__options: list[Ip4Option] | None = None,
        ip4__proto: Ip4Proto = Ip4Proto.RAW,
        ip4__data: bytes = b"",
    ):
        """
        Class constructor.
        """

        assert 0 <= ip4__ttl <= 0xFF
        assert 0 <= ip4__dscp <= 0x3F
        assert 0 <= ip4__ecn <= 0x03
        assert 0 <= ip4__id <= 0xFFFF
        assert ip4__proto in Ip4Proto

        self._tracker = Tracker(prefix="TX")
        self._ver = 4
        self._dscp = ip4__dscp
        self._ecn = ip4__ecn
        self._id = ip4__id
        self._flag_df = False
        self._flag_mf = ip4__flag_mf
        self._offset = ip4__offset
        self._ttl = ip4__ttl
        self._src = ip4__src
        self._dst = ip4__dst
        self._options: list[Ip4Option] = (
            [] if ip4__options is None else ip4__options
        )
        self._data = ip4__data
        self._proto = ip4__proto

        self._olen = sum(len(option) for option in self._options)
        self._hlen = IP4_HEADER_LEN + self._olen
        self._dlen = len(self._data)
        self._plen = self._hlen + self._dlen

    def __len__(self) -> int:
        """
        Get length of the packet.
        """

        return self._plen

    @property
    def tracker(self) -> Tracker:
        """
        Getter for the '_tracker' attribute.
        """
        return self._tracker

    def assemble(self, frame: memoryview) -> None:
        """
        Assemble packet into the raw form.
        """

        struct.pack_into(f"{self._hlen}s", frame, 0, bytes(self))
        struct.pack_into(f"{self._dlen}s", frame, self._hlen, self._data)
        struct.pack_into("! H", frame, 10, inet_cksum(frame[: self._hlen]))


#
#   IPv4 options
#


class Ip4OptionEolAssembler(Ip4OptionEol):
    """
    IPv4 EOL option assembler.
    """

    def __init__(self) -> None:
        """
        Option constructor.
        """

        pass


class Ip4OptionNopAssembler(Ip4OptionNop):
    """
    IPv4 NOP option assembler.
    """

    def __init__(self) -> None:
        """
        Option constructor.
        """

        pass
