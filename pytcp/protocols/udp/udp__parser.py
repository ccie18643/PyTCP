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
Module contains the UDP packet parser class.

protocols/udp/udp__parser.py

ver 3.0.1
"""


from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.proto_parser import ProtoParser
from pytcp.protocols.udp.udp__base import Udp
from pytcp.protocols.udp.udp__errors import UdpIntegrityError, UdpSanityError
from pytcp.protocols.udp.udp__header import UDP__HEADER__LEN, UdpHeader

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class UdpParser(Udp, ProtoParser):
    """
    The UDP packet parser.
    """

    _payload: memoryview

    def __init__(self, *, packet_rx: PacketRx) -> None:
        """
        Initialize the UDP packet parser.
        """

        self._frame = packet_rx.frame
        self._ip__payload_len = packet_rx.ip.payload_len
        self._ip__pshdr_sum = packet_rx.ip.pshdr_sum

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.udp = self
        packet_rx.frame = packet_rx.frame[len(self._header) :]

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the UDP packet before parsing it.
        """

        if not UDP__HEADER__LEN <= self._ip__payload_len <= len(self._frame):
            raise UdpIntegrityError(
                "The condition 'UDP__HEADER__LEN <= self._ip__payload_len <= "
                f"len(self._frame)' must be met. Got: {UDP__HEADER__LEN=}, "
                f"{self._ip__payload_len=}, {len(self._frame)=}",
            )

        plen = int.from_bytes(self._frame[4:6])
        if (
            not UDP__HEADER__LEN
            <= plen
            == self._ip__payload_len
            <= len(self._frame)
        ):
            raise UdpIntegrityError(
                "The condition 'UDP__HEADER__LEN <= plen == self._ip__payload_len "
                f"<= len(self._frame)' must be met. Got: {UDP__HEADER__LEN=}, "
                f"{plen=}, {self._ip__payload_len=}, {len(self._frame)=}",
            )

        if int.from_bytes(self._frame[6:8]) != 0 and inet_cksum(
            self._frame[: self._ip__payload_len], self._ip__pshdr_sum
        ):
            raise UdpIntegrityError("The packet checksum must be valid.")

    @override
    def _parse(self) -> None:
        """
        Parse the UDP packet.
        """

        self._header = UdpHeader.from_bytes(self._frame)
        self._payload = self._frame[len(self._header) : self._header.plen]

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the UDP packet after parsing it.
        """

        if (value := self.sport) == 0:
            raise UdpSanityError(
                f"The 'sport' field must be greater than 0. Got: {value}",
            )

        if (value := self.dport) == 0:
            raise UdpSanityError(
                f"The 'dport' field must be greater than 0. Got: {value}",
            )
