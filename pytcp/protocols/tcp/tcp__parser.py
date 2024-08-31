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
Module contains the TCP packet parser class.

pytcp/protocols/tcp/tcp__parser.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.proto_parser import ProtoParser
from pytcp.protocols.tcp.options.tcp_options import TcpOptions
from pytcp.protocols.tcp.tcp__base import Tcp
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError, TcpSanityError
from pytcp.protocols.tcp.tcp__header import TCP__HEADER__LEN, TcpHeader

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class TcpParser(Tcp, ProtoParser):
    """
    The TCP packet parser.
    """

    _payload: memoryview

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the TCP packet parser.
        """

        self._frame = packet_rx.frame
        self._ip__payload_len = packet_rx.ip.payload_len
        self._ip__pshdr_sum = packet_rx.ip.pshdr_sum

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.tcp = self
        packet_rx.frame = packet_rx.frame[self._header.hlen :]

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the TCP packet before parsing it.
        """

        if not TCP__HEADER__LEN <= self._ip__payload_len <= len(self._frame):
            raise TcpIntegrityError(
                "The condition 'TCP__HEADER__LEN <= self._ip__payload_len <= "
                f"len(self._frame)' must be met. Got: {TCP__HEADER__LEN=}, "
                f"{self._ip__payload_len=}, {len(self._frame)=}",
            )

        hlen = (self._frame[12] & 0b11110000) >> 2
        if (
            not TCP__HEADER__LEN
            <= hlen
            <= self._ip__payload_len
            <= len(self._frame)
        ):
            raise TcpIntegrityError(
                "The condition 'TCP__HEADER__LEN <= hlen <= self._ip__payload_len <= "
                f"len(self._frame)' must be met. Got: {TCP__HEADER__LEN=}, {hlen=}, "
                f"{self._ip__payload_len=}, {len(self._frame)=}"
            )

        if inet_cksum(
            self._frame[: self._ip__payload_len], self._ip__pshdr_sum
        ):
            raise TcpIntegrityError(
                "The packet checksum must be valid.",
            )

        TcpOptions.validate_integrity(frame=self._frame, hlen=hlen)

    @override
    def _parse(self) -> None:
        """
        Parse the TCP packet.
        """

        self._header = TcpHeader.from_bytes(self._frame)

        self._options = TcpOptions.from_bytes(
            self._frame[len(self._header) : self._header.hlen]
        )

        self._payload = self._frame[self._header.hlen : self._ip__payload_len]

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the TCP packet after parsing it.
        """

        if (value := self._header.sport) == 0:
            raise TcpSanityError(
                f"The 'sport' field must be greater than 0. Got: {value}",
            )

        if (value := self._header.dport) == 0:
            raise TcpSanityError(
                f"The 'dport' field must be greater than 0. Got: {value}",
            )

        if self._header.flag_syn and self._header.flag_fin:
            raise TcpSanityError(
                "The 'flag_syn' and 'flag_fin' must not be set simultaneously.",
            )

        if self._header.flag_syn and self._header.flag_rst:
            raise TcpSanityError(
                "The 'flag_syn' and 'flag_rst' must not be set simultaneously.",
            )

        if self._header.flag_fin and self._header.flag_rst:
            raise TcpSanityError(
                "The 'flag_fin' and 'flag_rst' must not be set simultaneously.",
            )

        if self._header.flag_fin and not self._header.flag_ack:
            raise TcpSanityError(
                "The 'flag_ack' must be set when 'flag_fin' is set.",
            )
