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
This module contains the TCP protocol base class.

net_proto/protocols/tcp/tcp__base.py

ver 3.0.9
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.proto import Proto
from net_proto.protocols.tcp.options.tcp__options import (
    TcpOptions,
    TcpOptionsProperties,
)
from net_proto.protocols.tcp.tcp__header import TcpHeader, TcpHeaderProperties


class Tcp(Proto, TcpHeaderProperties, TcpOptionsProperties):
    """
    The TCP protocol base.
    """

    _header: TcpHeader
    _options: TcpOptions
    _payload: Buffer

    pshdr_sum: int = 0

    @override
    def __len__(self) -> int:
        """
        Get the TCP packet length.
        """

        return len(self._header) + len(self._options) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the TCP packet log string.
        """

        any_flag_set = (
            self._header.flag_ns
            or self._header.flag_cwr
            or self._header.flag_ece
            or self._header.flag_urg
            or self._header.flag_ack
            or self._header.flag_psh
            or self._header.flag_rst
            or self._header.flag_syn
            or self._header.flag_fin
        )

        return (
            f"TCP {self._header.sport} > {self._header.dport}, "
            f"{'N' if self._header.flag_ns else ''}{'C' if self._header.flag_cwr else ''}"
            f"{'E' if self._header.flag_ece else ''}{'U' if self._header.flag_urg else ''}"
            f"{'A' if self._header.flag_ack else ''}{'P' if self._header.flag_psh else ''}"
            f"{'R' if self._header.flag_rst else ''}{'S' if self._header.flag_syn else ''}"
            f"{'F' if self._header.flag_fin else ''}"
            f"{', ' if any_flag_set else ''}"
            f"seq {self._header.seq}, ack {self._header.ack}, win {self._header.win}, "
            f"{f'urg {self._header.urg}, ' if self._header.flag_urg else ''}"
            f"len {len(self._header) + len(self._options) + len(self._payload)} "
            f"({len(self._header)}+{len(self._options)}+{len(self._payload)})"
            f"{f', opts [{self._options}]' if self._options else ''}"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the TCP packet representation string.
        """

        return f"{type(self).__name__}(header={self._header!r}, options={self._options!r}, payload={self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP packet as a memoryview.
        """

        buffer = bytearray(self._header)
        buffer += bytearray(self._options)
        buffer += self._payload
        buffer[16:18] = inet_cksum(buffer, init=self.pshdr_sum).to_bytes(2)

        return memoryview(buffer)

    @property
    def header(self) -> TcpHeader:
        """
        Get the TCP packet '_header' attribute.
        """

        return self._header

    @property
    def options(self) -> TcpOptions:
        """
        Get the TCP packet '_options' attribute.
        """

        return self._options

    @property
    def payload(self) -> Buffer:
        """
        Get the TCP packet '_payload' attribute.
        """

        return self._payload
