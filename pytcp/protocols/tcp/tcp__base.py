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
This module contains the TCP protccol base class.

pytcp/protocols/tcp/tpc__base.py

ver 3.0.2
"""


from __future__ import annotations

from typing import override

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.proto import Proto
from pytcp.protocols.tcp.options.tcp_options import (
    TcpOptions,
    TcpOptionsProperties,
)
from pytcp.protocols.tcp.tcp__header import TcpHeader, TcpHeaderProperties


class Tcp(Proto, TcpHeaderProperties, TcpOptionsProperties):
    """
    The TCP protocol base.
    """

    _header: TcpHeader
    _options: TcpOptions
    _payload: memoryview | bytes

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

        return (
            f"TCP {self._header.sport} > {self._header.dport}, "
            f"{'N' if self._header.flag_ns else ''}{'C' if self._header.flag_cwr else ''}"
            f"{'E' if self._header.flag_ece else ''}{'U' if self._header.flag_urg else ''}"
            f"{'A' if self._header.flag_ack else ''}{'P' if self._header.flag_psh else ''}"
            f"{'R' if self._header.flag_rst else ''}{'S' if self._header.flag_syn else ''}"
            f"{'F' if self._header.flag_fin else ''}"
            f"{
                ', '
                if any(
                    {
                        self._header.flag_ns,
                        self._header.flag_cwr,
                        self._header.flag_ece,
                        self._header.flag_urg,
                        self._header.flag_ack,
                        self._header.flag_psh,
                        self._header.flag_rst,
                        self._header.flag_syn,
                        self._header.flag_fin,
                    }
                )
                else ''
            }"
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

        return (
            f"{self.__class__.__name__}(header={self._header!r}, "
            f"options={self._options!r}, payload={self._payload!r})"
        )

    @override
    def __bytes__(self) -> bytes:
        """
        Get the TCP packet as bytes.
        """

        _bytes = bytearray(
            bytes(self._header) + bytes(self._options) + self._payload
        )
        _bytes[16:18] = inet_cksum(_bytes, self.pshdr_sum).to_bytes(2)

        return bytes(_bytes)

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
    def payload(self) -> bytes:
        """
        Get the TCP packet '_payload' attribute.
        """

        return self._payload
