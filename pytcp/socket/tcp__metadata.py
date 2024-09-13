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
Module contains interface class for the TCP Parser -> TCP Socket communication.

pytcp/socket/tcp__metadata.py

ver 3.0.2
"""


from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .socket import AddressFamily, IpProto, SocketType

if TYPE_CHECKING:
    from net_addr import IpAddress
    from pytcp.lib.tracker import Tracker


@dataclass(frozen=True, kw_only=True)
class TcpMetadata:
    """
    Store the TCP metadata taken from the received packet.
    """

    ip__ver: int
    ip__local_address: IpAddress
    ip__remote_address: IpAddress

    tcp__local_port: int
    tcp__remote_port: int
    tcp__flag_syn: bool
    tcp__flag_ack: bool
    tcp__flag_fin: bool
    tcp__flag_rst: bool
    tcp__seq: int
    tcp__ack: int
    tcp__win: int
    tcp__wscale: int
    tcp__mss: int
    tcp__data: memoryview

    tracker: Tracker | None

    @property
    def socket_id(self) -> tuple[Any, ...]:
        """
        Get the exact match socket ID.
        """

        return (
            AddressFamily.from_ver(self.ip__ver),
            SocketType.SOCK_STREAM,
            IpProto.IPPROTO_TCP,
            self.ip__local_address,
            self.tcp__local_port,
            self.ip__remote_address,
            self.tcp__remote_port,
        )

    @property
    def listening_socket_ids(self) -> list[tuple[Any, ...]]:
        """
        Get list of the listening socket IDs that match the metadata.
        """

        return [
            (
                AddressFamily.from_ver(self.ip__ver),
                SocketType.SOCK_STREAM,
                IpProto.IPPROTO_TCP,
                self.ip__local_address,
                self.tcp__local_port,
                self.ip__remote_address.unspecified,
                0,
            ),
            (
                AddressFamily.from_ver(self.ip__ver),
                SocketType.SOCK_STREAM,
                IpProto.IPPROTO_TCP,
                self.ip__local_address.unspecified,
                self.tcp__local_port,
                self.ip__remote_address.unspecified,
                0,
            ),
        ]
