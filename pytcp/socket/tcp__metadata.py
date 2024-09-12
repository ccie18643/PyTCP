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
from typing import TYPE_CHECKING

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

    def __str__(self) -> str:
        """
        Get the TCP metadata log string.
        """

        ver = self.ip__ver
        laddr = self.ip__local_address
        lport = self.tcp__local_port
        raddr = self.ip__remote_address
        rport = self.tcp__remote_port

        return f"AF_INET{ver}/SOCK_STREAM/{laddr}/{lport}/{raddr}/{rport}"

    @property
    def tcp_listening_socket_patterns(self) -> list[str]:
        """
        Get list of the socket ID patterns that match the metadata.
        """

        ver = self.ip__ver
        laddr = self.ip__local_address
        lport = self.tcp__local_port
        unspecified = self.ip__local_address.unspecified

        return [
            f"AF_INET{ver}/SOCK_STREAM/{laddr}/{lport}/{unspecified}/0",
            f"AF_INET{ver}/SOCK_STREAM/{unspecified}/{lport}/{unspecified}/0",
        ]
