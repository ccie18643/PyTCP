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

    ver: int
    local_ip_address: IpAddress
    local_port: int
    remote_ip_address: IpAddress
    remote_port: int
    flag_syn: bool
    flag_ack: bool
    flag_fin: bool
    flag_rst: bool
    seq: int
    ack: int
    win: int
    wscale: int
    mss: int
    data: memoryview
    tracker: Tracker | None

    def __str__(self) -> str:
        """
        Get the TCP metadata log string.
        """

        ver = self.ver
        laddr = self.local_ip_address
        lport = self.local_port
        raddr = self.remote_ip_address
        rport = self.remote_port

        return f"AF_INET{ver}/SOCK_STREAM/{laddr}/{lport}/{raddr}/{rport}"

    @property
    def tcp_listening_socket_patterns(self) -> list[str]:
        """
        Get list of the socket ID patterns that match the metadata.
        """

        ver = self.ver
        laddr = self.local_ip_address
        lport = self.local_port
        unspecified = self.local_ip_address.unspecified

        return [
            f"AF_INET{ver}/SOCK_STREAM/{laddr}/{lport}/{unspecified}/0",
            f"AF_INET{ver}/SOCK_STREAM/{unspecified}/{lport}/{unspecified}/0",
        ]
