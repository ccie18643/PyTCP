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
Module contains interface class for the FPP -> TCP Socket communication.

pytcp/protocols/tcp/tcp__metadata.py

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
    Store the TCP metadata for the RX packet.
    """

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

        return (
            f"AF_INET{self.local_ip_address.version}/SOCK_STREAM/"
            f"{self.local_ip_address}/{self.local_port}/"
            f"{self.remote_ip_address}/{self.remote_port}"
        )

    @property
    def tcp_listening_socket_patterns(self) -> list[str]:
        """
        Get the session ID patterns that match listening socket.
        """

        return [
            f"AF_INET{self.local_ip_address.version}/SOCK_STREAM/"
            f"{self.local_ip_address}/{self.local_port}/"
            f"{self.local_ip_address.unspecified}/0",
            f"AF_INET{self.local_ip_address.version}/SOCK_STREAM/"
            f"{self.local_ip_address.unspecified}/{self.local_port}/"
            f"{self.local_ip_address.unspecified}/0",
        ]
