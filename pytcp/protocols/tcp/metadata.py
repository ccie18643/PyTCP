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
# pylint: disable = too-many-arguments
# pylint: disable = too-many-locals

"""
Module contains interface class for the FPP -> TCP Socket communication.

pytcp/protocols/tcp/metadata.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pytcp.lib.ip_address import IpAddress
    from pytcp.lib.tracker import Tracker


class TcpMetadata:
    """
    Store TCP metadata for the RX packet.
    """

    def __init__(
        self,
        local_ip_address: IpAddress,
        local_port: int,
        remote_ip_address: IpAddress,
        remote_port: int,
        flag_syn: bool,
        flag_ack: bool,
        flag_fin: bool,
        flag_rst: bool,
        seq: int,
        ack: int,
        win: int,
        wscale: int | None,
        mss: int,
        data: memoryview,
        tracker: Tracker | None,
    ):
        """
        Class constructor.
        """
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.flag_syn = flag_syn
        self.flag_ack = flag_ack
        self.flag_fin = flag_fin
        self.flag_rst = flag_rst
        self.seq = seq
        self.ack = ack
        self.win = win
        self.wscale = wscale
        self.mss = mss
        self.data = data
        self.tracker = tracker

    def __str__(self) -> str:
        """
        String representation.
        """
        return (
            f"AF_INET{self.local_ip_address.version}/SOCK_STREAM/"
            f"{self.local_ip_address}/{self.local_port}/"
            f"{self.remote_ip_address}/{self.remote_port}"
        )

    @property
    def tcp_listening_socket_patterns(self) -> list[str]:
        """
        Session ID patterns that match listening socket.
        """
        return [
            f"AF_INET{self.local_ip_address.version}/SOCK_STREAM/"
            f"{self.local_ip_address}/{self.local_port}/"
            f"{self.local_ip_address.unspecified}/0",
            f"AF_INET{self.local_ip_address.version}/SOCK_STREAM/"
            f"{self.local_ip_address.unspecified}/{self.local_port}/"
            f"{self.local_ip_address.unspecified}/0",
        ]
