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

# pylint: disable = too-many-arguments

"""
Module contains interface class for the FPP -> UDP Socket communication.

pytcp/protocols/udp/metadata.py

ver 2.7
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp.lib.ip4_address import Ip4Address

if TYPE_CHECKING:
    from pytcp.lib.ip_address import IpAddress
    from pytcp.lib.tracker import Tracker


class UdpMetadata:
    """
    Store the 'AF_INET6/SOCK_DGRAM' metadata.
    """

    def __init__(
        self,
        local_ip_address: IpAddress,
        local_port: int,
        remote_ip_address: IpAddress,
        remote_port: int,
        data: bytes = b"",
        tracker: Tracker | None = None,
    ) -> None:
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.data = data
        self.tracker = tracker

    def __str__(self) -> str:
        """
        String representation.
        """
        return (
            f"AF_INET{self.local_ip_address.version}/SOCK_DGRAM/"
            f"{self.local_ip_address}/{self.local_port}/"
            f"{self.remote_ip_address}/{self.remote_port}"
        )

    @property
    def socket_patterns(self) -> list[str]:
        """
        Socket ID patterns that match this packet.
        """

        patterns = [
            f"AF_INET{self.local_ip_address.version}/SOCK_DGRAM/"
            f"{self.local_ip_address}/{self.local_port}/"
            f"{self.remote_ip_address}/{self.remote_port}",
            f"AF_INET{self.local_ip_address.version}/SOCK_DGRAM/"
            f"{self.local_ip_address}/{self.local_port}/"
            f"{self.local_ip_address.unspecified}/0",
            f"AF_INET{self.local_ip_address.version}/SOCK_DGRAM/"
            f"{self.local_ip_address.unspecified}/{self.local_port}/"
            f"{self.local_ip_address.unspecified}/0",
        ]

        if isinstance(self.local_ip_address, Ip4Address):
            patterns.append(
                f"AF_INET4/SOCK_DGRAM/0.0.0.0/{self.local_port}/"
                f"255.255.255.255/{self.remote_port}"
            )  # For DHCPv4 client

        return patterns
