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
Module contains interface class for the UDP Parser -> UDP Socket communication.

pytcp/socket/udp__metadata.py

ver 3.0.2
"""


from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from net_addr import Ip4Address

if TYPE_CHECKING:
    from net_addr import IpAddress
    from pytcp.lib.tracker import Tracker


@dataclass(frozen=True, kw_only=True)
class UdpMetadata:
    """
    Store the UDP metadata taken from the received packet.
    """

    ip__ver: int
    ip__local_address: IpAddress
    ip__remote_address: IpAddress

    udp__local_port: int
    udp__remote_port: int
    udp__data: bytes = bytes()

    tracker: Tracker | None = None

    def __str__(self) -> str:
        """
        Get the UDP metadata log string.
        """

        return self.socket_patterns[0]

    @property
    def socket_patterns(self) -> list[str]:
        """
        Get list of the socket ID patterns that match the metadata.
        """

        ver = self.ip__ver
        laddr = self.ip__local_address
        lport = self.udp__local_port
        raddr = self.ip__remote_address
        rport = self.udp__remote_port
        unspecified = self.ip__local_address.unspecified

        patterns = [
            f"AF_INET{ver}/SOCK_DGRAM/{laddr}/{lport}/{raddr}/{rport}",
            f"AF_INET{ver}/SOCK_DGRAM/{laddr}/{lport}/{unspecified}/0",
            f"AF_INET{ver}/SOCK_DGRAM/{unspecified}/{lport}/{unspecified}/0",
        ]

        if isinstance(self.ip__local_address, Ip4Address):
            patterns.append(
                f"AF_INET4/SOCK_DGRAM/0.0.0.0/{lport}/255.255.255.255/{rport}"
            )  # For the DHCPv4 client.

        return patterns
