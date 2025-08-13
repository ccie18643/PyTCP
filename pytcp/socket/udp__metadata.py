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

from net_addr.ip6_address import Ip6Address
from net_addr.ip_address import IpVersion

from net_addr import Ip4Address
from pytcp.socket.socket import AddressFamily, SocketType
from pytcp.socket.socket_id import SocketId

if TYPE_CHECKING:
    from net_addr import IpAddress
    from pytcp.lib.tracker import Tracker


@dataclass(frozen=True, kw_only=True)
class UdpMetadata:
    """
    Store the UDP metadata taken from the received packet.
    """

    ip__ver: IpVersion
    ip__local_address: IpAddress
    ip__remote_address: IpAddress

    udp__local_port: int
    udp__remote_port: int
    udp__data: bytes = bytes()

    tracker: Tracker | None = None

    @property
    def socket_ids(self) -> list[SocketId]:
        """
        Get list of the listening socket IDs that match the metadata.
        """

        match self.ip__ver, self.udp__local_port, self.udp__remote_port:
            case IpVersion.IP4, 68, 67:
                return [
                    SocketId(
                        AddressFamily.INET4,
                        SocketType.DGRAM,
                        Ip4Address(),
                        68,
                        Ip4Address("255.255.255.255"),
                        67,
                    ),  # ID for the DHCPv4 client operation.
                ]
            case IpVersion.IP6, 546, 547:
                return [
                    SocketId(
                        AddressFamily.INET6,
                        SocketType.DGRAM,
                        Ip6Address(),
                        546,
                        Ip6Address("ff02::1:2"),
                        547,
                    ),  # ID for the DHCPv6 client operation.
                    SocketId(
                        AddressFamily.INET6,
                        SocketType.DGRAM,
                        Ip6Address(),
                        546,
                        Ip6Address("ff02::1:3"),
                        547,
                    ),  # ID for the DHCPv6 client operation.
                ]
            case _:
                return [
                    SocketId(
                        AddressFamily.from_ver(self.ip__ver),
                        SocketType.DGRAM,
                        self.ip__local_address,
                        self.udp__local_port,
                        self.ip__remote_address,
                        self.udp__remote_port,
                    ),
                    SocketId(
                        AddressFamily.from_ver(self.ip__ver),
                        SocketType.DGRAM,
                        self.ip__local_address,
                        self.udp__local_port,
                        self.ip__remote_address.unspecified,
                        0,
                    ),
                    SocketId(
                        AddressFamily.from_ver(self.ip__ver),
                        SocketType.DGRAM,
                        self.ip__local_address.unspecified,
                        self.udp__local_port,
                        self.ip__remote_address.unspecified,
                        0,
                    ),
                ]
