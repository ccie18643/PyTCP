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
The base class for servers and clients used in examples.

examples/lib/subsystem.py

ver 3.0.3
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import click
from net_addr.ip_address import IpVersion

from pytcp.socket import (
    AF_INET4,
    AF_INET6,
    IPPROTO_ICMP4,
    IPPROTO_ICMP6,
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_STREAM,
    socket,
)
from pytcp.socket.socket import Socket

if TYPE_CHECKING:
    from net_addr.ip4_address import Ip4Address
    from net_addr.ip6_address import Ip6Address


class Subsystem(ABC):
    """
    Base class for 'user space' services like clients and servers.
    """

    stack_ip4_address: Ip4Address | None = None
    stack_ip6_address: Ip6Address | None = None

    _subsystem_name: str

    @abstractmethod
    def start(self) -> None:
        """
        Start the subsystem.
        """

        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        """
        Stop the subsystem.
        """

        raise NotImplementedError

    @abstractmethod
    def is_alive(self) -> bool:
        """
        Check if the subsystem is alive.
        """

        raise NotImplementedError

    def _log(self, message: str) -> None:
        """
        Log a message.
        """

        click.secho(
            f"{self._subsystem_name} - {message}",
            bg="bright_blue",
            fg="bright_yellow",
            bold=True,
        )

    def _get_subsystem_socket(
        self, *, ip_version: IpVersion, protocol_name: str
    ) -> Socket:
        """
        Create and bind the client socket.
        """

        match (ip_version, protocol_name):
            case IpVersion.IP6, "TCP":
                subsystem_socket = socket(family=AF_INET6, type=SOCK_STREAM)
            case IpVersion.IP4, "TCP":
                subsystem_socket = socket(family=AF_INET4, type=SOCK_STREAM)
            case IpVersion.IP6, "UDP":
                subsystem_socket = socket(family=AF_INET6, type=SOCK_DGRAM)
            case IpVersion.IP4, "UDP":
                subsystem_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
            case IpVersion.IP6, "ICMP":
                subsystem_socket = socket(
                    family=AF_INET6, type=SOCK_RAW, protocol=IPPROTO_ICMP6
                )
            case IpVersion.IP4, "ICMP":
                subsystem_socket = socket(
                    family=AF_INET4, type=SOCK_RAW, protocol=IPPROTO_ICMP4
                )
            case _:
                raise ValueError("Invalid IP versions or protocol combination.")

        self._log(f"Created socket [{subsystem_socket}].")

        return subsystem_socket
