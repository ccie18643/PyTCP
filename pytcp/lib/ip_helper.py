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
Module contains helper functions for IP related operations.

pycp/misc/ip_helper.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from pytcp.config import EPHEMERAL_PORT_RANGE
from pytcp.lib import stack

if TYPE_CHECKING:
    from net_addr import IpAddress
    from pytcp.socket.socket import AddressFamily, SocketType


def ip_version(
    ip_address: str,
) -> int | None:
    """
    Return version of IP address string.
    """

    try:
        return Ip6Address(ip_address).version
    except Ip6AddressFormatError:
        try:
            return Ip4Address(ip_address).version
        except Ip4AddressFormatError:
            return None


def str_to_ip(
    ip_address: str,
) -> Ip6Address | Ip4Address | None:
    """
    Convert string to appropriate version IP address.
    """

    try:
        return Ip6Address(ip_address)
    except Ip6AddressFormatError:
        try:
            return Ip4Address(ip_address)
        except Ip4AddressFormatError:
            return None


def pick_local_ip_address(
    remote_ip_address: IpAddress,
) -> Ip6Address | Ip4Address:
    """
    Pick appropriate source IP address based on provided
    destination IP address.
    """

    assert isinstance(remote_ip_address, (Ip6Address, Ip4Address))

    if isinstance(remote_ip_address, Ip6Address):
        return pick_local_ip6_address(remote_ip_address)

    return pick_local_ip4_address(remote_ip_address)


def pick_local_ip6_address(
    remote_ip6_address: Ip6Address,
) -> Ip6Address:
    """
    Pick appropriate source IPv6 address based on provided
    destination IPv6 address.
    """

    # If destination belongs to any of local networks
    # pick source address from that network.
    for ip6_host in stack.packet_handler.ip6_host:
        if remote_ip6_address in ip6_host.network:
            return ip6_host.address

    # If destination is external pick source from first
    # network that has default gateway set.
    for ip6_host in stack.packet_handler.ip6_host:
        if ip6_host.gateway:
            return ip6_host.address

    # In case everything else fails return unspecified.
    return Ip6Address()


def pick_local_ip4_address(
    remote_ip4_address: Ip4Address,
) -> Ip4Address:
    """
    Pick appropriate source IPv4 address based on provided
    destination IPv4 address.
    """

    # If destination belongs to any of local networks
    # pick source address from that network.
    for ip4_host in stack.packet_handler.ip4_host:
        if remote_ip4_address in ip4_host.network:
            return ip4_host.address

    # If destination is external pick source from first
    # network that has default gateway set.
    for ip4_host in stack.packet_handler.ip4_host:
        if ip4_host.gateway:
            return ip4_host.address

    # In case everything else fails return unspecified.
    return Ip4Address()


def pick_local_port() -> int:
    """
    Pick ephemeral local port, making sure it is not already being used
    by any socket.
    """

    available_ephemeral_ports = set(EPHEMERAL_PORT_RANGE) - {
        int(_.split("/")[3]) for _ in stack.sockets
    }

    if len(available_ephemeral_ports):
        return available_ephemeral_ports.pop()

    raise OSError(
        "[Errno 98] Address already in use - [Unable to find free "
        "local ephemeral port]"
    )


def is_address_in_use(
    *,
    local_ip_address: IpAddress,
    local_port: int,
    address_family: AddressFamily,
    socket_type: SocketType,
) -> bool:
    """
    Check if IP address / port combination is already in use.
    """

    for opened_socket in stack.sockets.values():
        if (
            opened_socket.family == address_family
            and opened_socket.type == socket_type
            and (
                (
                    opened_socket.local_ip_address.is_unspecified
                    or opened_socket.local_ip_address == local_ip_address
                )
                or local_ip_address.is_unspecified
            )
            and opened_socket.local_port == local_port
        ):
            return True

    return False
