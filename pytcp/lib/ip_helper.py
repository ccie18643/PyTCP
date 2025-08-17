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
This module contains helper functions for the IP related operations.

pycp/lib/ip_helper.py

ver 3.0.3
"""


from __future__ import annotations

from typing import TYPE_CHECKING, cast

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
    IpAddress,
    IpVersion,
)
from pytcp import stack

if TYPE_CHECKING:
    from pytcp.socket.socket import AddressFamily, SocketType


def ip_version(
    *,
    ip_address: str,
) -> IpVersion | None:
    """
    Return version of the IP address string.
    """

    try:
        return Ip6Address(ip_address).version
    except Ip6AddressFormatError:
        try:
            return Ip4Address(ip_address).version
        except Ip4AddressFormatError:
            return None


def str_to_ip(ip_address: str, /) -> Ip6Address | Ip4Address | None:
    """
    Convert string to the appropriate version of the IP address.
    """

    try:
        return Ip6Address(ip_address)
    except Ip6AddressFormatError:
        try:
            return Ip4Address(ip_address)
        except Ip4AddressFormatError:
            return None


def pick_local_ip_address[T: IpAddress](*, remote_ip_address: T) -> T:
    """
    Pick an appropriate source IP address based on the provided destination IP address.
    """

    match remote_ip_address.version:
        case IpVersion.IP6:
            assert isinstance(remote_ip_address, Ip6Address)
            return cast(
                T,
                pick_local_ip6_address(remote_ip6_address=remote_ip_address),
            )

        case IpVersion.IP4:
            assert isinstance(remote_ip_address, Ip4Address)
            return cast(
                T,
                pick_local_ip4_address(remote_ip4_address=remote_ip_address),
            )


def pick_local_ip6_address(
    *,
    remote_ip6_address: Ip6Address,
) -> Ip6Address:
    """
    Pick an appropriate source IPv6 address based on the provided destination IPv6 address.
    """

    # If the destination belongs to any of the local networks,
    # pick a source address from that network.
    for ip6_host in stack.packet_handler.ip6_host:
        if remote_ip6_address in ip6_host.network:
            return ip6_host.address

    # If the destination is an external address, pick the source address from the first
    # network that has a default gateway set.
    for ip6_host in stack.packet_handler.ip6_host:
        if ip6_host.gateway:
            return ip6_host.address

    # In case everything else fails, return the unspecified address.
    return Ip6Address()


def pick_local_ip4_address(
    *,
    remote_ip4_address: Ip4Address,
) -> Ip4Address:
    """
    Pick an appropriate source IPv4 address based on the provided destination IPv4 address.
    """

    # If the destination belongs to any of the local networks,
    # pick a source address from that network.
    for ip4_host in stack.packet_handler.ip4_host:
        if remote_ip4_address in ip4_host.network:
            return ip4_host.address

    # If the destination is an external address, pick the source address from the first
    # network that has a default gateway set.
    for ip4_host in stack.packet_handler.ip4_host:
        if ip4_host.gateway:
            return ip4_host.address

    # In case everything else fails, return the unspecified address.
    return Ip4Address()


def pick_local_port() -> int:
    """
    Pick an ephemeral local port, ensuring no socket is already using it.
    """

    available_ephemeral_ports = set(stack.EPHEMERAL_PORT_RANGE) - {
        socket.local_port for socket in stack.sockets.values()
    }

    if len(available_ephemeral_ports):
        return available_ephemeral_ports.pop()

    raise OSError(
        "[Errno 98] Address already in use - [Unable to find free "
        "local ephemeral port]"
    )


def is_address_in_use(
    *,
    local_ip_address: Ip6Address | Ip4Address,
    local_port: int,
    address_family: AddressFamily,
    socket_type: SocketType,
) -> bool:
    """
    Check if the IP address and port combination is already in use.
    """

    from pytcp.socket.tcp__socket import TcpSocket
    from pytcp.socket.udp__socket import UdpSocket

    for opened_socket in stack.sockets.values():
        if (
            opened_socket.family == address_family
            and opened_socket.type == socket_type
        ):
            opened_socket = cast(TcpSocket | UdpSocket, opened_socket)
            if (
                opened_socket.local_ip_address.is_unspecified
                or opened_socket.local_ip_address == local_ip_address
                or local_ip_address.is_unspecified
            ) and opened_socket.local_port == local_port:
                return True

    return False
