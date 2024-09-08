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
The example 'user space' service TCP Discard (RFC 863).

examples/tcp_discard_service.py

ver 3.0.2
"""


from __future__ import annotations

import time
from typing import TYPE_CHECKING, override

import click

from examples.lib.tcp_service import TcpService
from pytcp import TcpIpStack, initialize_interface
from pytcp.lib.net_addr.click_types import (
    ClickTypeIp4Address,
    ClickTypeIp4Host,
    ClickTypeIp6Address,
    ClickTypeIp6Host,
    ClickTypeMacAddress,
)
from pytcp.lib.net_addr.ip4_address import Ip4Address
from pytcp.lib.net_addr.ip4_host import Ip4Host
from pytcp.lib.net_addr.ip6_address import Ip6Address
from pytcp.lib.net_addr.ip6_host import Ip6Host
from pytcp.lib.net_addr.ip_address import IpAddress
from pytcp.lib.net_addr.mac_address import MacAddress

if TYPE_CHECKING:
    from pytcp.lib.socket import Socket


class TcpDiscardService(TcpService):
    """
    TCP Discard service support class.
    """

    def __init__(self, *, local_ip_address: IpAddress, local_port: int):
        """
        Class constructor.
        """
        super().__init__(
            service_name="Discard",
            local_ip_address=local_ip_address,
            local_port=local_port,
        )

    @override
    def _service(self, *, connected_socket: Socket) -> None:
        """
        Inbound connection handler.
        """

        click.echo(
            "Service TCP Echo: Sending first message to "
            f"{connected_socket.remote_ip_address}, port {connected_socket.remote_port}."
        )
        connected_socket.send(b"***CLIENT OPEN / SERVICE OPEN***\n")

        while self._run_thread:
            if not (message := connected_socket.recv()):
                click.echo(
                    f"Service TCP Discard: Connection to {connected_socket.remote_ip_address}, "
                    f"port {connected_socket.remote_port} has been closed by peer."
                )
                click.echo(
                    "Service TCP Discard: Sending last message to "
                    f"{connected_socket.remote_ip_address}, port {connected_socket.remote_port}."
                )
                connected_socket.send(b"***CLIENT CLOSED, SERVICE CLOSING***\n")
                click.echo(
                    "Service TCP Discard: Closng connection to "
                    f"{connected_socket.remote_ip_address}, port {connected_socket.remote_port}."
                )
                connected_socket.close()
                break

            if message.strip().lower() in {b"quit", b"close", b"bye", b"exit"}:
                click.echo(
                    "Service TCP Discard: Sending last message to "
                    f"{connected_socket.remote_ip_address}, port {connected_socket.remote_port}."
                )
                connected_socket.send(b"***CLIENT OPEN, SERVICE CLOSING***\n")
                click.echo(
                    "Service TCP Discard: Closng connection to "
                    f"{connected_socket.remote_ip_address}, port {connected_socket.remote_port}."
                )
                connected_socket.close()
                continue

            click.echo(
                f"Service TCP Discard: Received {len(message)} bytes from "
                f"{connected_socket.remote_ip_address}, port {connected_socket.remote_port}."
            )

        connected_socket.close()
        click.echo(
            f"Service TCP Discard: Connection from {connected_socket.remote_ip_address}, "
            f"port {connected_socket.remote_port} has been closed by peer."
        )


@click.command()
@click.option(
    "--interface",
    default="tap7",
    help="Name of the interface to be used by the stack.",
)
@click.option(
    "--mac-address",
    type=ClickTypeMacAddress(),
    default=None,
    help="MAC address to be assigned to the interface.",
)
@click.option(
    "--ip6-address",
    type=ClickTypeIp6Host(),
    default=None,
    help="IPv6 address/mask to be assigned to the interface.",
)
@click.option(
    "--ip6-gateway",
    type=ClickTypeIp6Address(),
    default=None,
    help="IPv6 gateway address to be assigned to the interface.",
)
@click.option(
    "--ip4-address",
    type=ClickTypeIp4Host(),
    default=None,
    help="IPv4 address/mask to be assigned to the interface.",
)
@click.option(
    "--ip4-gateway",
    type=ClickTypeIp4Address(),
    default=None,
    help="IPv4 gateway address to be assigned to the interface.",
)
@click.option(
    "--local-port",
    default=9,
    type=int,
    help="Local port number to be used by the service.",
)
def cli(
    *,
    interface: str,
    mac_address: MacAddress | None,
    ip6_address: Ip6Host | None,
    ip6_gateway: Ip6Address | None,
    ip4_address: Ip4Host | None,
    ip4_gateway: Ip4Address | None,
    local_port: int,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Start TCP Daytime service.
    """

    fd, mtu = initialize_interface(interface)

    ip6_host = (
        None
        if ip6_address is None
        else Ip6Host(ip6_address, gateway=ip6_gateway)
    )
    ip4_host = (
        None
        if ip4_address is None
        else Ip4Host(ip4_address, gateway=ip4_gateway)
    )

    stack = TcpIpStack(
        fd=fd,
        mtu=mtu,
        mac_address=mac_address,
        ip6_host=ip6_host,
        ip4_host=ip4_host,
    )

    service_ip4 = TcpDiscardService(
        local_ip_address=ip4_host.address if ip4_host else Ip4Address(),
        local_port=local_port,
    )

    service_ip6 = TcpDiscardService(
        local_ip_address=ip6_host.address if ip6_host else Ip6Address(),
        local_port=local_port,
    )

    try:
        stack.start()
        service_ip4.start()
        service_ip6.start()
        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        service_ip4.stop()
        service_ip6.stop()
        stack.stop()


if __name__ == "__main__":
    cli()  # pylint: disable = missing-kwoa
