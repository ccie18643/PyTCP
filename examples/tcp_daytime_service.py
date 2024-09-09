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
The example 'user space' service TCP Daytime (RFC 867).

examples/tcp_daytime_service.py - The 'user space' service TCP Daytime (RFC 867).

ver 3.0.2
"""


from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING, override

import click

from examples.lib.tcp_service import TcpService
from pytcp import TcpIpStack, initialize_interface
from pytcp.lib.net_addr import (
    ClickTypeIp4Address,
    ClickTypeIp4Host,
    ClickTypeIp6Address,
    ClickTypeIp6Host,
    ClickTypeMacAddress,
    Ip4Address,
    Ip4Host,
    Ip6Address,
    Ip6Host,
    IpAddress,
    MacAddress,
)

if TYPE_CHECKING:
    from pytcp.lib.socket import Socket


class TcpDaytimeService(TcpService):
    """
    TCP Daytime service support class.
    """

    def __init__(
        self,
        *,
        local_ip_address: IpAddress,
        local_port: int,
        message_count: int = -1,
        message_delay: int = 1,
    ):
        """
        Class constructor.
        """

        super().__init__(
            service_name="Daytime",
            local_ip_address=local_ip_address,
            local_port=local_port,
        )

        self._message_count = message_count
        self._message_delay = message_delay

    @override
    def _service(self, *, socket: Socket) -> None:
        """
        Inbound connection handler.
        """

        # Create local copy of this variable.
        message_count = self._message_count

        click.echo(
            "Service TCP Daytime: Sending first message to "
            f"{socket.remote_ip_address}, port {socket.remote_port}."
        )
        socket.send(b"***CLIENT OPEN / SERVICE OPEN***\n")

        while self._run_thread and message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")

            try:
                socket.send(message)
            except OSError as error:
                click.echo(f"Service TCP Daytime: send() error - {error!r}.")
                break

            click.echo(
                f"Service TCP Daytime: Sent {len(message)} bytes of data "
                f"to {socket.remote_ip_address}, port {socket.remote_port}."
            )
            time.sleep(self._message_delay)
            message_count = min(message_count, message_count - 1)

        socket.close()
        click.echo(
            "Service TCP Daytime: Closed connection to "
            f"{socket.remote_ip_address}, port {socket.remote_port}.",
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
    "ip6_host",
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
    "ip4_host",
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
    default=13,
    type=int,
    help="Local port number to be used by the service.",
)
def cli(
    *,
    interface: str,
    mac_address: MacAddress | None,
    ip6_host: Ip6Host | None,
    ip6_gateway: Ip6Address | None,
    ip4_host: Ip4Host | None,
    ip4_gateway: Ip4Address | None,
    local_port: int,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Start TCP Daytime service.
    """

    fd, mtu = initialize_interface(interface)

    if ip6_host:
        ip6_host.gateway = ip6_gateway

    if ip4_host:
        ip4_host.gateway = ip4_gateway

    stack = TcpIpStack(
        fd=fd,
        mtu=mtu,
        mac_address=mac_address,
        ip6_host=ip6_host,
        ip4_host=ip4_host,
    )

    service_ip4 = TcpDaytimeService(
        local_ip_address=ip4_host.address if ip4_host else Ip4Address(),
        local_port=local_port,
    )

    service_ip6 = TcpDaytimeService(
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
