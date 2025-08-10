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
The example 'user space' service UDP Echo (RFC 862).

examples/udp_echo.py

ver 3.0.2
"""


from __future__ import annotations

from typing import TYPE_CHECKING, override

import click

from examples.lib.malpi import malpa, malpi, malpka
from examples.lib.udp_service import UdpService
from net_addr import (
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
from pytcp import stack

if TYPE_CHECKING:
    from pytcp.socket.socket import Socket


class UdpEchoService(UdpService):
    """
    UDP Echo service support class.
    """

    def __init__(self, *, local_ip_address: IpAddress, local_port: int):
        """
        Class constructor.
        """

        self._service_name = "Echo"
        self._local_ip_address = local_ip_address
        self._local_port = local_port

    @override
    def _service(self, *, socket: Socket) -> None:
        """
        Service logic handler.
        """

        while self._run_thread:
            message, remote_address = socket.recvfrom()

            click.echo(
                f"Service UDP Echo: Received {len(message)} bytes from "
                f"{remote_address[0]}, port {remote_address[1]}."
            )

            if b"malpka" in message.strip().lower():
                message = malpka
            elif b"malpa" in message.strip().lower():
                message = malpa
            elif b"malpi" in message.strip().lower():
                message = malpi

            socket.sendto(message, remote_address)

            click.echo(
                f"Service UDP Echo: Echo'ed {len(message)} bytes back to "
                f"{remote_address[0]}, port {remote_address[1]}."
            )


@click.command()
@click.option(
    "--stack-interface",
    "stack__interface",
    default="tap7",
    help="Name of the interface to be used by the stack.",
)
@click.option(
    "--stack-mac-address",
    "stack__mac_address",
    type=ClickTypeMacAddress(),
    default=None,
    help="MAC address to be assigned to the interface.",
)
@click.option(
    "--stack-ip6-address",
    "stack__ip6_host",
    type=ClickTypeIp6Host(),
    default=None,
    help="IPv6 address/mask to be assigned to the interface.",
)
@click.option(
    "--stack-ip6-gateway",
    "stack__ip6_gateway",
    type=ClickTypeIp6Address(),
    default=None,
    help="IPv6 gateway address to be assigned to the interface.",
)
@click.option(
    "--stack-ip4-address",
    "stack__ip4_host",
    type=ClickTypeIp4Host(),
    default=None,
    help="IPv4 address/mask to be assigned to the interface.",
)
@click.option(
    "--stack-ip4-gateway",
    "stack__ip4_gateway",
    type=ClickTypeIp4Address(),
    default=None,
    help="IPv4 gateway address to be assigned to the interface.",
)
@click.option(
    "--stack-no-ip6",
    "stack__ip6_support",
    is_flag=True,
    default=True,
    help="Do not listen on IPv6 address.",
)
@click.option(
    "--stack-no-ip4",
    "stack__ip4_support",
    is_flag=True,
    default=True,
    help="Do not listen on IPv4 address.",
)
@click.option(
    "--local-port",
    default=7,
    type=int,
    help="Local port number to be used by the service.",
)
def cli(
    *,
    stack__interface: str,
    stack__mac_address: MacAddress | None,
    stack__ip6_host: Ip6Host | None,
    stack__ip6_gateway: Ip6Address | None,
    stack__ip4_host: Ip4Host | None,
    stack__ip4_gateway: Ip4Address | None,
    stack__ip6_support: bool,
    stack__ip4_support: bool,
    local_port: int,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Start TCP Echo service.
    """

    if stack__ip6_host:
        stack__ip6_host.gateway = stack__ip6_gateway

    if stack__ip4_host:
        stack__ip4_host.gateway = stack__ip4_gateway

    stack.init(
        *stack.initialize_interface(stack__interface),
        mac_address=stack__mac_address,
        ip6_host=stack__ip6_host,
        ip4_host=stack__ip4_host,
        ip6_support=stack__ip6_support,
        ip4_support=stack__ip4_support,
    )

    stack.start()

    service__ip6: UdpEchoService | None = None
    service__ip4: UdpEchoService | None = None

    if stack__ip6_support:
        service__ip6 = UdpEchoService(
            local_ip_address=(
                stack__ip6_host.address if stack__ip6_host else Ip6Address()
            ),
            local_port=local_port,
        )
        service__ip6.start()

    if stack__ip4_support:
        service__ip4 = UdpEchoService(
            local_ip_address=(
                stack__ip4_host.address if stack__ip4_host else Ip4Address()
            ),
            local_port=local_port,
        )
        service__ip4.start()

    try:
        next
    finally:
        if service__ip6:
            service__ip6.stop()

        if service__ip4:
            service__ip4.stop()

        stack.stop()


if __name__ == "__main__":
    cli()  # pylint: disable = missing-kwoa
