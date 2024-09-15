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
The example 'user space' client for UDP echo. It actively sends messages
to the UDP Echo service.

examples/udp_echo_client.py

ver 3.0.2
"""


from __future__ import annotations

import time

import click

from examples.lib.client import Client
from net_addr import (
    ClickTypeIp4Address,
    ClickTypeIp4Host,
    ClickTypeIp6Address,
    ClickTypeIp6Host,
    ClickTypeIpAddress,
    ClickTypeMacAddress,
    Ip4Address,
    Ip4Host,
    Ip6Address,
    Ip6Host,
    IpAddress,
    MacAddress,
)
from pytcp import stack


class UdpEchoClient(Client):
    """
    UDP Echo client support class.
    """

    _protocol_name = "UDP"
    _client_name = "Echo"

    def __init__(
        self,
        *,
        local_ip_address: IpAddress,
        remote_ip_address: IpAddress,
        local_port: int = 0,
        remote_port: int = 7,
        message_count: int = -1,
        message_delay: int = 1,
        message_size: int = 5,
    ) -> None:
        """
        Class constructor.
        """

        self._local_ip_address = local_ip_address
        self._remote_ip_address = remote_ip_address
        self._local_port = local_port
        self._remote_port = remote_port
        self._message_count = message_count
        self._message_delay = message_delay
        self._message_size = message_size
        self._run_thread = False

    def _thread__client(self) -> None:
        """
        Client thread.
        """

        if client_socket := self._get_client_socket():
            message_count = self._message_count

            while self._run_thread and message_count:
                message = "[------START------] "
                for i in range(self._message_size - 2):
                    message += f"[------{i + 1:05}------] "
                message += "[-------END-------]\n"

                try:
                    client_socket.send(bytes(message, "utf-8"))
                except OSError as error:
                    click.echo(f"Client UDP Echo: send() error - {error!r}.")
                    break

                click.echo(
                    f"Client UDP Echo: Sent {len(message)} bytes of data to "
                    f"{self._remote_ip_address}, port {self._remote_port}."
                )
                time.sleep(self._message_delay)
                message_count = min(message_count, message_count - 1)

            client_socket.close()
            click.echo(
                "Client UDP Echo: Closed connection to "
                f"{self._remote_ip_address}, port {self._remote_port}.",
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
    "--remote-ip-address",
    type=ClickTypeIpAddress(),
    required=True,
    help="Remote IP address of the UDP Echo server.",
)
def cli(
    *,
    interface: str,
    mac_address: MacAddress | None,
    ip6_host: Ip6Host | None,
    ip6_gateway: Ip6Address | None,
    ip4_host: Ip4Host | None,
    ip4_gateway: Ip4Address | None,
    remote_ip_address: IpAddress,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Start UDP Echo client.
    """

    if ip6_host:
        ip6_host.gateway = ip6_gateway

    if ip4_host:
        ip4_host.gateway = ip4_gateway

    stack.init(
        *stack.initialize_interface(interface),
        mac_address=mac_address,
        ip6_host=ip6_host,
        ip4_host=ip4_host,
    )

    match remote_ip_address.version:
        case 6:
            client = UdpEchoClient(
                local_ip_address=ip6_host.address if ip6_host else Ip6Address(),
                remote_ip_address=remote_ip_address,
            )
        case 4:
            client = UdpEchoClient(
                local_ip_address=ip4_host.address if ip4_host else Ip4Address(),
                remote_ip_address=remote_ip_address,
            )

    try:
        stack.start()
        client.start()
        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        client.stop()
        stack.stop()


if __name__ == "__main__":
    cli()  # pylint: disable = missing-kwoa
