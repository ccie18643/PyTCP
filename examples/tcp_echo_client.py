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
The example 'user space' client for TCP echo. It actively connects to
TCP Echo service and sends messages.

examples/tcp_echo_client.py

ver 3.0.2
"""


from __future__ import annotations

import threading
import time

import click

from pytcp import TcpIpStack, initialize_interface
from pytcp.lib import socket
from pytcp.lib.net_addr.click_types import (
    ClickTypeIp4Address,
    ClickTypeIp4Host,
    ClickTypeIp6Address,
    ClickTypeIp6Host,
    ClickTypeIpAddress,
    ClickTypeMacAddress,
)
from pytcp.lib.net_addr.ip4_address import Ip4Address
from pytcp.lib.net_addr.ip4_host import Ip4Host
from pytcp.lib.net_addr.ip6_address import Ip6Address
from pytcp.lib.net_addr.ip6_host import Ip6Host
from pytcp.lib.net_addr.ip_address import IpAddress
from pytcp.lib.net_addr.mac_address import MacAddress


class TcpEchoClient:
    """
    TCP Echo client support class.
    """

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

    def start(self) -> None:
        """
        Start the service thread.
        """

        click.echo("Starting the TCP Echo client.")
        self._run_thread = True
        threading.Thread(target=self.__thread__client).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop the service thread.
        """

        click.echo("Stopinging the TCP Echo client.")
        self._run_thread = False
        time.sleep(0.1)

    def __thread__client(self) -> None:
        """
        Client thread.
        """

        match self._local_ip_address.version:
            case 6:
                client_socket = socket.socket(
                    family=socket.AF_INET6, type=socket.SOCK_STREAM
                )
            case 4:
                client_socket = socket.socket(
                    family=socket.AF_INET4, type=socket.SOCK_STREAM
                )

        click.echo(f"Client TCP Echo: Created socket [{client_socket}].")

        try:
            client_socket.bind((str(self._local_ip_address), self._local_port))
            click.echo(
                "Client TCP Echo: Bound socket to "
                f"{self._local_ip_address}, port {self._local_port}."
            )
        except OSError as error:
            click.echo(
                "Client TCP Echo: Unable to bind socket to "
                f"{self._local_ip_address}, port {self._local_port} - "
                f"{error!r}.",
            )
            return

        try:
            client_socket.connect(
                (str(self._remote_ip_address), self._remote_port)
            )
            click.echo(
                "Client TCP Echo: Connection opened to "
                f"{self._remote_ip_address}, port {self._remote_port}."
            )
        except OSError as error:
            click.echo(
                f"Client TCP Echo: Connection to {self._remote_ip_address}, "
                f"port {self._remote_port} failed - {error!r}."
            )
            return

        message_count = self._message_count
        while message_count:
            message = "[------START------] "
            for i in range(self._message_size - 2):
                message += f"[------{i + 1:05}------] "
            message += "[-------END-------]\n"

            try:
                client_socket.send(bytes(message, "utf-8"))
            except OSError as error:
                click.echo(f"Client TCP Echo: send() error - {error!r}.")
                break

            click.echo(
                f"Client TCP Echo: Sent {len(message)} bytes of data to "
                f"{self._remote_ip_address}, port {self._remote_port}."
            )
            time.sleep(self._message_delay)
            message_count = min(message_count, message_count - 1)

        client_socket.close()
        click.echo(
            "Client TCP Echo: Closed connection to "
            f"{self._remote_ip_address}, port {self._remote_port}."
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
    "--remote-ip-address",
    type=ClickTypeIpAddress(),
    required=True,
    help="Remote IP address of the TCP Echo server.",
)
def cli(
    *,
    interface: str,
    mac_address: MacAddress | None,
    ip6_address: Ip6Host | None,
    ip6_gateway: Ip6Address | None,
    ip4_address: Ip4Host | None,
    ip4_gateway: Ip4Address | None,
    remote_ip_address: IpAddress,
) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Start TCP Echo client.
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

    match remote_ip_address.version:
        case 6:
            client = TcpEchoClient(
                local_ip_address=ip6_host.address if ip6_host else Ip6Address(),
                remote_ip_address=remote_ip_address,
            )
        case 4:
            client = TcpEchoClient(
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
