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
This module contains an out-of-process TCP echo client. Unlike
'client__tcp_echo.py' (a subsystem co-resident with the stack), this
example does not boot the stack at all: it connects to a running PyTCP
daemon over its AF_UNIX control socket and opens a TCP socket through
'pytcp.client', exactly the way a normal process talks to the kernel.

Start the daemon first (it owns the TAP interface):

    sudo make tap7 && sudo make bridge
    make daemon            # examples_legacy/stack.py --ipc-socket /tmp/pytcp.sock

then run this client against a remote echo server:

    make client_tcp_echo_ipc REMOTE=10.0.1.1

examples_legacy/client__tcp_echo_ipc.py

ver 3.0.8
"""

import time
from typing import cast

import click
from examples_legacy.lib.payload import payload

from net_addr import ClickTypeIpAddress, Ip4Address, Ip6Address
from pytcp.client import ClientTcpSocket, connect
from pytcp.runtime.socket import AddressFamily, SocketType


@click.command()
@click.option(
    "--ipc-socket",
    "ipc_socket",
    default="/tmp/pytcp.sock",
    show_default=True,
    help="AF_UNIX control socket the PyTCP daemon listens on.",
)
@click.option(
    "--count",
    "-c",
    "message_count",
    type=click.IntRange(1),
    default=4,
    show_default=True,
    help="Number of messages to send.",
)
@click.option(
    "--delay",
    "-d",
    "message_delay",
    type=click.FloatRange(0),
    default=1.0,
    show_default=True,
    help="Delay between messages in seconds.",
)
@click.option(
    "--size",
    "-s",
    "message_size",
    type=click.IntRange(0),
    default=64,
    show_default=True,
    help="Size of the payload in bytes.",
)
@click.argument(
    "remote_ip_address",
    type=ClickTypeIpAddress(),
    required=True,
)
@click.argument(
    "remote_port",
    type=click.IntRange(1, 65535),
    default=7,
    required=False,
)
def cli(
    *,
    ipc_socket: str,
    message_count: int,
    message_delay: float,
    message_size: int,
    remote_ip_address: Ip6Address | Ip4Address,
    remote_port: int,
) -> None:
    """
    Echo 'count' messages off a remote TCP server, through a running
    PyTCP daemon, without booting the stack in this process.
    """

    family = AddressFamily.INET6 if isinstance(remote_ip_address, Ip6Address) else AddressFamily.INET4
    message = payload(length=message_size)

    with connect(socket_path=ipc_socket) as client:
        sock = cast(ClientTcpSocket, client.socket(family, SocketType.STREAM))
        sock.connect((str(remote_ip_address), remote_port))
        click.echo(f"Connected to {remote_ip_address}, port {remote_port} (via daemon {ipc_socket}).")

        try:
            for index in range(message_count):
                sock.send(message)
                click.echo(f"Sent {len(message)} bytes ({index + 1}/{message_count}).")
                echo = sock.recv(len(message))
                if not echo:
                    click.echo("Remote closed the connection.")
                    break
                click.echo(f"Received {len(echo)} bytes back.")
                time.sleep(message_delay)
        finally:
            sock.close()
            click.echo("Closed the connection.")


if __name__ == "__main__":
    cli.main()
