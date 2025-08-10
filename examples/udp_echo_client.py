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
from typing import Any
import click
from examples.lib.client import Client
from net_addr import (
    ClickTypeIpAddress,
    Ip4Address,
    Ip6Address,
)
from run_stack import cli as stack_cli


class UdpEchoClient(Client):
    """
    UDP Echo client support class.
    """

    _protocol_name = "UDP"
    _client_name = "Echo"

    def __init__(
        self,
        *,
        remote_ip_address: Ip6Address | Ip4Address,
        local_port: int = 0,
        remote_port: int = 7,
        message_count: int = -1,
        message_delay: int = 1,
        message_size: int = 5,
    ) -> None:
        """
        Class constructor.
        """

        self._remote_ip_address = remote_ip_address
        self._local_port = local_port
        self._remote_port = remote_port
        self._message_count = message_count
        self._message_delay = message_delay
        self._message_size = message_size
        self._run_thread = False

    def _thread__client__sender(self) -> None:
        """
        Client thread used to send data.
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
@click.argument(
    "remote_ip_address",
    type=ClickTypeIpAddress(),
    required=True,
)
@click.argument(
    "remote_port",
    type=click.IntRange(1, 65535),
    default=7,
)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    remote_ip_address: Ip6Address | Ip4Address,
    remote_port: int,
    **kwargs: Any,
) -> None:
    """
    Start UDP Echo client.
    """

    ctx.invoke(
        stack_cli,
        subsystem=UdpEchoClient(
            remote_ip_address=remote_ip_address, remote_port=remote_port
        ),
        **kwargs,
    )


if __name__ == "__main__":
    cli.help = (cli.help or "").rstrip() + (stack_cli.help or "")
    cli.params += stack_cli.params
    cli.main()
