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
The example 'user space' client for UDP Echo protocol. It actively sends the UDP
packets to the remote IP address/port and waits for responses.

examples/client__udp_echo.py

ver 3.0.2
"""


from __future__ import annotations

import time
from typing import Any, override

import click

from examples.lib.client import Client
from examples.lib.payload import payload
from examples.stack import cli as stack_cli
from net_addr import (
    ClickTypeIpAddress,
    Ip4Address,
    Ip6Address,
)
from pytcp.socket.socket import ReceiveTimeout


class UdpEchoClient(Client):
    """
    UDP Echo client support class.
    """

    _protocol_name = "UDP"
    _subsystem_name = f"{_protocol_name} Echo Client"

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

    @override
    def _thread__client__sender(self) -> None:
        """
        Client thread used to send data.
        """

        if client_socket := self._client_socket:
            message_payload = payload(length=self._message_size)
            message_count = self._message_count

            while self._run_thread and message_count:
                try:
                    client_socket.send(message_payload)
                except OSError as error:
                    self._log(f"The 'send()' method failed. Error: {error!r}.")
                    break

                self._log(
                    f"Sent {len(message_payload)} bytes of data to "
                    f"{self._remote_ip_address}, port {self._remote_port}."
                )
                message_count = min(message_count, message_count - 1)
                time.sleep(self._message_delay)

            client_socket.close()
            self._log(
                f"Closed the connection to {self._remote_ip_address}, port {self._remote_port}."
            )

            self._run_thread = False
            self._log("Stopped the sender thread.")

    @override
    def _thread__client__receiver(self) -> None:
        """
        Client thread used to receive data.
        """

        if self._client_socket:
            self._log("Started the receiver thread.")

            while self._run_thread:
                try:
                    if message_payload := self._client_socket.recv(
                        bufsize=1024,
                        timeout=1,
                    ):
                        self._log(
                            f"Received {len(message_payload)} bytes from '{self._remote_ip_address}'."
                        )
                except ReceiveTimeout:
                    pass

            self._log("Stopped the receiver thread.")


@click.command()
@click.option(
    "--count",
    "-c",
    "message_count",
    type=click.IntRange(-1),
    default=-1,
    help="Number of messages to send.",
)
@click.option(
    "--delay",
    "-d",
    "message_delay",
    type=click.IntRange(0),
    default=1,
    help="Delay between messages in seconds.",
    show_default=True,
)
@click.option(
    "--size",
    "-s",
    "message_size",
    type=click.IntRange(0),
    default=64,
    help="Size of the payload in bytes.",
    show_default=True,
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
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    message_count: int,
    message_delay: int,
    message_size: int,
    remote_ip_address: Ip6Address | Ip4Address,
    remote_port: int,
    **kwargs: Any,
) -> None:
    """
    Start ICMP Echo client.
    """

    ctx.invoke(
        stack_cli,
        subsystem=UdpEchoClient(
            remote_ip_address=remote_ip_address,
            remote_port=remote_port,
            message_count=message_count,
            message_delay=message_delay,
            message_size=message_size,
        ),
        **kwargs,
    )


if __name__ == "__main__":
    cli.help = (cli.help or "").rstrip() + (stack_cli.help or "")
    cli.params += stack_cli.params
    cli.main()
