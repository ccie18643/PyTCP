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
The example 'user space' service TCP Echo (RFC 862).

examples/tcp_echo_service.py

ver 3.0.2
"""


from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, override

import click

from examples.lib.malpi import malpa, malpi, malpka
from examples.lib.tcp_service import TcpService
from examples.stack import cli as stack_cli
from net_addr import (
    Ip4Address,
    Ip6Address,
    IpAddress,
)

if TYPE_CHECKING:
    from pytcp.socket.socket import Socket


class TcpEchoService(TcpService):
    """
    TCP Echo service support class.
    """

    _subsystem_name = f"{TcpService._protocol_name} Echo Service"

    _event__stop_subsystem: threading.Event

    def __init__(self, *, local_ip_address: IpAddress, local_port: int):
        """
        Class constructor.
        """

        self._local_ip_address = local_ip_address
        self._local_port = local_port

        super().__init__()

    @override
    def _service(self, *, socket: Socket) -> None:
        """
        Service logic handler.
        """

        remote_ip_address, remote_port = socket.getpeername()

        self._log(
            f"Sending first message to {remote_ip_address}, "
            f"port {remote_port}."
        )
        socket.send(b"***CLIENT OPEN / SERVICE OPEN***\n")

        while not self._event__stop_subsystem.is_set():
            if not (message := socket.recv()):
                self._log(
                    f"Connection to {remote_ip_address}, port {remote_port} has been closed by peer."
                )
                self._log(
                    f"Sending last message to {remote_ip_address}, port {remote_port}."
                )
                socket.send(b"***CLIENT CLOSED, SERVICE CLOSING***\n")
                self._log(
                    f"Closing connection to {remote_ip_address}, port {remote_port}."
                )
                socket.close()
                break

            if message.strip().lower() in {b"quit", b"close", b"bye", b"exit"}:
                self._log(
                    f"Sending last message to {remote_ip_address}, port {remote_port}."
                )
                socket.send(b"***CLIENT OPEN, SERVICE CLOSING***\n")
                self._log(
                    f"Closing connection to {remote_ip_address}, port {remote_port}."
                )
                socket.close()
                continue

            self._log(
                f"Received {len(message)} bytes from {remote_ip_address}, port {remote_port}."
            )

            if b"malpka" in message.strip().lower():
                message = malpka

            elif b"malpa" in message.strip().lower():
                message = malpa

            elif b"malpi" in message.strip().lower():
                message = malpi

            if socket.send(message):
                self._log(
                    f"Sent {len(message)} bytes back to {remote_ip_address}, port {remote_port}."
                )


@click.command()
@click.option(
    "--local-port",
    default=7,
    type=int,
    help="Local port number to be used by the service.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    *,
    local_port: int,
    **kwargs: Any,
) -> None:
    """
    Start ICMP Echo service.
    """

    ctx.invoke(
        stack_cli,
        subsystems=[
            TcpEchoService(
                local_ip_address=(
                    kwargs["stack__ip6_host"].address
                    if kwargs["stack__ip6_host"]
                    else Ip6Address()
                ),
                local_port=local_port,
            ),
            TcpEchoService(
                local_ip_address=(
                    kwargs["stack__ip4_host"].address
                    if kwargs["stack__ip4_host"]
                    else Ip4Address()
                ),
                local_port=local_port,
            ),
        ],
        **kwargs,
    )


if __name__ == "__main__":
    cli.help = (cli.help or "").rstrip() + (stack_cli.help or "")
    cli.params += stack_cli.params
    cli.main()
