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
This module contains the example 'user space' service TCP Echo (RFC 862).

examples_legacy/service__tcp_echo.py

ver 3.0.8
"""

import threading
from typing import Any, override

import click
from examples_legacy.lib.malpi import malpa, malpi, malpka
from examples_legacy.lib.service import build_echo_services
from examples_legacy.lib.tcp_service import TcpService
from examples_legacy.stack import cli as stack_cli

from net_addr import IpAddress
from pytcp.runtime.socket import socket


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
    def _service(self, *, socket: socket) -> None:
        """
        Service logic handler.
        """

        remote_ip_address, remote_port = socket.getpeername()

        self._log(f"Sending first message to {remote_ip_address}, " f"port {remote_port}.")
        socket.send(b"***CLIENT OPEN / SERVICE OPEN***\n")

        while not self._event__stop_subsystem.is_set():
            try:
                message = socket.recv(timeout=1)
            except TimeoutError:
                continue

            if not message:
                self._log(f"Connection to {remote_ip_address}, port {remote_port} has been closed by peer.")
                self._log(f"Sending last message to {remote_ip_address}, port {remote_port}.")
                socket.send(b"***CLIENT CLOSED, SERVICE CLOSING***\n")
                self._log(f"Closing connection to {remote_ip_address}, port {remote_port}.")
                socket.close()
                break

            if message.strip().lower() in {b"quit", b"close", b"bye", b"exit"}:
                self._log(f"Sending last message to {remote_ip_address}, port {remote_port}.")
                socket.send(b"***CLIENT OPEN, SERVICE CLOSING***\n")
                self._log(f"Closing connection to {remote_ip_address}, port {remote_port}.")
                socket.close()
                continue

            if __debug__:
                self._log(f"Received {len(message)} bytes from {remote_ip_address}, port {remote_port}.")

            if b"malpka" in message.strip().lower():
                message = malpka

            elif b"malpa" in message.strip().lower():
                message = malpa

            elif b"malpi" in message.strip().lower():
                message = malpi

            if socket.send(message):
                if __debug__:
                    self._log(f"Sent {len(message)} bytes back to {remote_ip_address}, port {remote_port}.")


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
    /,
    *,
    local_port: int,
    **kwargs: Any,
) -> None:
    """
    Start TCP Echo service.
    """

    ctx.invoke(
        stack_cli,
        subsystems=build_echo_services(
            TcpEchoService,
            local_port=local_port,
            ip4_support=kwargs["stack__ip4_support"],
            ip4_host=kwargs["stack__ip4_host"],
            ip6_support=kwargs["stack__ip6_support"],
            ip6_host=kwargs["stack__ip6_host"],
        ),
        **kwargs,
    )


if __name__ == "__main__":
    cli.help = (cli.help or "").rstrip() + (stack_cli.help or "")
    cli.params += stack_cli.params
    cli.main()
