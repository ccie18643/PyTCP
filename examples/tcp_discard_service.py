#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# examples/tcp_discard_service.py - The 'user space' service TCP Discard (RFC 863).
#
# ver 2.7
#


from __future__ import annotations

import time
from typing import TYPE_CHECKING

import click

from examples.tcp_service import TcpService
from pytcp import TcpIpStack

if TYPE_CHECKING:
    from pytcp.lib.socket import Socket


class TcpDiscardService(TcpService):
    """
    TCP Discard service support class.
    """

    def __init__(
        self, *, local_ip_address: str = "0.0.0.0", local_port: int = 9
    ):
        """
        Class constructor.
        """
        super().__init__(
            service_name="Discard",
            local_ip_address=local_ip_address,
            local_port=local_port,
        )

    def service(self, *, connected_socket: Socket) -> None:
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

            if message.strip().lower() in {b"quit", b"close", b"bye"}:
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
@click.option("--interface", default="tap7")
def cli(*, interface: str) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Run the TCP Discard service.
    """

    stack = TcpIpStack(interface)
    service = TcpDiscardService()

    try:
        stack.start()
        service.start()
        while True:
            time.sleep(60)

    except KeyboardInterrupt:
        service.stop()
        stack.stop()


if __name__ == "__main__":
    cli()
