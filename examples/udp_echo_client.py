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


# pylint: disable = too-many-instance-attributes

"""
The example 'user space' client for UDP echo. It actively sends messages
to the UDP Echo service.

examples/udp_echo_client.py

ver 2.7
"""


from __future__ import annotations

import threading
import time

import click

from pytcp import TcpIpStack
from pytcp.lib import socket
from pytcp.lib.ip_helper import ip_version


class UdpEchoClient:
    """
    UDP Echo client support class.
    """

    def __init__(
        self,
        *,
        local_ip_address: str = "0.0.0.0",
        remote_ip_address: str,
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

        click.echo("Starting the UDP Echo client.")
        self._run_thread = True
        threading.Thread(target=self.__thread_client).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop the service thread.
        """

        click.echo("Stopinging the UDP Echo client.")
        self._run_thread = False
        time.sleep(0.1)

    def __thread_client(self) -> None:
        version = ip_version(self._local_ip_address)
        if version == 6:
            client_socket = socket.socket(
                family=socket.AF_INET6, type=socket.SOCK_DGRAM
            )
        elif version == 4:
            client_socket = socket.socket(
                family=socket.AF_INET4, type=socket.SOCK_DGRAM
            )
        else:
            click.echo(
                f"Client UDP Echo: Invalid local IP address - {self._local_ip_address}."
            )
            return

        click.echo(f"Client UDP Echo: Created socket [{client_socket}].")

        try:
            client_socket.bind((self._local_ip_address, self._local_port))
            click.echo(
                "Client UDP Echo: Bound socket to "
                f"{self._local_ip_address}, port {self._local_port}."
            )
        except OSError as error:
            click.echo(
                "Client UDP Echo: Unable to bind socket to "
                f"{self._local_ip_address}, port {self._local_port} - {error!r}.",
            )
            return

        try:
            client_socket.connect((self._remote_ip_address, self._remote_port))
            click.echo(
                f"Client UDP Echo: Connection opened to "
                f"{self._remote_ip_address}, port {self._remote_port}."
            )
        except OSError as error:
            click.echo(
                f"Client UDP Echo: Connection to {self._remote_ip_address}, "
                f"port {self._remote_port} failed - {error!r}."
            )
            return

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
@click.option("--interface", default="tap7")
@click.argument("remote_ip_address")
def cli(*, interface: str, remote_ip_address: str) -> None:
    """
    Start PyTCP stack and stop it when user presses Ctrl-C.
    Run the TCP Echo client.
    """

    stack = TcpIpStack(interface=interface)
    client = UdpEchoClient(
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
