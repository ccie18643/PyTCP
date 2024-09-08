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
The 'user space' TCP generic service class used in examples.

examples/lib/tcp_service.py

ver 3.0.2
"""


from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import click

from pytcp.lib import socket
from pytcp.lib.net_addr.ip_address import IpAddress

if TYPE_CHECKING:
    from pytcp.lib.socket import Socket


class TcpService:
    """
    TCP service support class.
    """

    def __init__(
        self, *, service_name: str, local_ip_address: IpAddress, local_port: int
    ) -> None:
        """
        Class constructor.
        """

        self._service_name = service_name
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        self._run_thread = False

    def start(self) -> None:
        """
        Start the service thread.
        """

        click.echo(f"Starting the TCP {self._service_name} service.")
        self._run_thread = True
        threading.Thread(target=self.__thread__service).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop the service thread.
        """

        click.echo(f"Stopinging the TCP {self._service_name} service.")
        self._run_thread = False
        time.sleep(0.1)

    def __thread__service(self) -> None:
        """
        Service initialization.
        """

        match self._local_ip_address.version:
            case 6:
                listening_socket = socket.socket(
                    family=socket.AF_INET6, type=socket.SOCK_STREAM
                )
            case 4:
                listening_socket = socket.socket(
                    family=socket.AF_INET4, type=socket.SOCK_STREAM
                )

        try:
            listening_socket.bind(
                (str(self._local_ip_address), self._local_port)
            )
            click.echo(
                f"Service TCP {self._service_name}: Socket created, bound to "
                f"{self._local_ip_address}, port {self._local_port}."
            )

        except OSError as error:
            click.echo(
                f"Service TCP {self._service_name}: bind() call failed - {error!r}."
            )
            return

        listening_socket.listen()
        click.echo(
            f"Service TCP {self._service_name}: Socket set to listening mode."
        )

        while True:
            connected_socket, _ = listening_socket.accept()
            click.echo(
                f"Service TCP {self._service_name}: Inbound connection received from "
                f"{connected_socket.remote_ip_address}, port {connected_socket.remote_port}."
            )
            threading.Thread(
                target=self.__thread__service__connection_handler,
                kwargs={"connected_socket": connected_socket},
            ).start()

    def __thread__service__connection_handler(
        self, *, connected_socket: Socket
    ) -> None:
        """
        Inbound connection handler.
        """

        self.service(connected_socket=connected_socket)

    def service(self, *, connected_socket: Socket) -> None:
        """
        Service method.
        """

        click.echo(
            f"Service TCP {self._service_name}: No service method defined, "
            "closing connection."
        )
        connected_socket.close()
