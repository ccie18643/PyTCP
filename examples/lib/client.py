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
The 'user space' generic client base class used in examples.

examples/lib/client.py

ver 3.0.2
"""


from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import click

from pytcp.lib import socket
from pytcp.lib.net_addr.ip_address import IpAddress

if TYPE_CHECKING:
    from pytcp.lib.socket import Socket


class Client(ABC):
    """
    Generic client support class.
    """

    _protocol_name: str
    _client_name: str
    _local_ip_address: IpAddress
    _local_port: int
    _remote_ip_address: IpAddress
    _remote_port: int
    _run_thread: bool

    def start(self) -> None:
        """
        Start the service thread.
        """

        click.echo(
            f"Starting the {self._protocol_name} {self._client_name} service."
        )
        self._run_thread = True
        threading.Thread(target=self._thread__client).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop the service thread.
        """

        click.echo(
            f"Stopping the {self._protocol_name} {self._client_name} service."
        )
        self._run_thread = False
        time.sleep(0.1)

    def _get_client_socket(self) -> Socket | None:
        """
        Create and bind the client socket.
        """

        match (
            self._local_ip_address.version,
            self._remote_ip_address.version,
            self._protocol_name,
        ):
            case 6, 6, "TCP":
                client_socket = socket.socket(
                    family=socket.AF_INET6, type=socket.SOCK_STREAM
                )
            case 4, 4, "TCP":
                client_socket = socket.socket(
                    family=socket.AF_INET4, type=socket.SOCK_STREAM
                )
            case 6, 6, "UDP":
                client_socket = socket.socket(
                    family=socket.AF_INET6, type=socket.SOCK_DGRAM
                )
            case 4, 4, "UDP":
                client_socket = socket.socket(
                    family=socket.AF_INET4, type=socket.SOCK_DGRAM
                )
            case _:
                raise ValueError("Invalid IP version or protocol.")

        click.echo(
            f"Client {self._protocol_name} {self._client_name}: "
            f"Created socket [{client_socket}]."
        )

        try:
            client_socket.bind((str(self._local_ip_address), self._local_port))
            click.echo(
                f"Client {self._protocol_name} {self._client_name}: Bound socket "
                f"to {self._local_ip_address}, port {self._local_port}."
            )
        except OSError as error:
            click.echo(
                f"Client {self._protocol_name} {self._client_name}: Unable to bind socket "
                f"to {self._local_ip_address}, port {self._local_port} - {error!r}.",
            )
            return None

        try:
            client_socket.connect(
                (str(self._remote_ip_address), self._remote_port)
            )
            click.echo(
                f"Client {self._protocol_name} {self._client_name}: Connection opened "
                f"to {self._remote_ip_address}, port {self._remote_port}."
            )
        except OSError as error:
            click.echo(
                f"Client {self._protocol_name} {self._client_name}: Connection to "
                f"{self._remote_ip_address}, port {self._remote_port} failed - {error!r}."
            )
            return None

        return client_socket

    @abstractmethod
    def _thread__client(self) -> None:
        """
        Client thread.
        """

        raise NotImplementedError
