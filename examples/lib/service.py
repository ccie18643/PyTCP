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
The 'user space' generic service base class used in examples.

examples/lib/service.py

ver 3.0.2
"""


from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import click
from net_addr.ip_address import IpAddress

from pytcp.socket import AF_INET4, AF_INET6, SOCK_DGRAM, SOCK_STREAM, socket

if TYPE_CHECKING:
    from pytcp.socket.socket import Socket


class Service(ABC):
    """
    Generic service support class.
    """

    _protocol_name: str
    _service_name: str
    _local_ip_address: IpAddress
    _local_port: int
    _run_thread: bool

    def start(self) -> None:
        """
        Start the service thread.
        """

        click.echo(
            f"Starting the {self._protocol_name} {self._service_name} service."
        )
        self._run_thread = True
        threading.Thread(target=self._thread__service).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop the service thread.
        """

        click.echo(
            f"Stopinging the {self._protocol_name} {self._service_name} service."
        )
        self._run_thread = False
        time.sleep(0.1)

    def _get_service_socket(self) -> Socket | None:
        """
        Create and bind the service socket.
        """

        match self._local_ip_address.version, self._protocol_name:
            case 6, "TCP":
                service_socket = socket(family=AF_INET6, type=SOCK_STREAM)
            case 4, "TCP":
                service_socket = socket(family=AF_INET4, type=SOCK_STREAM)
            case 6, "UDP":
                service_socket = socket(family=AF_INET6, type=SOCK_DGRAM)
            case 4, "UDP":
                service_socket = socket(family=AF_INET4, type=SOCK_DGRAM)

        try:
            service_socket.bind((str(self._local_ip_address), self._local_port))
            click.echo(
                f"Service {self._protocol_name} {self._service_name}: Socket created, "
                f"bound to {self._local_ip_address}, port {self._local_port}."
            )

        except OSError as error:
            click.echo(
                f"Service {self._protocol_name} {self._service_name}: bind() call "
                f"failed - {error!r}."
            )
            return None

        return service_socket

    @abstractmethod
    def _thread__service(self) -> None:
        """
        Service thread.
        """

        raise NotImplementedError

    @abstractmethod
    def _service(self, *, socket: Socket) -> None:
        """
        Service logic handler.
        """

        raise NotImplementedError
