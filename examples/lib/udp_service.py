#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyUDP - Python UDP/IP stack                                             #
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
#  Github repository: https://github.com/ccie18643/PyUDP                   #
#                                                                          #
############################################################################


"""
The 'user space' UDP generic service class used in examples.

examples/lib/udp_service.py

ver 2.7
"""


from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

import click

import pytcp.lib.socket as sock
from pytcp.lib.ip_helper import ip_version

if TYPE_CHECKING:
    from pytcp.lib.socket import Socket


class UdpService:
    """
    UDP service support class.
    """

    def __init__(
        self,
        *,
        service_name: str,
        local_ip_address: str,
        local_port: int,
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

        click.echo(f"Starting the UDP {self._service_name} service.")
        self._run_thread = True
        threading.Thread(target=self.__thread_service).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop the service thread.
        """

        click.echo(f"Stopinging the UDP {self._service_name} service.")
        self._run_thread = False
        time.sleep(0.1)

    def __thread_service(self) -> None:
        """
        Service initialization.
        """

        version = ip_version(self._local_ip_address)
        if version == 6:
            listening_socket = sock.socket(
                family=sock.AF_INET6, type=sock.SOCK_DGRAM
            )
        elif version == 4:
            listening_socket = sock.socket(
                family=sock.AF_INET4, type=sock.SOCK_DGRAM
            )
        else:
            click.echo(
                f"Service UDP {self._service_name}: Invalid local IP address - "
                f"{self._local_ip_address}."
            )
            return

        try:
            listening_socket.bind((self._local_ip_address, self._local_port))
            click.echo(
                f"Service UDP {self._service_name}: Socket created, bound to "
                f"{self._local_ip_address}, port {self._local_port}."
            )
        except OSError as error:
            click.echo(
                f"Service UDP {self._service_name}: bind() call failed - {error!r}."
            )
            return

        self.service(listening_socket=listening_socket)

    def service(
        self,
        *,
        listening_socket: Socket,
    ) -> None:
        """
        Service method.
        """

        click.echo(
            f"Service UDP {self._service_name}: No service method defined, "
            "closing connection."
        )
        listening_socket.close()
