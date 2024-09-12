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
from typing import TYPE_CHECKING, override

import click

from examples.lib.service import Service

if TYPE_CHECKING:
    from pytcp.socket.socket import Socket


class TcpService(Service):
    """
    TCP service support class.
    """

    _protocol_name = "TCP"

    @override
    def _thread__service(self) -> None:
        """
        Service thread.
        """

        if listening_socket := self._get_service_socket():
            listening_socket.listen()
            click.echo(
                f"Service {self._protocol_name} {self._service_name}: Socket "
                "set to listening mode."
            )
            while True:
                connected_socket, _ = listening_socket.accept()
                remote_ip_address, remote_port = connected_socket.getpeername()
                click.echo(
                    f"Service {self._protocol_name} {self._service_name}: Inbound "
                    f"connection received from {remote_ip_address}, "
                    f"port {remote_port}."
                )
                threading.Thread(
                    target=self._thread__service__connection_handler,
                    kwargs={"connected_socket": connected_socket},
                ).start()

    def _thread__service__connection_handler(
        self, *, connected_socket: Socket
    ) -> None:
        """
        Inbound connection handler.
        """

        self._service(socket=connected_socket)
