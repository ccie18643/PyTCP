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
This module contains the 'user space' generic service base class used in examples.

examples/lib/service.py

ver 3.0.3
"""


from __future__ import annotations

import threading
from abc import abstractmethod
from typing import TYPE_CHECKING, override

from net_addr.ip_address import IpAddress

from examples.lib.subsystem import Subsystem

if TYPE_CHECKING:
    from pytcp.socket.socket import Socket


class Service(Subsystem):
    """
    Generic service class.
    """

    _protocol_name: str
    _service_name: str
    _local_ip_address: IpAddress
    _local_port: int

    _event__stop_subsystem: threading.Event

    @override
    def start(self) -> None:
        """
        Start the service.
        """

        self._log("Starting the service.")

        self._event__stop_subsystem.clear()

        threading.Thread(target=self._thread__service).start()

    @override
    def stop(self) -> None:
        """
        Stop the service thread.
        """

        self._log("Stopping the service.")

        self._event__stop_subsystem.set()

    def _get_service_socket(self) -> Socket | None:
        """
        Create and bind the service socket.
        """

        service_socket = self._get_subsystem_socket(
            ip_version=self._local_ip_address.version,
            protocol_name=self._protocol_name,
        )

        try:
            service_socket.bind((str(self._local_ip_address), self._local_port))
            self._log(
                f"Socket created, bound to {self._local_ip_address}, port {self._local_port}."
            )

        except OSError as error:
            self._log(f"The bind() call failed - {error!r}.")
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
