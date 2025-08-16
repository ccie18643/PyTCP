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
This module contains the 'user space' generic client base class used in
the examples.

examples/lib/client.py

ver 3.0.3
"""


from __future__ import annotations

import threading
from abc import abstractmethod
from typing import TYPE_CHECKING, override

from net_addr.ip4_address import Ip4Address
from net_addr.ip6_address import Ip6Address
from net_addr.ip_address import IpVersion

from examples.lib.subsystem import Subsystem
from pytcp.socket import (
    IPPROTO_ICMP4,
    IPPROTO_ICMP6,
)

if TYPE_CHECKING:
    from pytcp.socket.socket import Socket


class Client(Subsystem):
    """
    Generic client class.
    """

    _protocol_name: str
    _subsystem_name: str
    _local_ip_address: Ip4Address | Ip6Address | None
    _local_port: int
    _remote_ip_address: Ip4Address | Ip6Address
    _remote_port: int
    _client_socket: Socket | None

    _event__stop_subsystem: threading.Event

    @override
    def start(self) -> None:
        """
        Start the client.
        """

        self._log("Starting the client.")

        if isinstance(self._remote_ip_address, Ip4Address):
            self._local_ip_address = self.stack_ip4_address
        if isinstance(self._remote_ip_address, Ip6Address):
            self._local_ip_address = self.stack_ip6_address

        try:
            self._client_socket = self._get_client_socket()
        except OSError:
            self._event__stop_subsystem.set()
            return

        self._event__stop_subsystem.clear()

        threading.Thread(target=self._thread__receiver).start()
        threading.Thread(target=self._thread__sender).start()

    @override
    def stop(self) -> None:
        """
        Stop the client.
        """

        self._log("Stopping the client.")

        self._event__stop_subsystem.set()

    def _get_client_socket(self) -> Socket:
        """
        Create and bind the client's socket.
        """

        client_socket = self._get_subsystem_socket(
            ip_version=self._remote_ip_address.version,
            protocol_name=self._protocol_name,
        )

        if self._protocol_name == "ICMP":
            self._local_port = int(
                IPPROTO_ICMP6
                if self._remote_ip_address.version == IpVersion.IP6
                else IPPROTO_ICMP4
            )
            self._remote_port = 0

        try:
            client_socket.bind((str(self._local_ip_address), self._local_port))
            self._log(
                f"Bound socket to {self._local_ip_address}, port {self._local_port}."
            )
        except OSError as error:
            self._log(
                f"Unable to bind socket to {self._local_ip_address}, port {self._local_port}. "
                f"Error: {error!r}.",
            )
            raise error

        try:
            client_socket.connect(
                (str(self._remote_ip_address), self._remote_port)
            )
            self._log(
                f"Connection opened to {self._remote_ip_address}, port {self._remote_port}."
            )
        except OSError as error:
            self._log(
                f"Connection to {self._remote_ip_address}, port {self._remote_port} failed. "
                f"Error: {error!r}."
            )
            raise error

        return client_socket

    @abstractmethod
    def _thread__sender(self) -> None:
        """
        Thread used to send data by the client.
        """

        raise NotImplementedError

    @abstractmethod
    def _thread__receiver(self) -> None:
        """
        Thread used to receive data by the client.
        """

        raise NotImplementedError
