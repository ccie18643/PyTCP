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
from abc import abstractmethod
from typing import TYPE_CHECKING, override

from net_addr.ip4_address import Ip4Address
from net_addr.ip6_address import Ip6Address
from net_addr.ip_address import IpVersion

from examples.lib.subsystem import Subsystem
from pytcp.socket import (
    AF_INET4,
    AF_INET6,
    IPPROTO_ICMP4,
    IPPROTO_ICMP6,
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_STREAM,
    socket,
)

if TYPE_CHECKING:
    from pytcp.socket.socket import Socket


class Client(Subsystem):
    """
    Generic client support class.
    """

    _protocol_name: str
    _subsystem_name: str
    _local_ip_address: Ip4Address | Ip6Address
    _local_port: int
    _remote_ip_address: Ip4Address | Ip6Address
    _remote_port: int
    _run_thread: bool
    _client_socket: Socket | None

    _thread__receiver: threading.Thread
    _thread__sender: threading.Thread
    _event__stop_receiver: threading.Event
    _event__stop_sender: threading.Event

    def __init__(self) -> None:
        """
        Initialize the client.
        """

        self._thread__receiver = threading.Thread(
            target=self._thread_target__receiver
        )
        self._thread__sender = threading.Thread(
            target=self._thread_target__sender
        )
        self._event__stop_receiver = threading.Event()
        self._event__stop_sender = threading.Event()

    @override
    def start(self) -> None:
        """
        Start the client thread.
        """

        self._log("Starting the client.")

        if isinstance(self._remote_ip_address, Ip4Address):
            self._local_ip_address = self.stack_ip4_address

        if isinstance(self._remote_ip_address, Ip6Address):
            self._local_ip_address = self.stack_ip6_address

        self._client_socket = self._get_client_socket()

        self._event__stop_receiver.clear()
        self._event__stop_sender.clear()

        self._thread__receiver.start()
        self._thread__sender.start()

    @override
    def stop(self) -> None:
        """
        Stop the service thread.
        """

        self._log("Stopping the client.")

        self._event__stop_receiver.set()
        self._event__stop_sender.set()

    def _get_client_socket(self) -> Socket | None:
        """
        Create and bind the client socket.
        """

        match (
            self._remote_ip_address.version,
            self._protocol_name,
        ):
            case IpVersion.IP6, "TCP":
                client_socket = socket(family=AF_INET6, type=SOCK_STREAM)
            case IpVersion.IP4, "TCP":
                client_socket = socket(family=AF_INET4, type=SOCK_STREAM)
            case IpVersion.IP6, "UDP":
                client_socket = socket(family=AF_INET6, type=SOCK_DGRAM)
            case IpVersion.IP4, "UDP":
                client_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
            case IpVersion.IP6, "ICMP":
                client_socket = socket(
                    family=AF_INET6, type=SOCK_RAW, protocol=IPPROTO_ICMP6
                )
                self._local_port = int(IPPROTO_ICMP6)
                self._remote_port = 0
            case IpVersion.IP4, "ICMP":
                client_socket = socket(
                    family=AF_INET4, type=SOCK_RAW, protocol=IPPROTO_ICMP4
                )
                self._local_port = int(IPPROTO_ICMP4)
                self._remote_port = 0
            case _:
                raise ValueError("Invalid IP versions or protocol combination.")

        self._log(f"Created socket [{client_socket}].")

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
            return None

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
            return None

        return client_socket

    @override
    def is_alive(self) -> bool:
        """
        Check if the service thread is alive.
        """

        return (
            self._thread__receiver.is_alive()
            and self._thread__sender.is_alive()
        )

    @abstractmethod
    def _thread_target__sender(self) -> None:
        """
        Thread used to send data.
        """

        raise NotImplementedError

    @abstractmethod
    def _thread_target__receiver(self) -> None:
        """
        Thread used to receive data.
        """

        raise NotImplementedError
