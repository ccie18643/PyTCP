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

examples_legacy/lib/service.py

ver 3.0.8
"""

import threading
from abc import abstractmethod
from collections.abc import Callable
from typing import override

from examples_legacy.lib.subsystem import Subsystem

from net_addr import Ip4Address, Ip4IfAddr, Ip6Address, Ip6IfAddr, IpAddress
from pytcp.runtime.socket import socket

# Delay between failed service-socket bind attempts. A static
# local address is not owned by the stack until RFC 5227 ACD (or
# DHCP / SLAAC) completes a few seconds after start, so the bind
# must be retried rather than attempted once.
SERVICE_SOCKET_RETRY__SEC: float = 0.5


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

    def _get_service_socket(self) -> socket | None:
        """
        Create and bind the service socket.
        """

        service_socket = self._get_subsystem_socket(
            ip_version=self._local_ip_address.version,
            protocol_name=self._protocol_name,
        )

        try:
            service_socket.bind((str(self._local_ip_address), self._local_port))
            self._log(f"Socket created, bound to {self._local_ip_address}, port {self._local_port}.")

        except OSError as error:
            self._log(f"The bind() call failed - {error!r}.")
            return None

        return service_socket

    def _acquire_service_socket(self) -> socket | None:
        """
        Create and bind the service socket, retrying until the
        bind succeeds or the subsystem is stopped. The configured
        local address is not owned by the stack until RFC 5227 ACD
        (or DHCP / SLAAC) completes after start, so a single bind
        attempt at startup would race that and the service would
        never come up.
        """

        while not self._event__stop_subsystem.is_set():
            if service_socket := self._get_service_socket():
                return service_socket
            self._event__stop_subsystem.wait(timeout=SERVICE_SOCKET_RETRY__SEC)

        return None

    @abstractmethod
    def _thread__service(self) -> None:
        """
        Service thread.
        """

        raise NotImplementedError

    @abstractmethod
    def _service(self, *, socket: socket) -> None:
        """
        Service logic handler.
        """

        raise NotImplementedError


def build_echo_services(
    service_cls: Callable[..., Service],
    *,
    local_port: int,
    ip4_support: bool,
    ip4_host: Ip4IfAddr | None,
    ip6_support: bool,
    ip6_host: Ip6IfAddr | None,
) -> list[Service]:
    """
    Build echo-service subsystems only for the enabled address
    families (IPv6 first, IPv4 second). A family with no static
    host binds the unspecified (wildcard) address - the intended
    DHCPv4 / SLAAC behaviour. Skipping a disabled family avoids a
    subsystem that could never bind and would otherwise retry
    forever.
    """

    services: list[Service] = []

    if ip6_support:
        services.append(
            service_cls(
                local_ip_address=ip6_host.address if ip6_host else Ip6Address(),
                local_port=local_port,
            )
        )

    if ip4_support:
        services.append(
            service_cls(
                local_ip_address=ip4_host.address if ip4_host else Ip4Address(),
                local_port=local_port,
            )
        )

    return services
