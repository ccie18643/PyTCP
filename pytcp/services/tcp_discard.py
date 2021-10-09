#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# services/tcp_discard.py - 'user space' service TCP Discard (RFC 863)
#


from __future__ import annotations

from typing import TYPE_CHECKING

from lib.logger import log
from services.tcp_generic import ServiceTcp

if TYPE_CHECKING:
    from lib.socket import Socket


class ServiceTcpDiscard(ServiceTcp):
    """TCP Echo service support class"""

    def __init__(self, local_ip_address: str, local_port: int = 9):
        """Class constructor"""

        super().__init__("Discard", local_ip_address, local_port)

    def service(self, cs: Socket) -> None:
        """Inbound connection handler"""

        if __debug__:
            log("service", f"Service TCP Echo: Sending first message to {cs.remote_ip_address}, port {cs.remote_port}")
        cs.send(b"***CLIENT OPEN / SERVICE OPEN***\n")

        while True:
            if not (message := cs.recv()):
                if __debug__:
                    log("service", f"Service TCP Discard: Connection to {cs.remote_ip_address}, port {cs.remote_port} has been closed by peer")
                if __debug__:
                    log("service", f"Service TCP Discard: Sending last message to {cs.remote_ip_address}, port {cs.remote_port}")
                cs.send(b"***CLIENT CLOSED, SERVICE CLOSING***\n")
                if __debug__:
                    log("service", f"Service TCP Discard: Closng connection to {cs.remote_ip_address}, port {cs.remote_port}")
                cs.close()
                break

            if message in {b"CLOSE\n", b"CLOSE\r\n", b"close\n", b"close\r\n"}:
                if __debug__:
                    log("service", f"Service TCP Discard: Sending last message to {cs.remote_ip_address}, port {cs.remote_port}")
                cs.send(b"***CLIENT OPEN, SERVICE CLOSING***\n")
                if __debug__:
                    log("service", f"Service TCP Discard: Closng connection to {cs.remote_ip_address}, port {cs.remote_port}")
                cs.close()
                continue

            if __debug__:
                log("service", f"Service TCP Discard: Received {len(message)} bytes from {cs.remote_ip_address}, port {cs.remote_port}")

        cs.close()
        if __debug__:
            log("service", f"Service TCP Discard: Connection from {cs.remote_ip_address}, port {cs.remote_port} has been closed by peer")
