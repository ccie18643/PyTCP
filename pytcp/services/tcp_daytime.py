#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
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
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# services/tcp_daytime.py - 'user space' service TCP Daytime (RFC 867)
#
# ver 2.7
#


from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.services.tcp_generic import ServiceTcp

if TYPE_CHECKING:
    from pytcp.lib.socket import Socket


class ServiceTcpDaytime(ServiceTcp):
    """
    TCP Daytime service support class.
    """

    def __init__(
        self,
        local_ip_address: str,
        local_port: int = 13,
        message_count: int = -1,
        message_delay: int = 1,
    ):
        """
        Class constructor.
        """

        super().__init__("Daytime", local_ip_address, local_port)

        self.message_count = message_count
        self.message_delay = message_delay

    def service(self, cs: Socket) -> None:
        """Inbound connection handler"""

        # Don't want to be working on object variable as it may be shar by
        # multiple connections.
        message_count = self.message_count

        if __debug__:
            log(
                "service",
                "Service TCP Daytime: Sending first message to "
                f"{cs.remote_ip_address}, port {cs.remote_port}",
            )
        cs.send(b"***CLIENT OPEN / SERVICE OPEN***\n")

        message_count = self.message_count
        while message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")

            try:
                cs.send(message)
            except OSError as error:
                if __debug__:
                    log(
                        "service",
                        f"Service TCP Daytime: send() error - [{error}]",
                    )
                break

            if __debug__:
                log(
                    "service",
                    f"Service TCP Daytime: Sent {len(message)} bytes of data "
                    f"to {cs.remote_ip_address}, port {cs.remote_port}",
                )
            time.sleep(self.message_delay)
            message_count = min(message_count, message_count - 1)

        cs.close()
        if __debug__:
            log(
                "service",
                "Service TCP Daytime: Closed connection to "
                f"{cs.remote_ip_address}, port {cs.remote_port}",
            )
