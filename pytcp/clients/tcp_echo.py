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
# clients/tcp_echo.py - 'user space' client for TCP echo, it activelly connects
# to service and sends messages
#
# ver 2.7
#


from __future__ import annotations

import threading
import time

import lib.socket as socket

from pytcp.lib.logger import log
from pytcp.misc.ip_helper import ip_version


class ClientTcpEcho:
    """
    TCP Echo client support class.
    """

    def __init__(
        self,
        local_ip_address: str,
        remote_ip_address: str,
        local_port: int = 0,
        remote_port=7,
        message_count: int = -1,
        message_delay: int = 1,
        message_size: int = 5,
    ) -> None:
        """
        Class constructor.
        """

        self.local_ip_address = local_ip_address
        self.remote_ip_address = remote_ip_address
        self.local_port = local_port
        self.remote_port = remote_port
        self.message_count = message_count
        self.message_delay = message_delay
        self.message_size = message_size

        threading.Thread(target=self.__thread_client).start()

    def __thread_client(self) -> None:
        """
        Client thread.
        """

        version = ip_version(self.local_ip_address)
        if version == 6:
            s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)
        elif version == 4:
            s = socket.socket(family=socket.AF_INET4, type=socket.SOCK_STREAM)
        else:
            if __debug__:
                log(
                    "client",
                    "Client TCP Echo: Invalid local IP address - "
                    f"{self.local_ip_address}",
                )
            return

        if __debug__:
            log("client", f"Client TCP Echo: Created socket [{s}]")

        try:
            s.bind((self.local_ip_address, self.local_port))
            if __debug__:
                log(
                    "client",
                    "Client TCP Echo: Bound socket to "
                    f"{self.local_ip_address}, port {self.local_port}",
                )
        except OSError as error:
            if __debug__:
                log(
                    "client",
                    "Client TCP Echo: Unable to bind socket to "
                    f"{self.local_ip_address}, port {self.local_port} - "
                    f"[{error}]",
                )
            return

        try:
            s.connect((self.remote_ip_address, self.remote_port))
            if __debug__:
                log(
                    "client",
                    "Client TCP Echo: Connection opened to "
                    f"{self.remote_ip_address}, port {self.remote_port}",
                )
        except OSError as error:
            if __debug__:
                log(
                    "client",
                    f"Client TCP Echo: Connection to {self.remote_ip_address}, "
                    "port {self.remote_port} failed - [{error}]",
                )
            return

        message_count = self.message_count
        while message_count:
            message = "[------START------] "
            for i in range(self.message_size - 2):
                message += f"[------{i + 1:05}------] "
            message += "[-------END-------]\n"

            try:
                s.send(bytes(message, "utf-8"))
            except OSError as error:
                if __debug__:
                    log("client", f"Client TCP Echo: send() error - [{error}]")
                break

            if __debug__:
                log(
                    "client",
                    f"Client TCP Echo: Sent {len(message)} bytes of data to "
                    f"{self.remote_ip_address}, port {self.remote_port}",
                )
            time.sleep(self.message_delay)
            message_count = min(message_count, message_count - 1)

        s.close()
        if __debug__:
            log(
                "client",
                "Client TCP Echo: Closed connection to "
                f"{self.remote_ip_address}, port {self.remote_port}",
            )
