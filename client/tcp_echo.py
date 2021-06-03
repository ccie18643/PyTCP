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
# client/tcp_echo.py - 'user space' client for TCP echo, it activelly connects to service and sends messages
#


import threading
import time
from datetime import datetime

from misc.ip_helper import ip_pick_version
from tcp.socket import TcpSocket


class ClientTcpEcho:
    """TCP Echo client support class"""

    def __init__(self, local_ip_address: str, remote_ip_address: str, local_port: int = 0, remote_port: int = 7, message_count: int = -1) -> None:
        """Class constructor"""

        self.local_ip_address = ip_pick_version(local_ip_address)
        self.remote_ip_address = ip_pick_version(remote_ip_address)
        self.local_port = local_port
        self.remote_port = remote_port
        self.message_count = message_count

        threading.Thread(target=self.__thread_client).start()

    def __thread_client(self) -> None:
        socket = TcpSocket()
        socket.bind(self.local_ip_address, self.local_port)

        print(f"Client TCP Echo: opening connection to {self.remote_ip_address}, port {self.remote_port}")
        if socket.connect(remote_ip_address=self.remote_ip_address, remote_port=self.remote_port):
            print(f"Client TCP Echo: Connection to {self.remote_ip_address}, port {self.remote_port} has been established")
        else:
            print(f"Client TCP Echo: Connection to {self.remote_ip_address}, port {self.remote_port} failed")
            return

        message_count = self.message_count
        while message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")
            # message = bytes("***START***" + "1234567890" * 1000 + "***STOP***", "utf-8")
            if socket.send(message):
                print(f"Client TCP Echo: Sent data to {self.remote_ip_address}, port {self.remote_port} - {str(message)}")
                time.sleep(1)
                message_count = min(message_count, message_count - 1)
            else:
                print(f"Client TCP Echo: Peer {self.remote_ip_address}, port {self.remote_port} closed connection")
                break

        socket.close()
        print(f"Client TCP Echo: Closed connection to {self.remote_ip_address}, port {self.remote_port}")
