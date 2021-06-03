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
# service/tcp_daytime.py - 'user space' service TCP Daytime (RFC 867)
#


import threading
import time

from tcp.socket import TcpSocket

# from datetime import datetime


class ServiceTcpDaytime:
    """TCP Daytime service support class"""

    def __init__(self, local_ip_address: str = "*", local_port: int = 13, message_count: int = 10, message_delay: int = 0, message_size: int = 1):
        """Class constructor"""

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.message_count = message_count
        self.message_delay = message_delay
        self.message_size = message_size

        threading.Thread(target=self.__thread_service).start()

    def __thread_service(self) -> None:
        """Service initialization"""

        socket = TcpSocket()
        socket.bind(self.local_ip_address, self.local_port)
        socket.listen()
        print(f"Service TCP Daytime: Socket created, bound to {self.local_ip_address}, port {self.local_port} and set to listening mode")

        while True:
            new_socket = socket.accept()
            print(f"Service TCP Daytime: Inbound connection received from {new_socket.remote_ip_address}, port {new_socket.remote_port}")

            threading.Thread(target=self.__thread_connection, args=(new_socket,)).start()

    def __thread_connection(self, socket: TcpSocket) -> None:
        """Inbound connection handler"""

        # Don't want to be working on object variable as it may be shared by multiple connections
        message_count = self.message_count

        while message_count:
            # daytime = "bytes(str(datetime.now()) + "\n", "utf-8") * self.message_size

            message = "[------START------] "
            for i in range(self.message_size - 2):
                message += f"[------{i + 1:05}------] "
            message += "[-------END-------]\n"
            daytime = bytes(message, "utf-8")

            if result := socket.send(daytime):
                print(f"Service TCP Daytime: Sent daytime message to {socket.remote_ip_address}, port {socket.remote_port}")
                time.sleep(self.message_delay)
                message_count = min(message_count, message_count - 1)
                if result == -1:
                    print(f"Service TCP Daytime: Connection to {socket.remote_ip_address}, port {socket.remote_port} has been closed by remote peer")
                    break
            else:
                print(f"Service TCP Daytime: Connection to {socket.remote_ip_address}, port {socket.remote_port} has failed")
                break

        socket.close()
        print(f"Service TCP Daytime: Closed connection to {socket.remote_ip_address}, port {socket.remote_port}")
