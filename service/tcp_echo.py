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
# service/tcp_echo.py - 'user space' service TCP Echo (RFC 862)
#


import threading

from misc.malpi import malpa, malpi, malpka
from tcp.socket import TcpSocket


class ServiceTcpEcho:
    """TCP Echo service support class"""

    def __init__(self, local_ip_address: str = "*", local_port: int = 7) -> None:
        """Class constructor"""

        self.local_ip_address = local_ip_address
        self.local_port = local_port

        threading.Thread(target=self.__thread_service).start()

    def __thread_service(self) -> None:
        """Service initialization"""

        socket = TcpSocket()
        socket.bind(self.local_ip_address, self.local_port)
        socket.listen()
        print(f"Service TCP Echo: Socket created, bound to {self.local_ip_address}, port {self.local_port} and set to listening mode")

        while True:
            new_socket = socket.accept()
            print(f"Service TCP Echo: Inbound connection received from {new_socket.remote_ip_address}, port {new_socket.remote_port}")

            threading.Thread(target=self.__thread_connection, args=(new_socket,)).start()

    def __thread_connection(self, socket: TcpSocket) -> None:
        """Inbound connection handler"""

        print(f"Service TCP Echo: Sending first message to {socket.remote_ip_address}, port {socket.remote_port}")
        socket.send(b"***CLIENT OPEN / SERVICE OPEN***\n")

        while True:
            message = socket.receive()
            if message is not None:
                print(f"Service TCP Echo: Received {len(message)} bytes from {socket.remote_ip_address}, port {socket.remote_port}")

            if message is None:
                print(f"Service TCP Echo: Connection to {socket.remote_ip_address}, port {socket.remote_port} has been closed by peer")
                print(f"Service TCP Echo: Sending last message to {socket.remote_ip_address}, port {socket.remote_port}")
                socket.send(b"***CLIENT CLOSED, SERVICE CLOSING***\n")
                print(f"Service TCP Echo: Closng connection to {socket.remote_ip_address}, port {socket.remote_port}")
                socket.close()
                break

            elif message in {b"CLOSE\n", b"CLOSE\r\n", b"close\n", b"close\r\n"}:
                print(f"Service TCP Echo: Sending last message to {socket.remote_ip_address}, port {socket.remote_port}")
                socket.send(b"***CLIENT OPEN, SERVICE CLOSING***\n")
                print(f"Service TCP Echo: Closng connection to {socket.remote_ip_address}, port {socket.remote_port}")
                socket.close()
                continue

            if b"malpka" in message.strip().lower():
                message = malpka

            elif b"malpa" in message.strip().lower():
                message = malpa

            elif b"malpi" in message.strip().lower():
                message = malpi

            if socket.send(message):
                print(f"Service TCP Echo: Echo'ed {len(message)} bytes back to {socket.remote_ip_address}, port {socket.remote_port}")
