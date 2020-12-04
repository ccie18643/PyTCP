#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# service_tcp_echo.py - 'user space' service TCP Echo (RFC 862)
#


import threading

import tcp_socket
from malpi import malpa, malpka


class ServiceTcpEcho:
    """ TCP Echo service support class """

    def __init__(self, local_ip_address="*", local_port=7):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port)).start()

    def __thread_service(self, local_ip_address, local_port):
        """ Service initialization """

        socket = tcp_socket.TcpSocket()
        socket.bind(local_ip_address, local_port)
        socket.listen()
        print(f"Service TCP Echo: Socket created, bound to {local_ip_address}, port {local_port} and set to listening mode")

        while True:
            new_socket = socket.accept()
            print(f"Service TCP Echo: Inbound connection received from {new_socket.remote_ip_address}, port {new_socket.remote_port}")

            threading.Thread(target=self.__thread_connection, args=(new_socket,)).start()

    @staticmethod
    def __thread_connection(socket):
        """ Inbound connection handler """

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

            if "malpka" in str(message, "utf-8").strip().lower():
                message = bytes(malpka, "utf-8")

            elif "malpa" in str(message, "utf-8").strip().lower():
                message = bytes(malpa, "utf-8")

            elif "malpi" in str(message, "utf-8").strip().lower():
                message = b""
                for malpka_line, malpa_line in zip(malpka.split("\n"), malpa.split("\n")):
                    message += bytes(malpka_line + malpa_line + "\n", "utf-8")

            if socket.send(message):
                print(f"Service TCP Echo: Echo'ed {len(message)} bytes back to {socket.remote_ip_address}, port {socket.remote_port}")
