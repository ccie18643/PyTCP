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


#
# service_tcp_discard.py - 'user space' service TCP Discard (RFC 863)
#


import threading

import tcp_socket


class ServiceTcpDiscard:
    """ TCP Discard service support class """

    def __init__(self, local_ip_address="0.0.0.0", local_port=9):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port)).start()

    def __thread_service(self, local_ip_address, local_port):
        """ Service initialization """

        socket = tcp_socket.TcpSocket()
        socket.bind(local_ip_address, local_port)
        socket.listen()
        print(f"Service TCP Discard: Socket created, bound to {local_ip_address}:{local_port} and set to listening mode")

        while True:
            new_socket = socket.accept()
            print(f"Service TCP Discard: Inbound connection received from {new_socket.remote_ip_address}:{new_socket.remote_port}")

            threading.Thread(target=self.__thread_connection, args=(new_socket,)).start()

    def __thread_connection(self, socket):
        """ Inbound connection handler """

        while True:
            message = socket.receive()

            if message is None:
                break

            print(f"Service TCP Discard: Discarded message from {socket.remote_ip_address}:{socket.remote_port} -", message)

        socket.close()
        print(f"Service TCP Discard: Connection from {socket.remote_ip_address}:{socket.remote_port} has been closed by peer")
