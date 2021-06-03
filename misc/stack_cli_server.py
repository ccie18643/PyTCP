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
# misc/cli_server.py - module contains class suppoting stack's CLI funcionality
#

import socket
import threading

import loguru

import misc.stack as stack


class StackCliServer:
    """CLI server class"""

    def __init__(self, local_ip_address="", local_port=777):
        """Class constructor"""

        if __debug__:
            self._logger = loguru.logger.bind(object_name="cli_server.")
        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port)).start()

    def __thread_service(self, local_ip_address, local_port):
        """Service initialization"""

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((local_ip_address, local_port))
            s.listen(5)

            if __debug__:
                self._logger.debug(f"Stack CLI server started, bound to {local_ip_address}, port {local_port}")

            while True:
                conn, addr = s.accept()
                if __debug__:
                    self._logger.debug(f"Stack CLI server received connection from {addr[0]}, port {addr[1]}")

                threading.Thread(target=self.__thread_connection, args=(conn,)).start()

    @staticmethod
    def __thread_connection(conn):
        """Inbound connection handler"""

        with conn:
            conn.sendall(b"\nStack CLI...\n\n")

            while True:
                message = conn.recv(1024).lower().strip()

                if message == b"exit":
                    break

                if message == b"":
                    continue

                if message.lower().strip() == b"show tcp sessions":
                    message = b"\n"
                    for session in stack.tcp_sessions:
                        message += bytes(str(session), "utf-8") + b"\n"
                    message += b"\n"
                    conn.sendall(message)

                elif message.lower().strip() == b"show ipv6 address":
                    message = b"\n"
                    for address in stack.packet_handler.ip6_address:
                        message += bytes(str(address), "utf-8") + b"\n"
                    message += b"\n"
                    conn.sendall(message)

                elif message.lower().strip() == b"show ipv6 unicast":
                    message = b"\n"
                    for address in stack.packet_handler.ip6_unicast:
                        message += bytes(str(address), "utf-8") + b"\n"
                    message += b"\n"
                    conn.sendall(message)

                elif message.lower().strip() == b"show ipv6 multicast":
                    message = b"\n"
                    for address in stack.packet_handler.ip6_multicast:
                        message += bytes(str(address), "utf-8") + b"\n"
                    message += b"\n"
                    conn.sendall(message)

                elif message.lower().strip() == b"show ipv4 address":
                    message = b"\n"
                    for address in stack.packet_handler.ip4_address:
                        message += bytes(str(address), "utf-8") + b"\n"
                    message += b"\n"
                    conn.sendall(message)

                elif message.lower().strip() == b"show ipv4 unicast":
                    message = b"\n"
                    for address in stack.packet_handler.ip4_unicast:
                        message += bytes(str(address), "utf-8") + b"\n"
                    message += b"\n"
                    conn.sendall(message)

                elif message.lower().strip() == b"show ipv4 mulicast":
                    message = b"\n"
                    for address in stack.packet_handler.ip4_multicast:
                        message += bytes(str(address), "utf-8") + b"\n"
                    message += b"\n"
                    conn.sendall(message)

                elif message.lower().strip() == b"show ipv4 broadcast":
                    message = b"\n"
                    for address in stack.packet_handler.ip4_broadcast:
                        message += bytes(str(address), "utf-8") + b"\n"
                    message += b"\n"
                    conn.sendall(message)

                else:
                    conn.sendall(b"Syntax error...\n")
