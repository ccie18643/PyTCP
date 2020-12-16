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
# service_tcp_daytime.py - 'user space' service TCP Daytime (RFC 867)
#


import threading
import time

import tcp_socket


class ServiceTcpDaytime:
    """ TCP Daytime service support class """

    def __init__(self, local_ip_address="*", local_port=13, message_count=1, message_delay=0, message_size=1):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port, message_count, message_delay, message_size)).start()

    def __thread_service(self, local_ip_address, local_port, message_count, message_delay, message_size):
        """ Service initialization """

        socket = tcp_socket.TcpSocket()
        socket.bind(local_ip_address, local_port)
        socket.listen()
        print(f"Service TCP Daytime: Socket created, bound to {local_ip_address}, port {local_port} and set to listening mode")

        while True:
            new_socket = socket.accept()
            print(f"Service TCP Daytime: Inbound connection received from {new_socket.remote_ip_address}, port {new_socket.remote_port}")

            threading.Thread(target=self.__thread_connection, args=(new_socket, message_count, message_delay, message_size)).start()

    @staticmethod
    def __thread_connection(socket, message_count, message_delay, message_size):
        """ Inbound connection handler """

        while message_count:
            # daytime = "bytes(str(datetime.now()) + "\n", "utf-8") * message_size

            message = "[------START------] "
            for i in range(message_size - 2):
                message += f"[------{i + 1:05}------] "
            message += "[-------END-------]\n"
            daytime = bytes(message, "utf-8")

            if result := socket.send(daytime):
                print(f"Service TCP Daytime: Sent daytime message to {socket.remote_ip_address}, port {socket.remote_port}")
                time.sleep(message_delay)
                message_count = min(message_count, message_count - 1)
                if result == -1:
                    print(f"Service TCP Daytime: Connection to {socket.remote_ip_address}, port {socket.remote_port} has been closed by remote peer")
                    break
            else:
                print(f"Service TCP Daytime: Connection to {socket.remote_ip_address}, port {socket.remote_port} has failed")
                break

        socket.close()
        print(f"Service TCP Daytime: Closed connection to {socket.remote_ip_address}, port {socket.remote_port}")
