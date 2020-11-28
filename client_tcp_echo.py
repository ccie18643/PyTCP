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
# client_tcp_echo.py - 'user space' client for TCP echo, it activelly connects to service and sends messages
#


import threading
import time
from datetime import datetime

from tcp_socket import TcpSocket


class ClientTcpEcho:
    """ TCP Echo client support class """

    def __init__(self, local_ipv4_address, remote_ipv4_address, local_port=0, remote_port=7, message_count=10):
        """ Class constructor """

        threading.Thread(target=self.__thread_client, args=(local_ipv4_address, local_port, remote_ipv4_address, remote_port, message_count)).start()

    def __thread_client(self, local_ipv4_address, local_port, remote_ipv4_address, remote_port, message_count):
        socket = TcpSocket()
        socket.bind(local_ipv4_address, 0)

        print(f"Client TCP Echo: opening connection to {remote_ipv4_address}, port {remote_port}")
        if socket.connect(remote_ipv4_address=remote_ipv4_address, remote_port=remote_port):
            print(f"Client TCP Echo: Connection to {remote_ipv4_address}, port {remote_port} has been established")
        else:
            print(f"Client TCP Echo: Connection to {remote_ipv4_address}, port {remote_port} failed")
            return

        i = 1
        while i <= message_count:
            message = bytes(str(datetime.now()) + "\n", "utf-8")
            # message = bytes("***START***" + "1234567890" * 1000 + "***STOP***", "utf-8")
            if socket.send(message):
                print(f"Client TCP Echo: Sent data to {remote_ipv4_address}, port {remote_port} - {message}")
                time.sleep(1)
                i += 1
            else:
                print(f"Client TCP Echo: Peer {remote_ipv4_address}, port {remote_port} closed connection")
                break

        socket.close()
        print(f"Client TCP Echo: Closed connection to {remote_ipv4_address}, port {remote_port}")
