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
# service_udp_discard.py - 'user space' service UDP Discard (RFC 863)
#


import threading

import udp_socket


class ServiceUdpDiscard:
    """ UDP Discard service support class """

    def __init__(self, local_ipv4_address="0.0.0.0", local_port=9):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ipv4_address, local_port)).start()

    def __thread_service(self, local_ipv4_address, local_port):
        """ Service initialization and rx/tx loop """

        socket = udp_socket.UdpSocket()
        socket.bind(local_ipv4_address, local_port)
        print(f"Service UDP Discard: Socket created, bound to {local_ipv4_address}:{local_port}")

        while True:
            packet = socket.receive_from()
            print(f"Service UDP Discard: Discarded message from {packet.remote_ipv4_address}:{packet.remote_port} -", packet.raw_data)
