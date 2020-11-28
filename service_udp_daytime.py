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
# service_udp_daytime.py - 'user space' service UDP Daytime (RFC 867)
#


import threading
from datetime import datetime

import udp_socket
from tracker import Tracker
from udp_metadata import UdpMetadata


class ServiceUdpDaytime:
    """ UDP Daytime service support class """

    def __init__(self, local_ip_address="*", local_port=13):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port)).start()

    def __thread_service(self, local_ip_address, local_port):
        """ Service initialization and rx/tx loop """

        socket = udp_socket.UdpSocket()
        socket.bind(local_ip_address, local_port)
        print(f"Service UDP Daytime: Socket created, bound to {local_ip_address}, port {local_port}")

        while True:
            packet_rx = socket.receive_from()
            packet_tx = UdpMetadata(
                local_ip_address=packet_rx.local_ip_address,
                local_port=packet_rx.local_port,
                remote_ip_address=packet_rx.remote_ip_address,
                remote_port=packet_rx.remote_port,
                raw_data=bytes(str(datetime.now()), "utf-8"),
                tracker=Tracker("TX", echo_tracker=packet_rx.tracker),
            )
            socket.send_to(packet_tx)
            print(f"Service UDP Daytime: Sent daytime message to {packet_tx.remote_ip_address}, port {packet_tx.remote_port} -", packet_tx.raw_data)
