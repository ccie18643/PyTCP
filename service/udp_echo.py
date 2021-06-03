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
# service/udp_echo.py - 'user space' service UDP Echo (RFC 862)
#


import threading

from misc.malpi import malpa, malpi, malpka
from misc.tracker import Tracker
from udp.metadata import UdpMetadata
from udp.socket import UdpSocket


class ServiceUdpEcho:
    """UDP Echo service support class"""

    def __init__(self, local_ip_address: str = "*", local_port: int = 7) -> None:
        """Class constructor"""

        self.local_ip_address = local_ip_address
        self.local_port = local_port

        threading.Thread(target=self.__thread_service).start()

    def __thread_service(self) -> None:
        """Service initialization and rx/tx loop"""

        socket = UdpSocket()
        socket.bind(self.local_ip_address, self.local_port)
        print(f"Service UDP Echo: Socket created, bound to {self.local_ip_address}, port {self.local_port}")

        while True:
            packet_rx = socket.receive_from()
            message = packet_rx.data
            print(f"Service UDP Echo: Received {len(message)} bytes from {packet_rx.remote_ip_address}, port {packet_rx.remote_port}")

            if b"malpka" in message.strip().lower():
                message = malpka

            elif b"malpa" in message.strip().lower():
                message = malpa

            elif b"malpi" in message.strip().lower():
                message = malpi

            packet_tx = UdpMetadata(
                local_ip_address=packet_rx.local_ip_address,
                local_port=packet_rx.local_port,
                remote_ip_address=packet_rx.remote_ip_address,
                remote_port=packet_rx.remote_port,
                data=message,
                tracker=Tracker("TX", echo_tracker=packet_rx.tracker),
            )
            socket.send_to(packet_tx)
            print(f"Service UDP Echo: Echo'ed {len(message)} bytes back to {packet_tx.remote_ip_address}, port {packet_tx.remote_port}")
