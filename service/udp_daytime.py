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
# service/udp_daytime.py - 'user space' service UDP Daytime (RFC 867)
#


import threading
from datetime import datetime

from misc.tracker import Tracker
from udp.metadata import UdpMetadata
from udp.socket import UdpSocket


class ServiceUdpDaytime:
    """UDP Daytime service support class"""

    def __init__(self, local_ip_address: str = "*", local_port: int = 13) -> None:
        """Class constructor"""

        self.local_ip_address = local_ip_address
        self.local_port = local_port

        threading.Thread(target=self.__thread_service).start()

    def __thread_service(self) -> None:
        """Service initialization and rx/tx loop"""

        socket = UdpSocket()
        socket.bind(self.local_ip_address, self.local_port)
        print(f"Service UDP Daytime: Socket created, bound to {self.local_ip_address}, port {self.local_port}")

        while True:
            packet_rx = socket.receive_from()
            packet_tx = UdpMetadata(
                local_ip_address=packet_rx.local_ip_address,
                local_port=packet_rx.local_port,
                remote_ip_address=packet_rx.remote_ip_address,
                remote_port=packet_rx.remote_port,
                data=bytes(str(datetime.now()), "utf-8"),
                tracker=Tracker("TX", echo_tracker=packet_rx.tracker),
            )
            socket.send_to(packet_tx)
            print(f"Service UDP Daytime: Sent daytime message to {packet_tx.remote_ip_address}, port {packet_tx.remote_port}, {len(packet_tx.data)} bytes")
