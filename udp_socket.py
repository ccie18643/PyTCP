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
# udp_socket.py - module contains class supporting UDP sockets
#


import loguru
import threading

import stack


class UdpSocket:
    """ Support for Socket operations """

    open_sockets = {}

    def __init__(self):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="socket.")

        self.local_ip_address = None
        self.local_port = None
        self.remote_ip_address = "0.0.0.0"
        self.remote_port = 0

        self.packet_rx = []
        self.packet_rx_ready = threading.Semaphore(0)
        self.logger.debug(f"Opened UDP socket {self.socket_id}")

    @property
    def socket_id(self):
        return f"UDP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    def bind(self, local_ip_address, local_port):
        """ Bind the socket to local address """

        self.local_ip_address = local_ip_address
        self.local_port = local_port
        stack.udp_sockets[self.socket_id] = self
        self.logger.debug(f"{self.socket_id} - Socket bound to local address")

    def send_to(self, packet):
        """ Put data from UdpPacketMetadata structure into TX ring """

        stack.packet_handler.phtx_udp(
            ip_src=packet.local_ip_address,
            udp_sport=packet.local_port,
            ip_dst=packet.remote_ip_address,
            udp_dport=packet.remote_port,
            raw_data=packet.raw_data,
        )

    def receive_from(self, timeout=None):
        """ Read data from listening socket and return UdpMessage structure """

        if self.packet_rx_ready.acquire(timeout=timeout):
            return self.packet_rx.pop(0)

    def close(self):
        """ Close socket """

        stack.udp_sockets.pop(self.socket_id)
        self.logger.debug(f"Closed UDP socket {self.socket_id}")

    def process_packet(self, packet):
        """ Process incoming UDP packet's metadata """

        self.packet_rx.append(packet)
        self.packet_rx_ready.release()
