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
# rx_ring.py - module contains class supporting RX operations
#


import os
import threading

import loguru

import ps_ether
import stack


class RxRing:
    """ Support for receiving packets from the network """

    def __init__(self, tap):
        """ Initialize access to tap interface and the inbound queue """

        stack.rx_ring = self

        self.tap = tap
        self.rx_ring = []
        self.logger = loguru.logger.bind(object_name="rx_ring.")

        self.packet_enqueued = threading.Semaphore(0)

        threading.Thread(target=self.__thread_receive).start()
        self.logger.debug("Started RX ring")

    def __enqueue(self, ether_packet_rx):
        """ Enqueue packet for further processing """

        if ether_packet_rx.ether_type == ps_ether.ETHER_TYPE_ARP:
            self.rx_ring.insert(0, ether_packet_rx)
            self.logger.opt(ansi=True).debug(f"{ether_packet_rx.tracker}, priority: Urgent, queue len: {len(self.rx_ring)}")
        else:
            self.rx_ring.append(ether_packet_rx)
            self.logger.opt(ansi=True).debug(f"{ether_packet_rx.tracker}, priority: Normal, queue len: {len(self.rx_ring)}")

        self.packet_enqueued.release()

    def __thread_receive(self):
        """ Thread responsible for receiving and enqueuing incoming packets """

        while True:

            # Wait till there is any packet comming and pick it up
            ether_packet_rx = ps_ether.EtherPacket(os.read(self.tap, 2048))
            self.logger.opt(ansi=True).debug(f"<green>[RX]</green> {ether_packet_rx.tracker} - {len(ether_packet_rx)} bytes")
            self.__enqueue(ether_packet_rx)

    def dequeue(self):
        """ Dequeue inboutd packet from RX ring """

        self.packet_enqueued.acquire()

        return self.rx_ring.pop(0)
