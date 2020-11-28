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
# tx_ring.py - module contains class supporting TX operations
#


import os
import threading

import loguru

import stack


class TxRing:
    """ Support for sending packets to the network """

    def __init__(self, tap):
        """ Initialize access to tap interface and the outbound queue """

        stack.tx_ring = self

        self.tap = tap

        self.tx_ring = []
        self.logger = loguru.logger.bind(object_name="tx_ring.")

        self.packet_enqueued = threading.Semaphore(0)

        threading.Thread(target=self.__thread_dequeue).start()
        self.logger.debug("Started TX ring")

    def __thread_dequeue(self):
        """ Dequeue packet from TX ring """

        while True:
            # Wait till packets is avaiable int he queue the pick it up
            self.packet_enqueued.acquire()
            ether_packet_tx = self.tx_ring.pop(0)
            self.logger.opt(ansi=True).debug(f"{ether_packet_tx.tracker}")
            self.__transmit(ether_packet_tx)

    def __transmit(self, ether_packet_tx):
        """ Transmit packet """

        os.write(self.tap, ether_packet_tx.get_raw_packet())
        self.logger.opt(ansi=True).debug(
            f"<magenta>[TX]</> {ether_packet_tx.tracker}<yellow>{ether_packet_tx.tracker.latency}</> - {len(ether_packet_tx)} bytes"
        )

    def enqueue(self, ether_packet_tx, urgent=False):
        """ Enqueue outbound Ethernet packet to TX ring """

        if urgent:
            self.tx_ring.insert(0, ether_packet_tx)
            self.logger.opt(ansi=True).debug(f"{ether_packet_tx.tracker}, priority: Urgent, queue len: {len(self.tx_ring)}")

        else:
            self.tx_ring.append(ether_packet_tx)
            self.logger.opt(ansi=True).debug(f"{ether_packet_tx.tracker}, priorty: Normal, queue len: {len(self.tx_ring)}")

        self.packet_enqueued.release()
