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
# misc/rx_ring.py - module contains class supporting RX operations
#


import os
import threading

import loguru

from misc.packet import PacketRx


class RxRing:
    """Support for receiving packets from the network"""

    def __init__(self, tap: int) -> None:
        """Initialize access to tap interface and the inbound queue"""

        self.tap = tap
        self.rx_ring: list[PacketRx] = []
        if __debug__:
            self._logger = loguru.logger.bind(object_name="rx_ring.")
        self.packet_enqueued = threading.Semaphore(0)

        threading.Thread(target=self.__thread_receive).start()
        if __debug__:
            self._logger.debug("Started RX ring")

    def __thread_receive(self) -> None:
        """Thread responsible for receiving and enqueuing incoming packets"""

        while True:
            packet_rx = PacketRx(os.read(self.tap, 2048))
            if __debug__:
                self._logger.opt(ansi=True).debug(f"<green>[RX]</> {packet_rx.tracker}> - received frame, {len(packet_rx.frame)} bytes")
            self.rx_ring.append(packet_rx)
            self.packet_enqueued.release()

    def dequeue(self) -> PacketRx:
        """Dequeue inboutd frame from RX ring"""

        self.packet_enqueued.acquire()
        return self.rx_ring.pop(0)
