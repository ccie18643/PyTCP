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
# misc/tx_ring.py - module contains class supporting TX operations
#


from __future__ import annotations  # Required by Python ver < 3.10

import os
import threading
from typing import TYPE_CHECKING

import loguru

import config

if TYPE_CHECKING:
    from ether.fpa import EtherAssembler


class TxRing:
    """Support for sending packets to the network"""

    def __init__(self, tap: int) -> None:
        """Initialize access to tap interface and the outbound queue"""

        if __debug__:
            self._logger = loguru.logger.bind(object_name="tx_ring.")

        self.tap = tap
        self.tx_ring: list[EtherAssembler] = []

        self.packet_enqueued = threading.Semaphore(0)

        threading.Thread(target=self.__thread_transmit).start()
        if __debug__:
            self._logger.debug("Started TX ring")

        self.frame = bytearray(config.mtu + 14)

    def __thread_transmit(self) -> None:
        """Dequeue packet from TX ring and send it out"""

        while True:
            self.packet_enqueued.acquire()
            packet_tx = self.tx_ring.pop(0)
            if (packet_tx_len := len(packet_tx)) > config.mtu + 14:
                if __debug__:
                    self._logger.error(f"{packet_tx.tracker} - Unable to send frame, frame len ({packet_tx_len}) > mtu ({config.mtu + 14})")
                continue
            packet_tx.assemble(self.frame, 0)

            try:
                os.write(self.tap, memoryview(self.frame)[:packet_tx_len])
            except OSError as error:
                self._logger.error(f"{packet_tx.tracker} - Unable to send frame, OSError: {error}")
                continue

            if __debug__:
                self._logger.opt(ansi=True).debug(
                    f"<magenta>[TX]</> {packet_tx.tracker}<yellow>{packet_tx.tracker.latency}</> - sent frame, {len(packet_tx)} bytes"
                )

    def enqueue(self, packet_tx: EtherAssembler) -> None:
        """Enqueue outbound packet into TX ring"""

        self.tx_ring.append(packet_tx)
        if __debug__:
            self._logger.opt(ansi=True).debug(f"{packet_tx.tracker}, queue len: {len(self.tx_ring)}")
        self.packet_enqueued.release()
