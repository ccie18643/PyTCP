#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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
# subsystems/tx_ring.py - module contains class supporting TX operations
#
# ver 2.7
#


from __future__ import annotations

import os
import threading
import time
from typing import TYPE_CHECKING

import pytcp.config as config
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from threading import Semaphore

    from pytcp.protocols.ether.fpa import EtherAssembler


class TxRing:
    """
    Support for sending packets to the network.
    """

    def __init__(self) -> None:
        """
        Initialize access to tap interface and the outbound queue.
        """
        self._tx_ring: list[EtherAssembler] = []
        self._packet_enqueued: Semaphore = threading.Semaphore(0)
        self._run_thread: bool = False
        self._tap: int = -1

    def start(self, tap: int) -> None:
        """
        Start Tx ring thread.
        """
        if __debug__:
            log("stack", "Starting TX ring")
        self._tap = tap
        self._run_thread = True
        threading.Thread(target=self.__thread_transmit).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop Tx ring thread.
        """
        if __debug__:
            log("stack", "Stopping TX ring")
        self._run_thread = False
        time.sleep(0.1)

    def __thread_transmit(self) -> None:
        """
        Dequeue packet from TX ring and send it out.
        """

        if __debug__:
            log("stack", "Started TX ring")

        # Using static frame buffer to avoid dynamic memory allocation
        # for each frame.
        frame_buffer = bytearray(config.TAP_MTU + 14)

        while self._run_thread:
            # Timeout here is needed so the call doesn't block forever and
            # we are able to end the thread gracefully
            self._packet_enqueued.acquire(timeout=0.1)
            if not self._tx_ring:
                continue

            packet_tx = self._tx_ring.pop(0)

            if (packet_tx_len := len(packet_tx)) > config.TAP_MTU + 14:
                if __debug__:
                    log(
                        "tx-ring",
                        f"{packet_tx.tracker} - Unable to send frame, frame"
                        f"len ({packet_tx_len}) > mtu ({config.TAP_MTU + 14})",
                    )
                continue
            frame = memoryview(frame_buffer)[:packet_tx_len]
            packet_tx.assemble(frame)
            try:
                os.write(self._tap, frame)
            except OSError as error:
                if __debug__:
                    log(
                        "tx-ring",
                        f"{packet_tx.tracker} - <CRIT>Unable to send frame, "
                        f"OSError: {error}</>",
                    )
                continue

            if __debug__:
                log(
                    "tx-ring",
                    f"<B><lr>[TX]</> {packet_tx.tracker}<y>"
                    f"{packet_tx.tracker.latency}</> - sent frame, "
                    f"{len(packet_tx)} bytes",
                )

        if __debug__:
            log("stack", "Stopped TX ring")

    def enqueue(self, packet_tx: EtherAssembler) -> None:
        """
        Enqueue outbound packet into TX ring.
        """
        self._tx_ring.append(packet_tx)
        if __debug__:
            log(
                "rx-ring",
                f"{packet_tx.tracker}, queue len: {len(self._tx_ring)}",
            )
        self._packet_enqueued.release()
