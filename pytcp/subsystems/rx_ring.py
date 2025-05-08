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

# pylint: disable = expression-not-assigned
# pylint: disable = consider-using-with

"""
Module contains class supporting stack interface RX operations.

pytcp/subsystems/rx_ring.py

ver 2.7
"""


from __future__ import annotations

import os
import select
import threading
import time
from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.lib.packet import PacketRx

if TYPE_CHECKING:
    from threading import Semaphore


class RxRing:
    """
    Support for receiving packets from the network.
    """

    def __init__(self) -> None:
        """
        Initialize access to tap interface and the inbound queue.
        """
        self._rx_ring: list[PacketRx] = []
        self._packet_enqueued: Semaphore = threading.Semaphore(0)
        self._run_thread: bool = False
        self._tap: int = -1

    def start(self, tap: int) -> None:
        """
        Start Rx ring thread.
        """
        __debug__ and log("stack", "Starting RX ring")
        self._run_thread = True
        self._tap = tap
        threading.Thread(target=self.__thread_receive).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop Rx ring thread.
        """
        __debug__ and log("stack", "Stopping RX ring")
        self._run_thread = False
        time.sleep(0.1)

    def __thread_receive(self) -> None:
        """
        Thread responsible for receiving and enqueuing incoming packets.
        """

        __debug__ and log("stack", "Started RX ring")

        while self._run_thread:
            # Need to use select here so the we ar enot blocking on the read
            # call and can exit the thread gracefully
            read_ready, _, _ = select.select([self._tap], [], [], 0.1)
            if not read_ready:
                continue

            packet_rx = PacketRx(os.read(self._tap, 2048))
            __debug__ and log(
                "rx-ring",
                f"<B><lg>[RX]</> {packet_rx.tracker} - received frame, "
                f"{len(packet_rx.frame)} bytes",
            )
            self._rx_ring.append(packet_rx)
            self._packet_enqueued.release()

        __debug__ and log("stack", "Stopped RX ring")

    def dequeue(self) -> PacketRx | None:
        """
        Dequeue inbound frame from RX ring.
        """

        # Timeout here is needed so this call doesn't block forever and we are
        # able to exit the thread in packet_handler gracefully.
        self._packet_enqueued.acquire(timeout=0.1)

        return self._rx_ring.pop(0) if self._rx_ring else None
