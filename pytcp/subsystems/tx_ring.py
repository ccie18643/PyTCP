#!/usr/bin/env python3

################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
Module contains class supporting stack TX Ring operations.

pytcp/subsystems/tx_ring.py

ver 3.0.2
"""


from __future__ import annotations

import os
import threading
import time
from typing import TYPE_CHECKING

from pytcp.lib.logger import log
from pytcp.protocols.ethernet.ethernet__assembler import EthernetAssembler

if TYPE_CHECKING:
    from threading import Semaphore

    from pytcp.protocols.ethernet_802_3.ethernet_802_3__assembler import (
        Ethernet8023Assembler,
    )


class TxRing:
    """
    Support for sending packets to the network.
    """

    _fd: int
    _mtu: int

    def __init__(self) -> None:
        """
        Initialize access to TX file descriptor and the outbound queue.
        """

        self._tx_ring: list[EthernetAssembler | Ethernet8023Assembler] = []
        self._packet_enqueued: Semaphore = threading.Semaphore(0)
        self._run_thread: bool = False

    def start(self, *, fd: int, mtu: int) -> None:
        """
        Start TX Ring thread.
        """

        __debug__ and log("stack", "Starting TX Ring")

        self._fd = fd
        self._mtu = mtu
        self._run_thread = True
        threading.Thread(target=self.__thread__tx_ring__transmit).start()
        time.sleep(0.1)

    def stop(self) -> None:
        """
        Stop TX Ring thread.
        """

        __debug__ and log("stack", "Stopping TX Ring")

        self._run_thread = False
        time.sleep(0.1)

    def __thread__tx_ring__transmit(self) -> None:
        """
        Dequeue packet from TX Ring and send it out.
        """

        __debug__ and log("stack", "Started TX Ring")

        while self._run_thread:
            # Timeout here is needed so the call doesn't block forever and
            # we are able to end the thread gracefully
            self._packet_enqueued.acquire(timeout=0.1)
            if not self._tx_ring:
                continue

            packet_tx = self._tx_ring.pop(0)

            if (packet_tx_len := len(packet_tx)) > self._mtu + 14:
                __debug__ and log(
                    "tx-ring",
                    f"{packet_tx.tracker} - Unable to send frame, frame"
                    f"len ({packet_tx_len}) > mtu ({self._mtu + 14})",
                )
                continue

            try:
                os.write(self._fd, bytes(packet_tx))

            except OSError as error:
                __debug__ and log(
                    "tx-ring",
                    f"{packet_tx.tracker} - <CRIT>Unable to send frame, "
                    f"OSError: {error}</>",
                )
                continue

            __debug__ and log(
                "tx-ring",
                f"<B><lr>[TX]</> {packet_tx.tracker}<y>"
                f"{packet_tx.tracker.latency}</> - sent frame, "
                f"{len(packet_tx)} bytes",
            )

        __debug__ and log("stack", "Stopped TX Ring")

    def enqueue(
        self, packet_tx: EthernetAssembler | Ethernet8023Assembler
    ) -> None:
        """
        Enqueue outbound packet into TX Ring.
        """

        self._tx_ring.append(packet_tx)

        __debug__ and log(
            "tx-ring",
            f"{packet_tx.tracker} - TX Queue len: {len(self._tx_ring)}",
        )

        self._packet_enqueued.release()
