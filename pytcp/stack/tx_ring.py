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
This module contains class supporting stack TX Ring operations.

pytcp/stack/tx_ring.py

ver 3.0.3
"""


from __future__ import annotations

import os
import queue
from typing import TYPE_CHECKING, override

from pytcp.lib.logger import log
from pytcp.lib.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem

if TYPE_CHECKING:
    from pytcp.protocols.ethernet_802_3.ethernet_802_3__assembler import (
        Ethernet8023Assembler,
    )
    from pytcp.protocols.ethernet.ethernet__assembler import EthernetAssembler


class TxRing(Subsystem):
    """
    Support for sending packets to the network.
    """

    _subsystem_name = "TX Ring"

    _fd: int
    _mtu: int
    _queue_max_size: int

    _tx_ring: queue.Queue[EthernetAssembler | Ethernet8023Assembler]

    def __init__(
        self, *, fd: int, mtu: int, queue_max_size: int = 1000
    ) -> None:
        """
        Initialize access to TX file descriptor and the outbound queue.
        """

        self._fd = fd
        self._mtu = mtu
        self._queue_max_size = queue_max_size

        super().__init__(
            info=f"fd={fd}, mtu={mtu}, queue_max_size={queue_max_size}"
        )

        self._tx_ring = queue.Queue(maxsize=queue_max_size)

    @override
    def _subsystem_loop(self) -> None:
        """
        Dequeue packets from TX Ring and put them on the wire.
        """

        try:
            packet_tx = self._tx_ring.get(
                block=True, timeout=SUBSYSTEM_SLEEP_TIME__SEC
            )
        except queue.Empty:
            return

        if (packet_tx_len := len(packet_tx)) > self._mtu + 14:
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - Unable to send frame, frame"
                f"len ({packet_tx_len}) > mtu ({self._mtu + 14})",
            )
            return

        try:
            os.write(self._fd, bytes(packet_tx))
        except OSError as error:
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - <CRIT>Unable to send frame, "
                f"OSError: {error}</>",
            )
            return

        __debug__ and log(
            "tx-ring",
            f"<B><lr>[TX]</> {packet_tx.tracker}<y>"
            f"{packet_tx.tracker.latency}</> - sent frame, "
            f"{len(packet_tx)} bytes",
        )

    def enqueue(
        self, packet_tx: EthernetAssembler | Ethernet8023Assembler
    ) -> None:
        """
        Enqueue outbound packet into TX Ring.
        """

        try:
            self._tx_ring.put(item=packet_tx, block=False)
        except queue.Full:
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - TX Queue is full, dropping packet",
            )

        __debug__ and log(
            "tx-ring",
            f"{packet_tx.tracker} - TX Queue len: {self._tx_ring.qsize()}",
        )
