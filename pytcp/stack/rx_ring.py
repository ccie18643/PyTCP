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
Module contains class supporting stack RX Ring operations.

pytcp/stack/rx_ring.py

ver 3.0.3
"""


from __future__ import annotations

import os
import queue
import selectors
from typing import override

from pytcp.lib.logger import log
from pytcp.lib.packet_rx import PacketRx
from pytcp.lib.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem


class RxRing(Subsystem):
    """
    Support for receiving packets from the network.
    """

    _subsystem_name = "RX Ring"

    _fd: int
    _mtu: int
    _queuse_max_size: int

    _rx_ring: queue.Queue[PacketRx]
    _selector: selectors.DefaultSelector

    def __init__(
        self, *, fd: int, mtu: int, queue_max_size: int = 1000
    ) -> None:
        """
        Initialize access to RX file descriptor and the inbound queue.
        """

        self._fd = fd
        self._mtu = mtu
        self._queue_max_size = queue_max_size

        super().__init__(
            info=f"fd={fd}, mtu={mtu}, queue_max_size={queue_max_size}"
        )

        self._rx_ring = queue.Queue(maxsize=queue_max_size)
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._fd, selectors.EVENT_READ)

    @override
    def _subsystem_loop(self) -> None:
        """
        Receive and enqueue the incoming packets.
        """

        if not self._selector.select(timeout=SUBSYSTEM_SLEEP_TIME__SEC):
            return

        packet_rx = PacketRx(os.read(self._fd, 2048))
        __debug__ and log(
            "rx-ring",
            f"<B><lg>[RX]</> {packet_rx.tracker} - received frame, "
            f"{len(packet_rx.frame)} bytes",
        )
        self._rx_ring.put(packet_rx)

    def dequeue(self) -> PacketRx | None:
        """
        Dequeue inbound frame from RX Ring.
        """

        try:
            return self._rx_ring.get(
                block=True, timeout=SUBSYSTEM_SLEEP_TIME__SEC
            )
        except queue.Empty:
            return None
