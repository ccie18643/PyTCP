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
This module contains the in-process loopback delivery queue.

pytcp/runtime/loopback_ring.py

ver 3.0.8
"""

import collections
import os
import select
import threading

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.logger import log
from pytcp.runtime.subsystem import SUBSYSTEM_SLEEP_TIME__SEC

# Default cap on the loopback backlog, mirroring the RX ring's bound.
# Local delivery over 'lo' has no wire flow control, so an unbounded
# queue would let a runaway local producer grow memory without limit.
LOOPBACK_RING__QUEUE_MAX_SIZE: int = 1000


class LoopbackRing:
    """
    In-process queue carrying locally-destined IP packets from the
    IP-TX layer to the loopback ('lo') interface's RX consumer — the
    PyTCP analogue of Linux's 'loopback_xmit() -> netif_rx() ->
    backlog -> softirq' internal delivery path.

    Deliberately NOT a 'Subsystem': the consumer is the loopback
    handler's own subsystem thread (its '_subsystem_loop' calls
    'dequeue'), so the ring is a plain data structure, not an
    independent thread of execution. This mirrors the 'RxRing' /
    packet-handler split — the ring holds the queue, the handler
    consumes — minus the fd/'select'-bound producer (loopback has no
    kernel fd; the producer is the TX hook calling 'enqueue').

    Producer / consumer contract: multiple producer threads may call
    'enqueue' (app-thread socket sends, the TX worker, the timer's
    retransmits), a single consumer thread calls 'dequeue'. The
    'collections.deque' append / popleft are thread-safe on their own;
    'enqueue' takes '_lock__enqueue' only to make the capacity check +
    drop-counter increment atomic under free-threaded CPython (no-GIL),
    where a lost-update on the counter would otherwise be possible.
    Producer and consumer synchronise via 'os.eventfd': the producer
    signals on append, the consumer blocks on 'select' until signalled.
    """

    _lo_deque: collections.deque[PacketRx]
    _lo_event_fd: int
    _queue_max_size: int
    _queue_full_drop_count: int
    _lock__enqueue: threading.Lock

    def __init__(self, *, queue_max_size: int = LOOPBACK_RING__QUEUE_MAX_SIZE) -> None:
        """
        Initialize the loopback delivery queue and its wake-up eventfd.
        """

        self._lo_deque = collections.deque()
        self._lo_event_fd = os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC)
        self._queue_max_size = queue_max_size
        self._queue_full_drop_count = 0
        self._lock__enqueue = threading.Lock()

    def enqueue(self, packet_rx: PacketRx, /) -> None:
        """
        Enqueue a locally-destined packet for delivery on the loopback
        interface and wake the consumer. Drops (and counts) the packet
        when the backlog is at capacity.
        """

        with self._lock__enqueue:
            if len(self._lo_deque) >= self._queue_max_size:
                self._queue_full_drop_count += 1
                __debug__ and log(
                    "rx-ring",
                    f"{packet_rx.tracker} - Loopback queue is full, dropping packet",
                )
                return
            self._lo_deque.append(packet_rx)

        try:
            os.eventfd_write(self._lo_event_fd, 1)
        except OSError:
            # Eventfd closed (stop in progress) — the packet sits on the
            # deque and will not be drained. Acceptable during shutdown.
            pass

    def dequeue(self) -> PacketRx | None:
        """
        Dequeue the next locally-destined packet. Fast path: pop
        immediately when the deque already holds packets. Slow path:
        block on the eventfd for up to 'SUBSYSTEM_SLEEP_TIME__SEC' for a
        producer signal so the consuming subsystem loop stays
        stop-responsive.
        """

        # Fast path: deque has data -> popleft without a syscall.
        if self._lo_deque:
            try:
                return self._lo_deque.popleft()
            except IndexError:
                pass  # consumer preempted; fall through to wait.

        # Slow path: block on the eventfd until a producer signals an
        # arrival (or the timeout expires so the loop can re-check stop).
        ready, _, _ = select.select([self._lo_event_fd], [], [], SUBSYSTEM_SLEEP_TIME__SEC)
        if not ready:
            return None

        # Drain the eventfd counter — one read clears the kernel-side
        # ready bit regardless of how many signals accumulated.
        try:
            os.eventfd_read(self._lo_event_fd)
        except OSError:
            pass

        try:
            return self._lo_deque.popleft()
        except IndexError:
            return None  # spurious wake-up (signal arrived after drain).

    @property
    def qsize(self) -> int:
        """
        Get the current depth of the loopback delivery queue.
        """

        return len(self._lo_deque)

    @property
    def queue_full_drop_count(self) -> int:
        """
        Get the cumulative count of packets dropped because the loopback
        backlog was at capacity — a saturation signal for monitoring.
        """

        return self._queue_full_drop_count

    def close(self) -> None:
        """
        Release the wake-up eventfd back to the kernel. Idempotent so
        teardown of an already-closed ring is safe.
        """

        try:
            os.close(self._lo_event_fd)
        except OSError:
            pass
