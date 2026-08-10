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
This module contains class supporting stack RX Ring operations.

pytcp/runtime/rx_ring.py

ver 3.0.9
"""

import collections
import os
import select
import selectors
from typing import override

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.logger import log
from pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsRx
from pytcp.runtime.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem

# Per-read kernel-buffer headroom over the configured L3 MTU. Sized
# to accommodate the largest L2 framing PyTCP supports plus slack:
#   14 bytes Ethernet II header
#  +  4 bytes 802.1Q VLAN tag (future-proofing — not parsed today)
#  +  4 bytes BSD TUN protocol-family prefix
#  +  ~40 bytes slack
# A buffer of 'mtu + RX_RING__READ_HEADROOM' fits any frame the
# kernel can hand us, including jumbo-Ethernet (MTU 9000) and IPv6
# jumbograms per RFC 2675 / RFC 9293 §3.7.5.
RX_RING__READ_HEADROOM: int = 64


class RxRing(Subsystem):
    """
    Support for receiving packets from the network.
    """

    _subsystem_name = "RX Ring"

    _fd: int
    _mtu: int
    _queue_max_size: int

    _rx_deque: collections.deque[PacketRx]
    _selector: selectors.DefaultSelector
    _rx_event_fd: int
    _queue_full_drop_count: int
    _os_error_drop_count: int
    _packet_stats: PacketStatsRx | None
    _link_stats: LinkStatsCounters | None

    @override
    def __init__(
        self,
        *,
        fd: int,
        mtu: int,
        queue_max_size: int = 1000,
        packet_stats: PacketStatsRx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        """
        Initialize access to RX file descriptor and the inbound queue.
        """

        self._fd = fd
        self._mtu = mtu
        self._queue_max_size = queue_max_size

        super().__init__(info=f"fd={fd}, mtu={mtu}, queue_max_size={queue_max_size}")

        # 'collections.deque' append/popleft are atomic under the
        # GIL, no kernel mutex calls per op. The producer (the
        # rx-ring '_subsystem_loop') and consumer (packet-handler
        # thread calling 'dequeue') synchronise via 'os.eventfd':
        # producer signals on append, consumer waits via
        # 'select.select' on the eventfd. Net per packet: ~5-8 µs
        # saved over the prior 'queue.Queue' that used 'Lock +
        # Condition' on every put/get.
        self._rx_deque = collections.deque()
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._fd, selectors.EVENT_READ)
        self._rx_event_fd = os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC)
        self._queue_full_drop_count = 0
        self._os_error_drop_count = 0
        # Optional shared 'PacketStatsRx' object — when set, ring
        # drop counters live as fields on the shared stats instead
        # of on the ring's private ints, so unified-stats consumers
        # see ring drops alongside per-protocol drops in one
        # dataclass. Ring properties below transparently dispatch
        # to whichever source is authoritative.
        self._packet_stats = packet_stats
        # Optional shared 'LinkStatsCounters' object — when set,
        # 'rx_bytes' is bumped here per successful 'os.read'. The
        # PacketHandler owns the canonical instance; sharing it
        # mirrors the 'packet_stats' pattern above and gives the
        # Link API a single source of truth for 'stats.rx_bytes'.
        self._link_stats = link_stats

    def set_mtu(self, mtu: int, /) -> None:
        """
        Set the read-size MTU bound for this RX ring — the Link API's
        'set_mtu' mutator resizes the bound interface's own ring through
        this. Validation (RFC 791 floor, uint16 ceiling) is the Link
        API's responsibility.
        """

        self._mtu = mtu

    @property
    def queue_full_drop_count(self) -> int:
        """
        Get the cumulative count of inbound frames dropped because
        the RX ring was at capacity. Useful as a saturation signal
        for monitoring — a non-zero rate-of-change indicates the
        consumer is not keeping up with kernel-side packet arrivals.
        Sources from the shared 'PacketStatsRx' field when wired,
        falls back to the internal counter otherwise.
        """

        if self._packet_stats is not None:
            return self._packet_stats.rx_ring__queue_full__drop
        return self._queue_full_drop_count

    @property
    def os_error_drop_count(self) -> int:
        """
        Get the cumulative count of inbound frames dropped because
        'os.read' raised 'OSError' (transient kernel errors: EINTR
        on signal, EBADF on shutdown race, EIO on hardware glitches,
        ENOMEM on tight memory). Without the counter, these errors
        would silently kill the RX subsystem thread.
        """

        if self._packet_stats is not None:
            return self._packet_stats.rx_ring__os_error__drop
        return self._os_error_drop_count

    @property
    def qsize(self) -> int:
        """
        Get the current depth of the RX deque (analogous to
        'queue.Queue.qsize'). Useful for live observability —
        steady-state qsize > 0 indicates the consumer is falling
        behind the producer.
        """

        return len(self._rx_deque)

    @override
    def _subsystem_loop(self) -> None:
        """
        Receive and enqueue the incoming packets. After the outer
        'selector.select' wake-up, drain every additional frame the
        kernel TAP / TUN buffer holds via a 'select(timeout=0)'
        inner peek so a single wake-up amortises across the whole
        pending burst — at line rate the kernel queue can hold many
        frames between two selector polls, and reading them one-
        wake-up-at-a-time wastes outer-loop overhead. Each successful
        append signals the consumer-side eventfd so the packet
        handler's blocking 'dequeue()' wakes immediately.
        """

        if not self._selector.select(timeout=SUBSYSTEM_SLEEP_TIME__SEC):
            return

        while True:
            try:
                packet_rx = PacketRx(os.read(self._fd, self._mtu + RX_RING__READ_HEADROOM))
            except OSError as error:
                # Transient kernel errors (EINTR / EBADF on
                # shutdown race / EIO / ENOMEM) — drop the read
                # attempt, count it, and break the inner drain so
                # the outer loop can take a fresh tick (and check
                # the stop event).
                if self._packet_stats is not None:
                    self._packet_stats.rx_ring__os_error__drop += 1
                else:
                    self._os_error_drop_count += 1
                __debug__ and log(
                    "rx-ring",
                    f"<CRIT>RX read failed, OSError: {error}</>",
                )
                break

            __debug__ and log(
                "rx-ring",
                f"<B><lg>[RX]</> {packet_rx.tracker} - received frame, " f"{len(packet_rx.frame)} bytes",
            )

            # Link API rx_bytes: count wire-level frame bytes
            # received from the kernel regardless of which
            # protocol consumes them. Bumped here at the canonical
            # RX entry point so both L2 (TAP) and L3 (TUN) paths
            # are covered uniformly.
            if self._link_stats is not None:
                self._link_stats.rx_bytes += len(packet_rx.frame)

            if len(self._rx_deque) >= self._queue_max_size:
                if self._packet_stats is not None:
                    self._packet_stats.rx_ring__queue_full__drop += 1
                else:
                    self._queue_full_drop_count += 1
                __debug__ and log(
                    "rx-ring",
                    f"{packet_rx.tracker} - RX Queue is full, dropping packet",
                )
                # Stop draining the moment the consumer falls
                # behind — further reads would just keep dropping.
                break

            self._rx_deque.append(packet_rx)
            try:
                os.eventfd_write(self._rx_event_fd, 1)
            except OSError:
                # Eventfd closed (stop in progress) — packet sits
                # on the deque, will not be drained. Acceptable
                # during shutdown.
                pass

            # Peek for more readable data without blocking. Empty
            # list => kernel buffer drained; exit and let the
            # outer Subsystem driver re-enter on the next wake-up.
            if not self._selector.select(timeout=0):
                break

    @override
    def _stop(self) -> None:
        """
        Release the OS-level epoll/poll/kqueue resource backing the
        'selectors.DefaultSelector' AND the consumer-wakeup eventfd
        so 'stack.stop()' returns both descriptors to the kernel.
        Idempotent.
        """

        self._selector.close()
        try:
            os.close(self._rx_event_fd)
        except OSError:
            pass

    def dequeue(self) -> PacketRx | None:
        """
        Dequeue inbound frame from RX Ring. Fast path: if the deque
        already has packets, popleft and return immediately —
        single-consumer means the eventfd counter doesn't need to
        match deque length. Slow path: wait on the eventfd for up
        to SUBSYSTEM_SLEEP_TIME__SEC for a producer signal.
        """

        # Fast path: deque has data → popleft without syscall.
        if self._rx_deque:
            try:
                return self._rx_deque.popleft()
            except IndexError:
                pass  # producer preempted; fall through to wait.

        # Slow path: block on the eventfd until a producer signals
        # an arrival (or the timeout expires).
        ready, _, _ = select.select([self._rx_event_fd], [], [], SUBSYSTEM_SLEEP_TIME__SEC)
        if not ready:
            return None

        # Drain the eventfd counter — it accumulates one signal
        # per producer enqueue; a single read clears the kernel-
        # side ready bit. We don't care about the exact count.
        try:
            os.eventfd_read(self._rx_event_fd)
        except OSError:
            pass

        try:
            return self._rx_deque.popleft()
        except IndexError:
            return None  # spurious wake-up (signal arrived after consumer drained).
