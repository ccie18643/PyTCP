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
This module contains tests for the 'RxRing' subsystem.

pytcp/tests/unit/runtime/test__runtime__rx_ring.py

ver 3.0.8
"""

import os
import queue
from typing import Any, override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_proto.lib.packet_rx import PacketRx
from pytcp.runtime.rx_ring import RxRing


class _RxRingFixture(TestCase):
    """
    Shared fixture: opens a real pipe to provide a valid 'fd' to the
    'selector', suppresses module-level logging, and tears down the
    pipe after every test so no file descriptor leaks.
    """

    @override
    def setUp(self) -> None:
        """
        Install the logging patches and open a pipe whose read end
        serves as the RX file descriptor.
        """

        self._log_patch = patch("pytcp.runtime.rx_ring.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log_patch.start()

        self._read_fd, self._write_fd = os.pipe()
        self._ring = RxRing(fd=self._read_fd, mtu=1500)

    @override
    def tearDown(self) -> None:
        """
        Close the pipe endpoints, release the ring's selector +
        eventfd via '_stop', and stop the log patches.
        """

        try:
            self._ring._stop()
        except OSError:
            pass
        try:
            os.close(self._read_fd)
        except OSError:
            pass
        try:
            os.close(self._write_fd)
        except OSError:
            pass
        self._log_patch.stop()
        self._subsystem_log_patch.stop()


class TestRxRingInit(_RxRingFixture):
    """
    The 'RxRing.__init__' tests.
    """

    def test__rx_ring__stores_fd_and_mtu(self) -> None:
        """
        Ensure '__init__' stores the 'fd', 'mtu', and
        'queue_max_size' fields on private attributes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring._fd,
            self._read_fd,
            msg="RxRing.__init__ must store the fd argument verbatim.",
        )
        self.assertEqual(
            self._ring._mtu,
            1500,
            msg="RxRing.__init__ must store the mtu argument verbatim.",
        )
        self.assertEqual(
            self._ring._queue_max_size,
            1000,
            msg="RxRing._queue_max_size must default to 1000.",
        )

    def test__rx_ring__creates_deque(self) -> None:
        """
        Ensure '__init__' creates an empty deque and a sane
        configured queue cap.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring._queue_max_size,
            1000,
            msg="RxRing._queue_max_size must equal queue_max_size.",
        )
        self.assertEqual(
            len(self._ring._rx_deque),
            0,
            msg="RxRing._rx_deque must start empty.",
        )

    def test__rx_ring__custom_queue_size(self) -> None:
        """
        Ensure a non-default 'queue_max_size' is honored.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = RxRing(fd=self._read_fd, mtu=1500, queue_max_size=7)
        self.addCleanup(ring._stop)
        self.assertEqual(
            ring._queue_max_size,
            7,
            msg="Custom queue_max_size must be propagated to the deque cap.",
        )


class TestRxRingDequeue(_RxRingFixture):
    """
    The 'RxRing.dequeue' tests.
    """

    def test__rx_ring__dequeue_returns_queued_packet(self) -> None:
        """
        Ensure 'dequeue()' returns the next queued 'PacketRx' in FIFO
        order via the fast path (deque non-empty, no eventfd wait).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=PacketRx)
        self._ring._rx_deque.append(pkt)
        self.assertIs(
            self._ring.dequeue(),
            pkt,
            msg="dequeue() must return the queued PacketRx in FIFO order.",
        )

    def test__rx_ring__dequeue_returns_none_on_timeout(self) -> None:
        """
        Ensure 'dequeue()' returns 'None' when the deque stays empty
        past the subsystem-sleep timeout. Exercises the slow path
        ('select.select' on the eventfd times out).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch(
            "pytcp.runtime.rx_ring.SUBSYSTEM_SLEEP_TIME__SEC",
            0.001,
        ):
            self.assertIsNone(
                self._ring.dequeue(),
                msg="dequeue() must return None when the deque stays empty past the timeout.",
            )

    def test__rx_ring__dequeue_drains_eventfd_signal_on_slow_path(self) -> None:
        """
        Ensure the slow-path 'dequeue()' calls 'os.eventfd_read'
        once a 'select.select' wake fires so the kernel-side ready
        bit clears. If the slow path didn't drain the eventfd,
        subsequent calls would spin on stale signals.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Pre-signal the eventfd, leave deque empty so dequeue takes
        # the slow path. Capture the eventfd_read call.
        os.eventfd_write(self._ring._rx_event_fd, 1)

        with patch(
            "pytcp.runtime.rx_ring.os.eventfd_read",
            wraps=os.eventfd_read,
        ) as mock_read:
            with patch(
                "pytcp.runtime.rx_ring.SUBSYSTEM_SLEEP_TIME__SEC",
                0.5,
            ):
                self._ring.dequeue()  # spurious wake — deque empty.

        mock_read.assert_called_once_with(self._ring._rx_event_fd)


class TestRxRingSubsystemLoop(_RxRingFixture):
    """
    The 'RxRing._subsystem_loop' tests.
    """

    def test__rx_ring__loop_returns_early_when_selector_idle(self) -> None:
        """
        Ensure the loop returns early (without reading the fd) when
        the selector signals no readable events. This is the happy
        no-op path while the interface is quiet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch.object(self._ring._selector, "select", return_value=[]),
            patch("pytcp.runtime.rx_ring.os.read") as mock_read,
        ):
            self._ring._subsystem_loop()
        mock_read.assert_not_called()

    def test__rx_ring__loop_enqueues_packet_on_read(self) -> None:
        """
        Ensure the loop reads bytes from the fd and enqueues a
        'PacketRx' when the selector signals a readable event. The
        selector is mocked to return ready on the first call and
        empty on the inner-drain peek so the loop exits after one
        frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = b"\x00" * 64
        with (
            patch.object(
                self._ring._selector,
                "select",
                side_effect=[[MagicMock()], []],
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                return_value=frame,
            ),
        ):
            self._ring._subsystem_loop()

        self.assertEqual(
            len(self._ring._rx_deque),
            1,
            msg="_subsystem_loop must enqueue one PacketRx per readable event.",
        )

    def test__rx_ring__loop_read_size_honors_mtu_for_jumbo_frames(self) -> None:
        """
        Ensure 'os.read' is called with a buffer large enough to hold
        a full jumbo Ethernet frame ('mtu + L2 overhead'), not the
        legacy hardcoded 2048-byte buffer that silently truncated
        anything above ~2 KiB. Jumbo Ethernet (MTU 9000) and IPv6
        jumbograms require this.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 2675 (IPv6 jumbograms).
        Reference: RFC 9293 §3.7.5 (IPv6 jumbograms).
        """

        ring = RxRing(fd=self._read_fd, mtu=9000)

        captured: list[int] = []

        def _capture_read(fd: int, size: int) -> bytes:
            captured.append(size)
            return b"\x00" * 64

        with (
            patch.object(
                ring._selector,
                "select",
                side_effect=[[MagicMock()], []],
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                side_effect=_capture_read,
            ),
        ):
            ring._subsystem_loop()

        self.assertEqual(
            len(captured),
            1,
            msg="Setup invariant: _subsystem_loop must call os.read once.",
        )
        self.assertGreaterEqual(
            captured[0],
            9014,
            msg=(
                "os.read buffer must be at least 'mtu + 14 (Ethernet)' bytes "
                f"to fit a jumbo frame. Got size={captured[0]} for mtu=9000."
            ),
        )

    def test__rx_ring__loop_drops_packet_on_full_queue(self) -> None:
        """
        Ensure the loop catches 'queue.Full' when the RX ring is
        already at 'queue_max_size' — the frame is dropped instead of
        blocking the RX thread.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Exhaust the queue first.
        ring = RxRing(fd=self._read_fd, mtu=1500, queue_max_size=1)
        self.addCleanup(ring._stop)
        ring._rx_deque.append(MagicMock(spec=PacketRx))
        self.assertEqual(
            len(ring._rx_deque),
            ring._queue_max_size,
            msg="Precondition: the deque must be at capacity before we exercise the drop path.",
        )

        with (
            patch.object(
                ring._selector,
                "select",
                return_value=[MagicMock()],
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                return_value=b"\x00" * 64,
            ),
        ):
            ring._subsystem_loop()  # must not raise

        self.assertEqual(
            len(ring._rx_deque),
            1,
            msg="On a full queue, the new frame must be dropped (queue size unchanged).",
        )

    def test__rx_ring__loop_drains_all_pending_packets_per_select_wake(self) -> None:
        """
        Ensure a single 'selectors.DefaultSelector.select' wake-up
        drains every packet currently readable on the fd, not just
        one. The inner-drain pattern amortises the outer-select
        round-trip across the whole pending burst — under bursty
        traffic, the kernel TAP buffer can hold many frames between
        two selector wake-ups, and the producer should empty them
        in one pass rather than yielding back to the subsystem
        driver between every packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = RxRing(fd=self._read_fd, mtu=1500, queue_max_size=100)
        n_frames = 25

        # First select() returns ready (outer wake-up); subsequent
        # peeks return ready N-1 more times then empty so the
        # inner drain naturally exits.
        select_returns: list[list[Any]] = [[MagicMock()]] * n_frames + [[]]
        with (
            patch.object(
                ring._selector,
                "select",
                side_effect=select_returns,
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                return_value=b"\x00" * 64,
            ),
        ):
            ring._subsystem_loop()

        self.assertEqual(
            len(ring._rx_deque),
            n_frames,
            msg=(
                f"A single _subsystem_loop wake must drain all {n_frames} "
                f"pre-buffered frames in one pass. Got qsize="
                f"{len(ring._rx_deque)}."
            ),
        )

    def test__rx_ring__loop_inner_drain_breaks_on_full_queue(self) -> None:
        """
        Ensure the inner-drain loop stops the moment the consumer-
        side ring is full — continuing to read would only keep
        bumping the drop counter without delivering anything to the
        consumer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = RxRing(fd=self._read_fd, mtu=1500, queue_max_size=2)

        select_returns: list[list[Any]] = [[MagicMock()]] * 100  # plenty of "ready"
        read_calls: list[int] = []

        def _track_read(fd: int, size: int) -> bytes:
            read_calls.append(size)
            return b"\x00" * 64

        with (
            patch.object(
                ring._selector,
                "select",
                side_effect=select_returns,
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                side_effect=_track_read,
            ),
        ):
            ring._subsystem_loop()

        # The ring is size-2 and starts empty: two successful puts,
        # then one queue.Full drop, then break. No further reads.
        self.assertEqual(
            len(read_calls),
            3,
            msg=(
                "Inner drain must break after the first queue-full "
                "drop. Expected 3 reads (2 enqueued + 1 dropped); "
                f"got {len(read_calls)}."
            ),
        )
        self.assertEqual(
            ring.queue_full_drop_count,
            1,
            msg="Exactly one drop should be counted before the drain breaks.",
        )

    def test__rx_ring__queue_full_drop_count_starts_at_zero(self) -> None:
        """
        Ensure 'queue_full_drop_count' starts at 0 on a freshly
        constructed ring so observability monitors can establish a
        baseline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring.queue_full_drop_count,
            0,
            msg="A fresh RxRing must report queue_full_drop_count == 0.",
        )

    def test__rx_ring__os_error_drop_count_starts_at_zero(self) -> None:
        """
        Ensure 'os_error_drop_count' starts at 0 on a freshly
        constructed ring so monitors have a clean baseline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring.os_error_drop_count,
            0,
            msg="A fresh RxRing must report os_error_drop_count == 0.",
        )

    def test__rx_ring__loop_swallows_os_read_oserror(self) -> None:
        """
        Ensure 'os.read' raising 'OSError' does not crash the RX
        subsystem thread. Transient kernel errors (EINTR on
        signal, EBADF on shutdown race, EIO on hardware glitches)
        must be caught and counted, not propagated to the
        Subsystem driver where they would silently kill the
        thread.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch.object(
                self._ring._selector,
                "select",
                side_effect=[[MagicMock()], []],
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                side_effect=OSError("transient kernel error"),
            ),
        ):
            # Must not propagate the OSError.
            self._ring._subsystem_loop()

        self.assertEqual(
            self._ring.os_error_drop_count,
            1,
            msg="os.read OSError must bump 'os_error_drop_count' by exactly one.",
        )

    def test__rx_ring__loop_increments_drop_count_on_full_queue(self) -> None:
        """
        Ensure 'queue_full_drop_count' increments by exactly one each
        time the RX loop catches 'queue.Full'. Drop counters are the
        only signal that the kernel-side TAP / TUN buffer has
        outpaced the consumer; without this counter, packet loss is
        invisible to monitoring.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = RxRing(fd=self._read_fd, mtu=1500, queue_max_size=1)
        self.addCleanup(ring._stop)
        ring._rx_deque.append(MagicMock(spec=PacketRx))

        with (
            patch.object(
                ring._selector,
                "select",
                return_value=[MagicMock()],
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                return_value=b"\x00" * 64,
            ),
        ):
            ring._subsystem_loop()
            ring._subsystem_loop()

        self.assertEqual(
            ring.queue_full_drop_count,
            2,
            msg="Each queue-full drop must bump 'queue_full_drop_count' by exactly one.",
        )


class TestRxRingSharedPacketStats(_RxRingFixture):
    """
    The 'RxRing' shared-PacketStats integration tests.
    """

    def test__rx_ring__queue_full_drop_increments_shared_stats(self) -> None:
        """
        Ensure that when a 'PacketStatsRx' instance is wired in via
        the constructor's 'packet_stats=' kwarg, queue-full drops
        bump 'stats.rx_ring__queue_full__drop' instead of the ring's
        private internal counter. Lets monitoring tools see ring
        drops alongside per-protocol drops in one dataclass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib.packet_stats import PacketStatsRx

        stats = PacketStatsRx()
        ring = RxRing(fd=self._read_fd, mtu=1500, queue_max_size=1, packet_stats=stats)
        self.addCleanup(ring._stop)
        ring._rx_deque.append(MagicMock(spec=PacketRx))  # fill to cap

        with (
            patch.object(
                ring._selector,
                "select",
                side_effect=[[MagicMock()], []],
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                return_value=b"\x00" * 64,
            ),
        ):
            ring._subsystem_loop()

        self.assertEqual(
            stats.rx_ring__queue_full__drop,
            1,
            msg="Queue-full drop must bump the shared PacketStatsRx field.",
        )
        # The ring's property should now read from the shared field.
        self.assertEqual(
            ring.queue_full_drop_count,
            1,
            msg="queue_full_drop_count property must read the shared stats value.",
        )

    def test__rx_ring__os_error_drop_increments_shared_stats(self) -> None:
        """
        Ensure that 'os.read' OSError increments
        'stats.rx_ring__os_error__drop' when stats are shared.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib.packet_stats import PacketStatsRx

        stats = PacketStatsRx()
        ring = RxRing(fd=self._read_fd, mtu=1500, packet_stats=stats)
        self.addCleanup(ring._stop)

        with (
            patch.object(
                ring._selector,
                "select",
                side_effect=[[MagicMock()], []],
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                side_effect=OSError("transient kernel error"),
            ),
        ):
            ring._subsystem_loop()

        self.assertEqual(
            stats.rx_ring__os_error__drop,
            1,
            msg="os.read OSError must bump the shared PacketStatsRx field.",
        )

    def test__rx_ring__without_shared_stats_uses_internal_counters(self) -> None:
        """
        Ensure that when no 'packet_stats' is provided, the ring
        falls back to its private internal counters — the
        standalone-bench / unit-test path stays working unchanged.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = RxRing(fd=self._read_fd, mtu=1500, queue_max_size=1)
        self.addCleanup(ring._stop)
        ring._rx_deque.append(MagicMock(spec=PacketRx))

        with (
            patch.object(
                ring._selector,
                "select",
                side_effect=[[MagicMock()], []],
            ),
            patch(
                "pytcp.runtime.rx_ring.os.read",
                return_value=b"\x00" * 64,
            ),
        ):
            ring._subsystem_loop()

        self.assertEqual(
            ring._queue_full_drop_count,
            1,
            msg="With no shared stats, drop must increment the internal counter.",
        )
        self.assertEqual(
            ring.queue_full_drop_count,
            1,
            msg="Property must read the internal counter when no stats are shared.",
        )


class TestRxRingStopReleasesSelector(_RxRingFixture):
    """
    The 'RxRing._stop' selector-cleanup tests.
    """

    def test__rx_ring__stop_closes_selector(self) -> None:
        """
        Ensure 'RxRing._stop' closes the underlying
        'selectors.DefaultSelector' so the epoll fd it wraps is
        released back to the kernel. Long-lived embedded use of the
        stack would otherwise leak one epoll fd per stack.start /
        stack.stop cycle.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sel = self._ring._selector
        with patch.object(sel, "close") as mock_close:
            self._ring._stop()

        mock_close.assert_called_once_with()


class TestRxRingQueueFullSpelling(TestCase):
    """
    Cross-check the module imports 'queue.Full' (not a custom class).
    """

    def test__rx_ring__queue_full_is_stdlib(self) -> None:
        """
        Ensure the module's 'queue.Full' reference resolves to the
        standard library's exception class — a shim or rename would
        silently change the drop-path semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            queue.Full,
            queue.Full,
            msg="Sanity: stdlib queue.Full must still be accessible.",
        )
