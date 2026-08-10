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
This module contains tests for the 'LoopbackRing' in-process queue.

pytcp/tests/unit/runtime/test__runtime__loopback_ring.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase

from net_proto.lib.packet_rx import PacketRx
from pytcp.runtime.loopback_ring import LoopbackRing

# A minimal well-formed IPv4 header (version nibble 4) is enough for
# the queue tests — the ring is version-agnostic; dispatch lives on
# the loopback handler, not here.
_IP4_FRAME = b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x00\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01"


class _LoopbackRingFixture(TestCase):
    """
    Shared fixture: build a fresh 'LoopbackRing' and close its eventfd
    on teardown so no descriptor leaks.
    """

    @override
    def setUp(self) -> None:
        """
        Build the ring under test.
        """

        self._ring = LoopbackRing()
        self.addCleanup(self._ring.close)


class TestLoopbackRingEnqueueDequeue(_LoopbackRingFixture):
    """
    The 'LoopbackRing' enqueue / dequeue round-trip tests.
    """

    def test__loopback_ring__enqueue_then_dequeue_returns_same_packet(self) -> None:
        """
        Ensure a packet enqueued by the producer is returned by the next
        dequeue on the consumer side (the fast path).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        packet_rx = PacketRx(_IP4_FRAME)
        self._ring.enqueue(packet_rx)

        self.assertIs(
            self._ring.dequeue(),
            packet_rx,
            msg="LoopbackRing.dequeue must return the exact PacketRx that was enqueued.",
        )

    def test__loopback_ring__dequeue_preserves_fifo_order(self) -> None:
        """
        Ensure the ring hands packets back in first-in-first-out order.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = PacketRx(_IP4_FRAME)
        second = PacketRx(_IP4_FRAME)
        self._ring.enqueue(first)
        self._ring.enqueue(second)

        self.assertEqual(
            [self._ring.dequeue(), self._ring.dequeue()],
            [first, second],
            msg="LoopbackRing must dequeue packets in FIFO order.",
        )

    def test__loopback_ring__dequeue_on_empty_returns_none(self) -> None:
        """
        Ensure a dequeue on an empty ring returns None after the poll
        timeout rather than blocking forever or raising.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(
            self._ring.dequeue(),
            msg="LoopbackRing.dequeue on an empty ring must return None.",
        )

    def test__loopback_ring__qsize_reflects_pending_depth(self) -> None:
        """
        Ensure 'qsize' reports the number of packets currently queued.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._ring.qsize, 0, msg="A fresh ring must have qsize 0.")
        self._ring.enqueue(PacketRx(_IP4_FRAME))
        self._ring.enqueue(PacketRx(_IP4_FRAME))
        self.assertEqual(self._ring.qsize, 2, msg="qsize must reflect the two queued packets.")


class TestLoopbackRingQueueFull(TestCase):
    """
    The 'LoopbackRing' capacity / drop-counter tests.
    """

    def test__loopback_ring__over_capacity_drops_and_counts(self) -> None:
        """
        Ensure enqueue past the configured capacity drops the packet and
        bumps the queue-full drop counter rather than growing unbounded.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = LoopbackRing(queue_max_size=2)
        self.addCleanup(ring.close)

        ring.enqueue(PacketRx(_IP4_FRAME))
        ring.enqueue(PacketRx(_IP4_FRAME))
        ring.enqueue(PacketRx(_IP4_FRAME))  # over capacity — dropped

        self.assertEqual(ring.qsize, 2, msg="LoopbackRing must not queue past its capacity.")
        self.assertEqual(
            ring.queue_full_drop_count,
            1,
            msg="LoopbackRing must count the over-capacity drop.",
        )


class TestLoopbackRingClose(TestCase):
    """
    The 'LoopbackRing.close' idempotence tests.
    """

    def test__loopback_ring__close_is_idempotent(self) -> None:
        """
        Ensure calling 'close' more than once does not raise — teardown
        of a ring whose eventfd is already released must be safe.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = LoopbackRing()
        ring.close()
        ring.close()  # must not raise
