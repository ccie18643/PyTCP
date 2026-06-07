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
This module contains tests for the 'TxRing' subsystem.

pytcp/tests/unit/runtime/test__runtime__tx_ring.py

ver 3.0.8
"""

import os
import threading
from typing import Any, override
from unittest import TestCase
from unittest.mock import MagicMock, patch

import pytcp.runtime.tx_ring as tx_ring_module
from net_addr import Buffer
from net_proto import (
    Ethernet8023Assembler,
    EthernetAssembler,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
)
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.tx_ring import TxRing


class _TxRingFixture(TestCase):
    """
    Shared fixture that opens a pipe (the read end stands in for the
    TX file descriptor in tests of enqueue-only behavior) and
    suppresses module-level logging.
    """

    @override
    def setUp(self) -> None:
        """
        Install the logging patches and open the pipe.
        """

        # Register the log patches via 'enterContext' so their
        # cleanup runs LAST (LIFO) — after any 'addCleanup(ring.stop)'
        # a test registers — keeping start/stop log output silenced
        # while a started worker is torn down.
        self.enterContext(patch("pytcp.runtime.tx_ring.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))

        self._read_fd, self._write_fd = os.pipe()
        self.addCleanup(self._close_fd, self._read_fd)
        self.addCleanup(self._close_fd, self._write_fd)
        self._ring = TxRing(fd=self._write_fd, mtu=1500)
        # Release the ring's eventfd back to the kernel; '_stop' is
        # idempotent and safe on a never-started ring.
        self.addCleanup(self._ring._stop)

    @staticmethod
    def _close_fd(fd: int) -> None:
        """
        Close a file descriptor, tolerating an already-closed fd.
        """

        try:
            os.close(fd)
        except OSError:
            pass


class TestTxRingInit(_TxRingFixture):
    """
    The 'TxRing.__init__' tests.
    """

    def test__tx_ring__stores_fd_mtu_queue_size(self) -> None:
        """
        Ensure '__init__' stores the 'fd', 'mtu', and
        'queue_max_size' fields on private attributes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring._fd,
            self._write_fd,
            msg="TxRing.__init__ must store the fd argument verbatim.",
        )
        self.assertEqual(
            self._ring._mtu,
            1500,
            msg="TxRing.__init__ must store the mtu argument verbatim.",
        )
        self.assertEqual(
            self._ring._queue_max_size,
            1000,
            msg="TxRing._queue_max_size must default to 1000.",
        )

    def test__tx_ring__creates_empty_deque(self) -> None:
        """
        Ensure '__init__' creates an empty deque and a sane
        configured queue cap.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring._queue_max_size,
            1000,
            msg="TxRing._queue_max_size must equal queue_max_size.",
        )
        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="TxRing._tx_deque must start empty.",
        )


class TestTxRingEnqueue(_TxRingFixture):
    """
    The 'TxRing.enqueue' tests.
    """

    def test__tx_ring__enqueue_appends_packet(self) -> None:
        """
        Ensure enqueue() places the packet on the internal deque.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=EthernetAssembler)
        self._ring.enqueue(pkt)
        self.assertEqual(
            len(self._ring._tx_deque),
            1,
            msg="enqueue() must place the packet on the TX ring.",
        )

    def test__tx_ring__enqueue_drops_when_full(self) -> None:
        """
        Ensure enqueue() silently drops the packet when the deque is
        at capacity rather than blocking — dropping an outbound
        frame is preferable to stalling the caller.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500, queue_max_size=1)
        self.addCleanup(ring._stop)
        ring._tx_deque.append(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))  # must not raise
        self.assertEqual(
            len(ring._tx_deque),
            1,
            msg="enqueue() on a full TX ring must drop the new packet (size unchanged).",
        )


class TestTxRingSubsystemLoop(_TxRingFixture):
    """
    The 'TxRing._subsystem_loop' tests.
    """

    def test__tx_ring__loop_returns_early_when_queue_empty(self) -> None:
        """
        Ensure the loop returns early on 'queue.Empty' — there is
        nothing to transmit so os.writev() must not be called.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch(
                "pytcp.runtime.tx_ring.SUBSYSTEM_SLEEP_TIME__SEC",
                0.001,
            ),
            patch("pytcp.runtime.tx_ring.os.writev") as mock_writev,
        ):
            self._ring._subsystem_loop()
        mock_writev.assert_not_called()

    def _make_ethernet(self) -> MagicMock:
        """
        Build a MagicMock that behaves like an 'EthernetAssembler':
        passes 'isinstance(packet, EthernetAssembler)', has __len__,
        and has an 'assemble()' method that appends a stub buffer.
        """

        pkt = MagicMock(spec=EthernetAssembler)
        pkt.__len__.return_value = 64

        def assemble(buffers: list[Buffer]) -> None:
            buffers.append(b"x" * 64)

        pkt.assemble.side_effect = assemble
        return pkt

    def test__tx_ring__loop_writes_ethernet_frame(self) -> None:
        """
        Ensure the loop builds the buffer list for an
        'EthernetAssembler' packet and writes it to the fd via
        'os.writev'. The Ethernet branch uses an empty initial buffer
        list and adds Ethernet-header overhead to the MTU check.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = self._make_ethernet()
        self._ring.enqueue(pkt)

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        mock_writev.assert_called_once()
        fd_arg, buffers_arg = mock_writev.call_args.args
        self.assertEqual(
            fd_arg,
            self._write_fd,
            msg="os.writev must be called with the TX ring fd.",
        )
        self.assertEqual(
            buffers_arg,
            [b"x" * 64],
            msg="os.writev must be called with the assembled buffer list.",
        )

    def test__tx_ring__loop_ip6_uses_ipv6_ethertype_prefix(self) -> None:
        """
        Ensure the loop prepends the IPv6 EtherType prefix
        (b'\\x00\\x00\\x86\\xdd') to the buffer list for an
        'Ip6Assembler' packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=Ip6Assembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"p6")

        self._ring.enqueue(pkt)

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        buffers_arg = mock_writev.call_args.args[1]
        self.assertEqual(
            buffers_arg[0],
            b"\x00\x00\x86\xdd",
            msg="The Ip6Assembler branch must prepend the IPv6 EtherType prefix.",
        )

    def test__tx_ring__loop_ip4_uses_ipv4_ethertype_prefix(self) -> None:
        """
        Ensure the loop prepends the IPv4 EtherType prefix
        (b'\\x00\\x00\\x08\\x00') to the buffer list for an
        'Ip4Assembler' packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=Ip4Assembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"p4")

        self._ring.enqueue(pkt)

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        buffers_arg = mock_writev.call_args.args[1]
        self.assertEqual(
            buffers_arg[0],
            b"\x00\x00\x08\x00",
            msg="The Ip4Assembler branch must prepend the IPv4 EtherType prefix.",
        )

    def test__tx_ring__loop_ip4_frag_uses_ipv4_prefix(self) -> None:
        """
        Ensure 'Ip4FragAssembler' packets also receive the IPv4
        EtherType prefix — they share a branch with 'Ip4Assembler'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=Ip4FragAssembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"frag")

        self._ring.enqueue(pkt)

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        buffers_arg = mock_writev.call_args.args[1]
        self.assertEqual(
            buffers_arg[0],
            b"\x00\x00\x08\x00",
            msg="The Ip4FragAssembler branch must share the IPv4 EtherType prefix.",
        )

    def test__tx_ring__loop_eth802_3_branch_writes(self) -> None:
        """
        Ensure 'Ethernet8023Assembler' packets exercise the
        corresponding MTU branch and get written out — the test only
        verifies the dispatch, not the 802.3 framing internals.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=Ethernet8023Assembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"z")

        self._ring.enqueue(pkt)

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        mock_writev.assert_called_once()

    def test__tx_ring__loop_drops_oversized_frame(self) -> None:
        """
        Ensure the loop drops a frame whose length exceeds the MTU
        (plus Ethernet header overhead) without calling os.writev.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = self._make_ethernet()
        pkt.__len__.return_value = 65535  # way bigger than MTU + 14

        self._ring.enqueue(pkt)

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        mock_writev.assert_not_called()

    def test__tx_ring__loop_swallows_oserror(self) -> None:
        """
        Ensure an 'OSError' from 'os.writev' is caught so the TX
        thread does not crash on transient interface errors.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = self._make_ethernet()
        self._ring.enqueue(pkt)

        with patch(
            "pytcp.runtime.tx_ring.os.writev",
            side_effect=OSError("no buffer space"),
        ):
            self._ring._subsystem_loop()  # must not propagate the error

    def test__tx_ring__loop_unknown_packet_type_dropped(self) -> None:
        """
        Ensure packets of an unexpected type (not one of the five
        accepted assemblers) are logged and dropped — os.writev must
        not be called.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock()  # plain MagicMock, no spec -> unknown type
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"x")

        self._ring.enqueue(pkt)

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        mock_writev.assert_not_called()


class TestTxRingInnerDrain(_TxRingFixture):
    """
    The 'TxRing._subsystem_loop' inner-drain tests.
    """

    def _make_ethernet(self) -> MagicMock:
        """
        Build a MagicMock 'EthernetAssembler' for queue insertion.
        """

        pkt = MagicMock(spec=EthernetAssembler)
        pkt.__len__.return_value = 64

        def assemble(buffers: list[Buffer]) -> None:
            buffers.append(b"x" * 64)

        pkt.assemble.side_effect = assemble
        return pkt

    def test__tx_ring__loop_drains_all_pending_packets_per_get_wake(self) -> None:
        """
        Ensure a single '_subsystem_loop' invocation drains every
        packet currently in the TX ring queue, not just one. The
        inner-drain pattern mirrors the RX-side optimisation: the
        outer 'queue.get(block=True, timeout=0.1)' is the slow path;
        once awoken, the worker should drain the rest of the queue
        via cheap 'queue.get(block=False)' calls until the queue
        is empty, then yield back to the Subsystem driver.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        n_frames = 10
        for _ in range(n_frames):
            self._ring.enqueue(self._make_ethernet())

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        self.assertEqual(
            mock_writev.call_count,
            n_frames,
            msg=(
                f"A single _subsystem_loop call must drain all {n_frames} "
                f"queued packets in one pass. Got {mock_writev.call_count} "
                f"os.writev calls."
            ),
        )
        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="After the inner drain the deque must be empty.",
        )

    def test__tx_ring__loop_inner_drain_breaks_on_writev_oserror(self) -> None:
        """
        Ensure the inner-drain loop stops on the first 'os.writev'
        OSError. Repeatedly retrying when the interface is down /
        ENOBUFS would only burn cycles — better to yield and let
        the next outer-loop iteration check the stop event.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for _ in range(5):
            self._ring.enqueue(self._make_ethernet())

        with patch(
            "pytcp.runtime.tx_ring.os.writev",
            side_effect=OSError("link down"),
        ) as mock_writev:
            self._ring._subsystem_loop()

        # First writev errors → break. No further writev calls,
        # but exactly one drop counted.
        self.assertEqual(
            mock_writev.call_count,
            1,
            msg=(
                "Inner drain must break after the first writev OSError. "
                f"Expected 1 writev call; got {mock_writev.call_count}."
            ),
        )
        self.assertEqual(
            self._ring.os_error_drop_count,
            1,
            msg="Exactly one drop should be counted before the drain breaks.",
        )


class TestTxRingSharedPacketStats(_TxRingFixture):
    """
    The 'TxRing' shared-PacketStats integration tests.
    """

    def test__tx_ring__queue_full_drop_increments_shared_stats(self) -> None:
        """
        Ensure that when a 'PacketStatsTx' instance is wired in via
        the constructor's 'packet_stats=' kwarg, queue-full drops
        bump 'stats.tx_ring__queue_full__drop' instead of the
        ring's private internal counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib.packet_stats import PacketStatsTx

        stats = PacketStatsTx()
        ring = TxRing(fd=self._write_fd, mtu=1500, queue_max_size=1, packet_stats=stats)
        self.addCleanup(ring._stop)
        ring._tx_deque.append(MagicMock(spec=EthernetAssembler))

        ring.enqueue(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))

        self.assertEqual(
            stats.tx_ring__queue_full__drop,
            2,
            msg="Each enqueue-on-full drop must bump the shared PacketStatsTx field.",
        )
        self.assertEqual(
            ring.queue_full_drop_count,
            2,
            msg="queue_full_drop_count property must read the shared stats value.",
        )

    def test__tx_ring__os_error_drop_increments_shared_stats(self) -> None:
        """
        Ensure that 'os.writev' OSError increments
        'stats.tx_ring__os_error__drop' when stats are shared.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib.packet_stats import PacketStatsTx

        stats = PacketStatsTx()
        ring = TxRing(fd=self._write_fd, mtu=1500, packet_stats=stats)
        self.addCleanup(ring._stop)

        pkt = MagicMock(spec=EthernetAssembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"x" * 64)
        ring.enqueue(pkt)

        with patch(
            "pytcp.runtime.tx_ring.os.writev",
            side_effect=OSError("link down"),
        ):
            ring._subsystem_loop()

        self.assertEqual(
            stats.tx_ring__os_error__drop,
            1,
            msg="os.writev OSError must bump the shared PacketStatsTx field.",
        )


class TestTxRingDropCounters(_TxRingFixture):
    """
    The 'TxRing' drop-counter observability tests.
    """

    def test__tx_ring__queue_full_drop_count_starts_at_zero(self) -> None:
        """
        Ensure 'queue_full_drop_count' starts at 0 on a freshly
        constructed ring so monitors have a clean baseline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring.queue_full_drop_count,
            0,
            msg="A fresh TxRing must report queue_full_drop_count == 0.",
        )

    def test__tx_ring__os_error_drop_count_starts_at_zero(self) -> None:
        """
        Ensure 'os_error_drop_count' starts at 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring.os_error_drop_count,
            0,
            msg="A fresh TxRing must report os_error_drop_count == 0.",
        )

    def test__tx_ring__enqueue_increments_drop_count_on_full_queue(self) -> None:
        """
        Ensure 'queue_full_drop_count' bumps each time
        'enqueue' is called on a full ring. Without the counter,
        a saturated TX queue silently drops outbound packets.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500, queue_max_size=1)
        self.addCleanup(ring._stop)
        ring._tx_deque.append(MagicMock(spec=EthernetAssembler))

        ring.enqueue(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))

        self.assertEqual(
            ring.queue_full_drop_count,
            3,
            msg="Each full-queue drop must bump 'queue_full_drop_count' by exactly one.",
        )

    def test__tx_ring__loop_increments_os_error_drop_count(self) -> None:
        """
        Ensure 'os_error_drop_count' bumps each time 'os.writev'
        raises 'OSError' (interface down, ENOBUFS, etc.). Without
        the counter, link-down conditions silently lose every
        outbound packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        def _make_pkt() -> MagicMock:
            pkt = MagicMock(spec=EthernetAssembler)
            pkt.__len__.return_value = 64
            pkt.assemble.side_effect = lambda buffers: buffers.append(b"x" * 64)
            return pkt

        for _ in range(2):
            self._ring.enqueue(_make_pkt())

        with patch(
            "pytcp.runtime.tx_ring.os.writev",
            side_effect=OSError("link down"),
        ):
            self._ring._subsystem_loop()
            # Inner drain re-armed the eventfd on break; second
            # call processes the second packet.
            self._ring._subsystem_loop()

        self.assertEqual(
            self._ring.os_error_drop_count,
            2,
            msg="Each os.writev OSError must bump 'os_error_drop_count' by exactly one.",
        )


class TestTxRingDispatchFastPath(_TxRingFixture):
    """
    The '_TX_PROTO_DISPATCH' production fast-path tests — verify the
    dict is keyed by the actual production assembler classes so a
    real (non-mock) packet resolves via a single 'type()' lookup
    rather than the 'isinstance' fallback loop reserved for
    'MagicMock(spec=...)' fixtures.
    """

    def test__tx_ring__dispatch_dict_keys_are_production_assembler_classes(self) -> None:
        """
        Ensure '_TX_PROTO_DISPATCH' contains every production assembler
        class as a literal 'type' key. If a key were ever replaced with
        a string, a subclass, or removed, real packets would skip the
        O(1) fast path and silently degrade to the 'isinstance' walk —
        a regression mocked-only unit tests cannot catch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for cls in (
            EthernetAssembler,
            Ethernet8023Assembler,
            Ip6Assembler,
            Ip4Assembler,
            Ip4FragAssembler,
        ):
            self.assertIn(
                cls,
                tx_ring_module._TX_PROTO_DISPATCH,
                msg=(
                    f"{cls.__name__} must be a literal key of _TX_PROTO_DISPATCH so "
                    "type(packet) lookup hits the O(1) fast path. Missing keys force "
                    "the isinstance fallback loop on every send."
                ),
            )

    def test__tx_ring__send_one_real_assembler_resolves_via_type_lookup(self) -> None:
        """
        Ensure '_send_one' on a real (non-mock) 'EthernetAssembler'
        resolves its dispatch entry via the 'type()' dict-lookup fast
        path: 'dict.get' returns non-None and the 'isinstance' fallback
        loop is not entered. Existing unit tests use 'MagicMock(spec=X)'
        whose 'type(...)' is 'MagicMock', so they always exercise the
        fallback path — this test pins the production behaviour.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        get_calls: list[type] = []

        class _SpyDict(dict[type, tuple[bytes, int]]):
            """
            Wraps the production dispatch dict; records every '.get'
            key and fail-louds if the 'isinstance' fallback path
            iterates '.items()'.
            """

            @override
            def get(self, key: Any, default: Any = None) -> Any:
                get_calls.append(key)
                return super().get(key, default)

            @override
            def items(self) -> Any:
                raise AssertionError(
                    "isinstance fallback path entered — real EthernetAssembler should "
                    "resolve via 'type()' dict-lookup fast path, not via the "
                    "'.items()' iteration reserved for MagicMock(spec=...) fixtures."
                )

        spy_dispatch = _SpyDict(tx_ring_module._TX_PROTO_DISPATCH)
        real_assembler = EthernetAssembler()

        with (
            patch.object(tx_ring_module, "_TX_PROTO_DISPATCH", spy_dispatch),
            patch("pytcp.runtime.tx_ring.os.writev", return_value=14) as writev,
        ):
            sent_ok = self._ring._send_one(real_assembler)

        self.assertTrue(
            sent_ok,
            msg="_send_one on a real EthernetAssembler must return True (success).",
        )
        self.assertEqual(
            get_calls,
            [EthernetAssembler],
            msg=("_send_one must call _TX_PROTO_DISPATCH.get exactly once with type(packet); " f"got: {get_calls!r}"),
        )
        self.assertEqual(
            writev.call_count,
            1,
            msg="_send_one must invoke os.writev exactly once on a successful dispatch.",
        )


class TestTxRingDispatch(_TxRingFixture):
    """
    The 'TxRing.dispatch' ring-handoff (single-writer) tests. The
    TX worker thread is the sole executor of a marshaled '_phtx_*'
    pipeline; 'dispatch' marshals the callable to the worker and
    blocks for its 'TxStatus' result, except when there is no live
    worker (unit-test / pre-start path) or the caller IS the worker
    (re-entrant solicitation), in which case it runs inline.
    """

    def test__tx_ring__dispatch_runs_inline_when_no_worker(self) -> None:
        """
        Ensure 'dispatch' runs the callable inline on the calling
        thread when the worker has not been started, and returns its
        'TxStatus'. With no worker to hand off to, blocking would
        deadlock; running inline preserves the synchronous contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ran_on: list[threading.Thread] = []

        def run() -> TxStatus:
            ran_on.append(threading.current_thread())
            return TxStatus.PASSED__ETHERNET__TO_TX_RING

        result = self._ring.dispatch(run)

        self.assertEqual(
            result,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="dispatch must return the callable's TxStatus when running inline.",
        )
        self.assertEqual(
            ran_on,
            [threading.current_thread()],
            msg="With no worker, dispatch must run the callable on the calling thread.",
        )

    def test__tx_ring__dispatch_marshals_to_worker_thread(self) -> None:
        """
        Ensure 'dispatch' from a non-worker thread, with a live
        worker, executes the callable on the worker thread (not the
        caller's) and blocks until the worker returns the result.
        This is the single-writer guarantee: the per-interface
        '_phtx_*' state writes happen only on the worker thread.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500)
        ring.start()
        self.addCleanup(ring.stop)

        ran_on: list[threading.Thread] = []

        def run() -> TxStatus:
            ran_on.append(threading.current_thread())
            return TxStatus.PASSED__IP6__TO_TX_RING

        result = ring.dispatch(run)

        self.assertEqual(
            result,
            TxStatus.PASSED__IP6__TO_TX_RING,
            msg="dispatch must block for and return the worker's TxStatus result.",
        )
        self.assertEqual(
            ran_on,
            [ring._thread],
            msg="dispatch from a non-worker thread must execute the callable on the worker thread.",
        )

    def test__tx_ring__dispatch_runs_inline_when_called_from_worker(self) -> None:
        """
        Ensure a 'dispatch' issued from within a callable already
        running on the worker thread (the re-entrant solicitation
        case — a '_phtx_*' pipeline emitting an ARP/ND probe) runs
        the nested callable inline rather than re-enqueuing onto its
        own queue and deadlocking waiting for itself.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500)
        ring.start()
        self.addCleanup(ring.stop)

        outer_thread: list[threading.Thread] = []
        inner_thread: list[threading.Thread] = []

        def inner() -> TxStatus:
            inner_thread.append(threading.current_thread())
            return TxStatus.PASSED__IP4__TO_TX_RING

        def outer() -> TxStatus:
            outer_thread.append(threading.current_thread())
            return ring.dispatch(inner)

        result = ring.dispatch(outer)

        self.assertEqual(
            result,
            TxStatus.PASSED__IP4__TO_TX_RING,
            msg="A re-entrant dispatch must return the nested callable's result without deadlock.",
        )
        self.assertEqual(
            inner_thread,
            outer_thread,
            msg="A re-entrant dispatch must run the nested callable on the same (worker) thread inline.",
        )
        self.assertEqual(
            outer_thread,
            [ring._thread],
            msg="The outer marshaled callable must run on the worker thread.",
        )

    def test__tx_ring__dispatch_propagates_exception_when_marshaled(self) -> None:
        """
        Ensure an exception raised by the callable on the worker
        thread is re-raised to the blocked caller, so 'send_*_packet'
        surfaces the same error it would have raised running inline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500)
        ring.start()
        self.addCleanup(ring.stop)

        def run() -> TxStatus:
            raise ValueError("boom")

        with self.assertRaises(ValueError) as ctx:
            ring.dispatch(run)

        self.assertEqual(
            str(ctx.exception),
            "boom",
            msg="dispatch must re-raise the worker-side exception verbatim to the caller.",
        )

    def test__tx_ring__dispatch_propagates_exception_when_inline(self) -> None:
        """
        Ensure an exception raised by the callable on the inline (no
        worker) path propagates directly to the caller.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        def run() -> TxStatus:
            raise ValueError("boom-inline")

        with self.assertRaises(ValueError) as ctx:
            self._ring.dispatch(run)

        self.assertEqual(
            str(ctx.exception),
            "boom-inline",
            msg="Inline dispatch must propagate the callable's exception unchanged.",
        )

    def test__tx_ring__loop_executes_request_and_drains_reenqueued_frame(self) -> None:
        """
        Ensure the worker loop, on popping a '_TxRequest', executes
        its callable (which itself enqueues the built frame back onto
        the same deque) and continues the inner drain to write that
        frame in the same pass — proving the queue carries both
        request and built-frame item kinds.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        def _make_ethernet() -> MagicMock:
            pkt = MagicMock(spec=EthernetAssembler)
            pkt.__len__.return_value = 64
            pkt.assemble.side_effect = lambda buffers: buffers.append(b"x" * 64)
            return pkt

        executed: list[bool] = []

        def run() -> TxStatus:
            executed.append(True)
            self._ring.enqueue(_make_ethernet())
            return TxStatus.PASSED__ETHERNET__TO_TX_RING

        request = tx_ring_module._TxRequest(run)
        self._ring._tx_deque.append(request)
        os.eventfd_write(self._ring._tx_event_fd, 1)

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        self.assertEqual(
            executed,
            [True],
            msg="The worker loop must execute the _TxRequest callable exactly once.",
        )
        self.assertEqual(
            request.result(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="The executed request must expose the callable's TxStatus result.",
        )
        mock_writev.assert_called_once()
        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="The re-enqueued built frame must be drained in the same loop pass.",
        )


class TestTxRingDispatchAsync(_TxRingFixture):
    """
    The 'TxRing.dispatch_async' fire-and-forget tests (Phase 4b). The
    caller enqueues the marshaled '_phtx_*' call and returns
    immediately without blocking for the worker's result; the worker
    still runs it on its own thread (single-writer preserved).
    """

    def test__tx_ring__dispatch_async_runs_inline_when_no_worker(self) -> None:
        """
        Ensure 'dispatch_async' runs the callable inline on the
        calling thread when no worker is live, returning None — the
        unit-test / boot path with no worker to hand off to.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ran_on: list[threading.Thread] = []

        def run() -> TxStatus:
            ran_on.append(threading.current_thread())
            return TxStatus.PASSED__ETHERNET__TO_TX_RING

        self._ring.dispatch_async(run)

        self.assertEqual(
            ran_on,
            [threading.current_thread()],
            msg="With no worker, dispatch_async must run the callable on the calling thread.",
        )

    def test__tx_ring__dispatch_async_marshals_to_worker_without_blocking(self) -> None:
        """
        Ensure 'dispatch_async' from a non-worker thread hands the
        callable to the worker thread for execution and returns None
        immediately rather than waiting for a result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500)
        ring.start()
        self.addCleanup(ring.stop)

        ran_on: list[threading.Thread] = []
        done = threading.Event()

        def run() -> TxStatus:
            ran_on.append(threading.current_thread())
            done.set()
            return TxStatus.PASSED__IP6__TO_TX_RING

        ring.dispatch_async(run)

        self.assertTrue(
            done.wait(timeout=2.0),
            msg="The worker must eventually execute the fire-and-forget callable.",
        )
        self.assertEqual(
            ran_on,
            [ring._thread],
            msg="dispatch_async must execute the callable on the worker thread.",
        )

    def test__tx_ring__dispatch_async_swallows_exception(self) -> None:
        """
        Ensure an exception raised by a fire-and-forget callable is
        swallowed (logged, not propagated) — there is no caller
        blocked to receive it, and a raise must not kill the TX loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        def run() -> TxStatus:
            raise ValueError("boom-async")

        # Must not raise (inline path, no worker) — the call returning
        # at all is the assertion; a propagated exception fails the test.
        self._ring.dispatch_async(run)


class TestTxRingRawFrame(_TxRingFixture):
    """
    The 'TxRing.enqueue_raw_frame' / verbatim-frame TX tests.
    """

    def test__tx_ring__enqueue_raw_frame_appends(self) -> None:
        """
        Ensure 'enqueue_raw_frame' places the verbatim frame bytes on
        the internal deque (the AF_PACKET egress primitive that skips
        the assembler / IP layers).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06payload"
        self._ring.enqueue_raw_frame(frame)

        self.assertEqual(
            list(self._ring._tx_deque),
            [frame],
            msg="enqueue_raw_frame() must place the verbatim frame on the TX ring.",
        )

    def test__tx_ring__enqueue_raw_frame_drops_when_full(self) -> None:
        """
        Ensure 'enqueue_raw_frame' silently drops the frame when the
        deque is already at capacity.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500, queue_max_size=1)
        self.addCleanup(ring._stop)
        ring.enqueue_raw_frame(b"first-frame")

        ring.enqueue_raw_frame(b"second-frame")  # must not raise

        self.assertEqual(
            len(ring._tx_deque),
            1,
            msg="enqueue_raw_frame() on a full TX ring must drop the new frame.",
        )

    def test__tx_ring__loop_writes_raw_frame_verbatim(self) -> None:
        """
        Ensure the subsystem loop writes a queued raw frame to the TX fd
        verbatim via 'os.writev', without prepending any ethertype
        framing prefix.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06payload"
        self._ring.enqueue_raw_frame(frame)

        with patch("pytcp.runtime.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        mock_writev.assert_called_once()
        fd_arg, buffers_arg = mock_writev.call_args.args
        self.assertEqual(fd_arg, self._write_fd, msg="os.writev must target the TX ring fd.")
        self.assertEqual(
            b"".join(bytes(b) for b in buffers_arg),
            frame,
            msg="A raw frame must be written verbatim, with no framing prefix added.",
        )
