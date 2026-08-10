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
This module contains tests for the heap-based 'Timer' subsystem.

pytcp/tests/unit/runtime/test__runtime__timer.py

ver 3.0.9
"""

import threading
import time
from typing import Any, override
from unittest import TestCase
from unittest.mock import MagicMock, call, create_autospec, patch

from pytcp.runtime.timer import Timer, TimerHandle, _HeapEntry


class _ClockControlledTimerTestCase(TestCase):
    """
    Shared fixture: a 'Timer' with a patched monotonic clock and a
    manual single-pass loop driver, no worker thread.
    """

    @override
    def setUp(self) -> None:
        """
        Suppress subsystem / timer logging, patch 'time.monotonic_ns'
        to a controllable virtual clock, and build a fresh 'Timer'.
        """

        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log = self._subsystem_log_patch.start()
        self.addCleanup(self._subsystem_log_patch.stop)
        self._timer_log_patch = patch("pytcp.runtime.timer.log")
        self._timer_log = self._timer_log_patch.start()
        self.addCleanup(self._timer_log_patch.stop)

        self._now_ns = 1_000_000_000_000  # 1 s -> now_ms == 1_000_000
        self._monotonic_patch = patch(
            "pytcp.runtime.timer.time.monotonic_ns",
            side_effect=lambda: self._now_ns,
        )
        self._monotonic_patch.start()
        self.addCleanup(self._monotonic_patch.stop)

        self._timer = Timer()
        self._base_ms = self._timer.now_ms

    def _advance(self, ms: int) -> None:
        """
        Advance the virtual clock by 'ms' milliseconds.
        """

        self._now_ns += ms * 1_000_000

    def _drive_loop(self) -> None:
        """
        Run exactly one drain-and-dispatch pass of '_subsystem_loop'
        without spawning the worker thread or blocking on a wait.
        """

        self._timer._event__stop_subsystem.set()
        self._timer._subsystem_loop()
        self._timer._event__stop_subsystem.clear()


class _LifecycleTimerTestCase(TestCase):
    """
    Shared fixture: a 'Timer' with a real worker thread, logging
    suppressed, with guaranteed thread teardown.
    """

    @override
    def setUp(self) -> None:
        """
        Suppress logging and build a fresh 'Timer'.
        """

        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log_patch.start()
        self.addCleanup(self._subsystem_log_patch.stop)
        self._timer_log_patch = patch("pytcp.runtime.timer.log")
        self._timer_log_patch.start()
        self.addCleanup(self._timer_log_patch.stop)

        self._timer = Timer()

    @override
    def tearDown(self) -> None:
        """
        Stop the timer and drain any lingering worker thread.
        """

        self._timer._event__stop_subsystem.set()
        self._timer._wakeup.set()
        if self._timer._thread is not None:
            self._timer._thread.join(timeout=2.0)


class _Counter:
    """
    Thread-safe call counter used as a real (non-mock) callback for
    the concurrency tests.
    """

    def __init__(self) -> None:
        """
        Initialize the counter at zero.
        """

        self._lock = threading.Lock()
        self.count = 0

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        """
        Increment the counter under the lock.
        """

        with self._lock:
            self.count += 1


class TestTimerNowMs(TestCase):
    """
    The 'Timer.now_ms' property tests.
    """

    def test__timer__now_ms_returns_int(self) -> None:
        """
        Ensure 'now_ms' returns an int (milliseconds since the
        monotonic-clock epoch), the type the RFC 6298 RTO
        sampling code in 'TcpSession' expects.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.runtime.subsystem.log"):
            timer = Timer()

        self.assertIsInstance(
            timer.now_ms,
            int,
            msg="Timer.now_ms must return an int (milliseconds).",
        )

    def test__timer__now_ms_is_monotonic(self) -> None:
        """
        Ensure two successive 'now_ms' reads return values that
        never decrease — backed by 'time.monotonic_ns()' so the
        property is wall-clock-adjustment safe.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.runtime.subsystem.log"):
            timer = Timer()

        t0 = timer.now_ms
        t1 = timer.now_ms
        self.assertGreaterEqual(
            t1,
            t0,
            msg=f"Timer.now_ms must be monotonic; got t0={t0}, t1={t1}.",
        )

    def test__timer__now_ms_uses_monotonic_ns(self) -> None:
        """
        Ensure 'now_ms' divides 'time.monotonic_ns()' by 1_000_000
        — the documented backing primitive. Pinned via patching
        so a future regression that switched to 'time.time_ns()'
        (wall-clock, jump-prone) is caught.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.runtime.subsystem.log"):
            timer = Timer()

        with patch("pytcp.runtime.timer.time.monotonic_ns", return_value=42_123_456_789):
            self.assertEqual(
                timer.now_ms,
                42_123,
                msg="now_ms must divide monotonic_ns() by 1_000_000.",
            )


class TestTimerHandle(TestCase):
    """
    The 'TimerHandle' dataclass invariant tests.
    """

    @staticmethod
    def _make() -> TimerHandle:
        """
        Build a minimal one-shot handle.
        """

        return TimerHandle(
            method=MagicMock(),
            args=(),
            kwargs={},
            deadline_ms=0,
            seq=0,
        )

    def test__timer_handle__has_slots(self) -> None:
        """
        Ensure 'TimerHandle' is slot-based so an accidental
        attribute assignment fails loudly instead of silently
        shadowing scheduler state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._make()
        self.assertTrue(
            hasattr(TimerHandle, "__slots__"),
            msg="TimerHandle must declare __slots__.",
        )
        with self.assertRaises(AttributeError):
            handle.foo = 1  # type: ignore[attr-defined]

    def test__timer_handle__cancelled_starts_false(self) -> None:
        """
        Ensure a freshly constructed handle is not cancelled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            self._make().cancelled,
            False,
            msg="A new TimerHandle must start with cancelled=False.",
        )

    def test__timer_handle__period_ms_none_means_one_shot(self) -> None:
        """
        Ensure 'period_ms' defaults to None, the one-shot marker
        the worker uses to decide whether to re-arm an entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(
            self._make().period_ms,
            msg="TimerHandle.period_ms must default to None (one-shot).",
        )


class TestTimerCoreApi(_ClockControlledTimerTestCase):
    """
    The 'Timer.call_later' / 'call_periodic' / 'cancel' core tests.
    """

    def test__timer__call_later_returns_handle(self) -> None:
        """
        Ensure 'call_later' returns a one-shot 'TimerHandle' whose
        absolute deadline is 'now_ms + delay_ms'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_later(100, MagicMock())
        self.assertIsInstance(handle, TimerHandle, msg="call_later must return a TimerHandle.")
        self.assertIs(handle.cancelled, False, msg="A new handle must not be cancelled.")
        self.assertIsNone(handle.period_ms, msg="call_later must produce a one-shot handle.")
        self.assertEqual(
            handle.deadline_ms,
            self._base_ms + 100,
            msg="call_later deadline must be now_ms + delay_ms.",
        )

    def test__timer__call_periodic_returns_handle(self) -> None:
        """
        Ensure 'call_periodic' returns a periodic 'TimerHandle'
        whose first deadline is 'now_ms + period_ms'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_periodic(50, MagicMock())
        self.assertEqual(handle.period_ms, 50, msg="call_periodic must record period_ms.")
        self.assertIs(handle.cancelled, False, msg="A new handle must not be cancelled.")
        self.assertEqual(
            handle.deadline_ms,
            self._base_ms + 50,
            msg="call_periodic first deadline must be now_ms + period_ms.",
        )

    def test__timer__call_later_zero_delay_fires_immediately(self) -> None:
        """
        Ensure 'call_later(0, ...)' fires on the very next loop
        pass with no clock advance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        self._timer.call_later(0, method)
        self._drive_loop()
        method.assert_called_once_with()

    def test__timer__call_later_in_the_past_fires_immediately(self) -> None:
        """
        Ensure an entry whose deadline is already in the past
        fires on the next loop pass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        handle = TimerHandle(
            method=method,
            args=(),
            kwargs={},
            deadline_ms=self._base_ms - 500,
            seq=self._timer._next_seq(),
        )
        self._timer._heap.append(_HeapEntry(handle.deadline_ms, handle.seq, handle))
        self._drive_loop()
        method.assert_called_once_with()

    def test__timer__cancel_prevents_firing(self) -> None:
        """
        Ensure cancelling a handle before its deadline stops the
        callback from ever running.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        handle = self._timer.call_later(100, method)
        self._timer.cancel(handle)
        self._advance(200)
        self._drive_loop()
        method.assert_not_called()

    def test__timer__cancel_is_idempotent(self) -> None:
        """
        Ensure cancelling the same handle twice raises nothing and
        leaves it cancelled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_later(100, MagicMock())
        self._timer.cancel(handle)
        self._timer.cancel(handle)
        self.assertIs(handle.cancelled, True, msg="Double cancel must leave cancelled=True.")

    def test__timer__cancel_after_fire_is_noop(self) -> None:
        """
        Ensure cancelling a handle whose one-shot already fired is
        a harmless no-op and does not double-fire.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        handle = self._timer.call_later(5, method)
        self._advance(5)
        self._drive_loop()
        self._timer.cancel(handle)
        self.assertIs(handle.cancelled, True, msg="cancel must still set the flag post-fire.")
        method.assert_called_once_with()

    def test__timer__call_periodic_fires_repeatedly(self) -> None:
        """
        Ensure a periodic entry fires once per elapsed period as
        the clock advances across multiple loop passes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        self._timer.call_periodic(50, method)
        for _ in range(4):
            self._advance(50)
            self._drive_loop()
        self.assertEqual(
            method.call_count,
            4,
            msg="A 50 ms periodic must fire 4 times across 4 x 50 ms advances.",
        )

    def test__timer__call_periodic_reschedules_at_absolute_deadline(self) -> None:
        """
        Ensure a periodic entry re-arms by advancing its deadline
        by exactly 'period_ms' so it does not drift when the loop
        wakes late.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        handle = self._timer.call_periodic(50, method)

        self._advance(60)  # past the first (base+50) deadline
        self._drive_loop()
        self._advance(50)  # now at base+110
        self._drive_loop()

        self.assertEqual(method.call_count, 2, msg="Two periods elapsed -> two fires.")
        self.assertEqual(
            handle.deadline_ms,
            self._base_ms + 150,
            msg="Periodic deadline must progress 50/100/150 (no drift), not 50/110/160.",
        )

    def test__timer__cancel_periodic_stops_reschedule(self) -> None:
        """
        Ensure cancelling a periodic handle stops further
        re-arming after the in-flight cycle.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        handle = self._timer.call_periodic(50, method)
        self._advance(50)
        self._drive_loop()
        self._timer.cancel(handle)
        for _ in range(4):
            self._advance(50)
            self._drive_loop()
        self.assertEqual(
            method.call_count,
            1,
            msg="A cancelled periodic must not fire again after the cancel.",
        )

    def test__timer__same_deadline_fires_in_registration_order(self) -> None:
        """
        Ensure entries sharing one deadline fire in registration
        order, fixed by the monotonic seq tiebreaker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        manager = MagicMock()
        self._timer.call_later(50, manager.m1)
        self._timer.call_later(50, manager.m2)
        self._timer.call_later(50, manager.m3)
        self._advance(50)
        self._drive_loop()
        self.assertEqual(
            manager.mock_calls,
            [call.m1(), call.m2(), call.m3()],
            msg="Same-deadline entries must fire in registration order.",
        )

    def test__timer__multiple_deadlines_fire_in_deadline_order(self) -> None:
        """
        Ensure entries with distinct deadlines fire earliest
        first regardless of registration order.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        manager = MagicMock()
        self._timer.call_later(100, manager.late)
        self._timer.call_later(50, manager.early)
        self._timer.call_later(75, manager.mid)
        self._advance(100)
        self._drive_loop()
        self.assertEqual(
            manager.mock_calls,
            [call.early(), call.mid(), call.late()],
            msg="Entries must fire in ascending deadline order.",
        )

    def test__timer__callback_invokes_call_later_reentrantly(self) -> None:
        """
        Ensure a callback may register a new entry from inside its
        own invocation and that entry fires on a later pass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        inner = MagicMock()

        def outer() -> None:
            self._timer.call_later(50, inner)

        self._timer.call_later(0, outer)
        self._drive_loop()
        inner.assert_not_called()
        self._advance(50)
        self._drive_loop()
        inner.assert_called_once_with()

    def test__timer__callback_exception_isolated(self) -> None:
        """
        Ensure one callback raising does not prevent a sibling
        callback at the same deadline from running, and the loop
        logs the failure instead of crashing.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        bad = MagicMock(__name__="bad", side_effect=RuntimeError("boom"))
        good = MagicMock(__name__="good")
        self._timer.call_later(50, bad)
        self._timer.call_later(50, good)
        self._advance(50)
        self._drive_loop()
        bad.assert_called_once_with()
        good.assert_called_once_with()
        self.assertTrue(
            any(
                c.args and c.args[0] == "timer" and "Handler raised" in c.args[1]
                for c in self._timer_log.call_args_list
            ),
            msg="A raising handler must be logged on the 'timer' channel.",
        )

    def test__timer__handle_reuse_across_periodics(self) -> None:
        """
        Ensure a periodic uses one stable handle object whose
        deadline advances each cycle (not a fresh handle per
        cycle).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        handle = self._timer.call_periodic(50, method)
        for _ in range(3):
            self._advance(50)
            self._drive_loop()
        self.assertEqual(method.call_count, 3, msg="Three periods elapsed -> three fires.")
        self.assertEqual(
            handle.deadline_ms,
            self._base_ms + 200,
            msg="The single handle's deadline must progress 50/100/150/200.",
        )


class TestTimerLoopPort(_ClockControlledTimerTestCase):
    """
    The ported '_subsystem_loop' behavior tests (via the heap core).
    """

    def test__timer__loop_ticks_registered_tasks(self) -> None:
        """
        Ensure a periodic method registered via the core API fires
        when its deadline is reached on a loop pass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        self._timer.call_periodic(5, method)
        self._advance(5)
        self._drive_loop()
        method.assert_called_once_with()

    def test__timer__loop_purges_finished_tasks(self) -> None:
        """
        Ensure a one-shot entry leaves the heap empty once it has
        fired (no re-arm).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        self._timer.call_later(5, method)
        self._advance(5)
        self._drive_loop()
        self.assertEqual(
            self._timer._heap,
            [],
            msg="A fired one-shot must not remain on the heap.",
        )


class TestTimerWorkerLoop(_LifecycleTimerTestCase):
    """
    The 'Timer' worker-thread + wakeup-semantics tests.
    """

    def test__timer__worker_blocks_on_empty_heap(self) -> None:
        """
        Ensure the worker idles on an empty heap without firing
        anything or leaving the wakeup event set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.start()
        time.sleep(0.1)
        self.assertTrue(self._timer._thread is not None and self._timer._thread.is_alive())
        self.assertEqual(self._timer._heap, [], msg="An idle worker must keep the heap empty.")
        self.assertFalse(self._timer._wakeup.is_set(), msg="An idle worker must not leave wakeup set.")
        self._timer.stop()

    def test__timer__register_wakes_worker(self) -> None:
        """
        Ensure registering an entry on an idle worker wakes it and
        the callback fires near its deadline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.start()
        time.sleep(0.05)
        counter = _Counter()
        self._timer.call_later(10, counter)
        deadline = time.monotonic() + 1.0
        while counter.count == 0 and time.monotonic() < deadline:
            time.sleep(0.005)
        self._timer.stop()
        self.assertEqual(counter.count, 1, msg="A registered one-shot must fire on the worker.")

    def test__timer__cancel_wakes_worker_if_top(self) -> None:
        """
        Ensure cancelling the top-of-heap entry prevents its
        callback from running on the worker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.start()
        counter = _Counter()
        handle = self._timer.call_later(50, counter)
        self._timer.cancel(handle)
        time.sleep(0.2)
        self._timer.stop()
        self.assertEqual(counter.count, 0, msg="A cancelled top entry must not fire.")

    def test__timer__idle_wakeup_ceiling(self) -> None:
        """
        Ensure the worker bounds its idle wait at
        '_IDLE_WAKEUP__SEC' when the heap is empty.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        timer = self._timer
        fake_event = create_autospec(threading.Event, spec_set=True)
        fake_event.wait.side_effect = lambda timeout=None: timer._event__stop_subsystem.set()
        timer._wakeup = fake_event
        with patch("pytcp.runtime.timer._IDLE_WAKEUP__SEC", 0.05):
            timer._subsystem_loop()
        fake_event.wait.assert_called_once_with(timeout=0.05)

    def test__timer__stop_breaks_out_of_wait(self) -> None:
        """
        Ensure 'stop()' wakes a worker blocked on the idle wait so
        teardown returns promptly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.start()
        time.sleep(0.05)
        t0 = time.monotonic()
        self._timer.stop()
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 2.0, msg="stop() must not block on the idle wait.")
        self.assertFalse(
            self._timer._thread is not None and self._timer._thread.is_alive(),
            msg="The worker thread must be dead after stop().",
        )

    def test__timer__simultaneous_register_during_dispatch(self) -> None:
        """
        Ensure an entry registered from inside a callback is not
        dispatched in the same batch but fires on the next pass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer._event__stop_subsystem.set()
        inner = MagicMock()

        def outer() -> None:
            self._timer.call_later(0, inner)

        self._timer.call_later(0, outer)
        self._timer._subsystem_loop()
        inner.assert_not_called()
        self._timer._subsystem_loop()
        inner.assert_called_once_with()


class TestTimerThreadSafety(_LifecycleTimerTestCase):
    """
    The 'Timer' concurrency / locking tests.
    """

    def test__timer__concurrent_register_no_loss(self) -> None:
        """
        Ensure registrations from many threads while the worker
        runs are never dropped.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.start()
        counter = _Counter()

        def register() -> None:
            self._timer.call_later(0, counter)

        threads = [threading.Thread(target=register) for _ in range(100)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        deadline = time.monotonic() + 2.0
        while counter.count < 100 and time.monotonic() < deadline:
            time.sleep(0.005)
        self._timer.stop()
        self.assertEqual(counter.count, 100, msg="Every concurrent registration must fire exactly once.")

    def test__timer__concurrent_cancel_no_double_fire(self) -> None:
        """
        Ensure many threads cancelling one periodic handle stop it
        cleanly with no exception and no further fires.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.start()
        counter = _Counter()
        handle = self._timer.call_periodic(1, counter)
        time.sleep(0.05)

        threads = [threading.Thread(target=lambda: self._timer.cancel(handle)) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        time.sleep(0.05)
        settled = counter.count
        time.sleep(0.1)
        self._timer.stop()
        self.assertEqual(
            counter.count,
            settled,
            msg="A cancelled periodic must stop firing across all cancel threads.",
        )

    def test__timer__lock_held_during_heap_mutation_not_callback(self) -> None:
        """
        Ensure the heap lock is released during callback
        invocation so another thread can register concurrently.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.start()
        in_callback = threading.Event()

        def slow() -> None:
            in_callback.set()
            time.sleep(0.05)

        self._timer.call_later(0, slow)
        self.assertTrue(in_callback.wait(timeout=1.0), msg="The slow callback must start.")

        second = _Counter()
        t0 = time.monotonic()
        self._timer.call_later(0, second)
        register_elapsed = time.monotonic() - t0

        deadline = time.monotonic() + 1.0
        while second.count == 0 and time.monotonic() < deadline:
            time.sleep(0.005)
        self._timer.stop()

        self.assertLess(
            register_elapsed,
            0.04,
            msg="call_later must not block behind an in-flight callback (lock released).",
        )
        self.assertEqual(second.count, 1, msg="The concurrently-registered entry must fire.")
