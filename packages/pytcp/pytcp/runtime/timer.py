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
This module contains the stack-wide millisecond-resolution timer.

pytcp/runtime/timer.py

ver 3.0.10
"""

import heapq
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, override

from pytcp.lib.logger import log
from pytcp.runtime.subsystem import Subsystem

# Ceiling on the worker's idle wait. When the heap is empty the
# worker blocks on 'threading.Event.wait(timeout=_IDLE_WAKEUP__SEC)'
# rather than forever, so the stop event is re-checked at least
# this often even on a fully idle stack.
_IDLE_WAKEUP__SEC: float = 60.0


@dataclass(slots=True, kw_only=True)
class TimerHandle:
    """
    Cancellation handle returned by 'Timer.call_later' and
    'Timer.call_periodic'. Pass it to 'Timer.cancel(handle)' to
    deactivate the entry; cancellation is lazy (the worker skips
    cancelled handles when they reach the top of the heap).
    """

    method: Callable[..., None]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    deadline_ms: int
    seq: int
    period_ms: int | None = None
    cancelled: bool = False


@dataclass(slots=True, order=True)
class _HeapEntry:
    """
    Heap node wrapping a 'TimerHandle'. Ordered solely by
    '(deadline_ms, seq)'; the handle itself is excluded from
    comparison so 'heapq' never inspects it.
    """

    deadline_ms: int
    seq: int
    handle: TimerHandle = field(compare=False)


class Timer(Subsystem):
    """
    Stack-wide millisecond-resolution timer Subsystem.

    Maintains a single min-heap of '_HeapEntry' nodes keyed by
    '(deadline_ms, seq)'. The worker thread (inherited from
    'Subsystem') sleeps on a 'threading.Event' until the nearest
    deadline or until a registration / cancellation wakes it, then
    pops and dispatches every due entry. Periodic entries are
    re-armed by advancing their deadline by exactly 'period_ms'
    (interval-based, so they do not drift).

    External callers register / cancel from arbitrary stack
    threads; '_lock' (RLock) guards every heap mutation. Callback
    invocation happens with the lock released so a handler may
    re-enter 'call_later' / 'cancel' without deadlocking.

    The public API is 'call_later' / 'call_periodic' / 'cancel'
    / 'now_ms'. (The legacy named-flag shim — 'register_timer' /
    'is_expired' / 'unregister_timers_with_prefix' — was removed
    once the TCP timer-client migration retired its last
    consumer; the FSM is now event-driven.)
    """

    _subsystem_name = "Timer"

    _heap: list[_HeapEntry]
    _lock: threading.RLock
    _wakeup: threading.Event
    _seq: int

    @override
    def __init__(self) -> None:
        """
        Class constructor.
        """

        super().__init__()

        self._heap = []
        self._lock = threading.RLock()
        self._wakeup = threading.Event()
        self._seq = 0

    @property
    def now_ms(self) -> int:
        """
        Get the wall-clock time in milliseconds, used by the RFC
        6298 RTO sample-collection hooks in 'TcpSession' to record
        outbound-segment send times and compute observed RTTs on
        ACK harvest. Backed by 'time.monotonic_ns()' so the value
        increases monotonically and is unaffected by wall-clock
        adjustments. Test deployments swap this 'Timer' for the
        deterministic 'FakeTimer' fixture which exposes the same
        'now_ms' surface over its virtual clock.
        """

        return time.monotonic_ns() // 1_000_000

    def _next_seq(self) -> int:
        """
        Return a fresh monotonic sequence number. Callers hold
        '_lock'; the counter breaks heap-key ties so same-deadline
        entries fire in registration order.
        """

        seq = self._seq
        self._seq += 1
        return seq

    def call_later(
        self,
        delay_ms: int,
        method: Callable[..., None],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> TimerHandle:
        """
        Schedule 'method(*args, **kwargs)' to fire once after
        'delay_ms' milliseconds. Returns a cancellation handle the
        caller must retain if it wants to cancel later.
        """

        assert delay_ms >= 0, f"call_later delay_ms must be >= 0; got {delay_ms}"

        with self._lock:
            handle = TimerHandle(
                method=method,
                args=args,
                kwargs=kwargs,
                deadline_ms=self.now_ms + delay_ms,
                seq=self._next_seq(),
            )
            heapq.heappush(self._heap, _HeapEntry(handle.deadline_ms, handle.seq, handle))

        self._wakeup.set()
        return handle

    def call_periodic(
        self,
        period_ms: int,
        method: Callable[..., None],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> TimerHandle:
        """
        Schedule 'method(*args, **kwargs)' to fire every
        'period_ms' milliseconds, starting 'period_ms' from now.
        Re-armed interval-based (no drift). Returns a cancellation
        handle the caller must retain if it wants to cancel later.
        """

        assert period_ms >= 1, f"call_periodic period_ms must be >= 1; got {period_ms}"

        with self._lock:
            handle = TimerHandle(
                method=method,
                args=args,
                kwargs=kwargs,
                deadline_ms=self.now_ms + period_ms,
                seq=self._next_seq(),
                period_ms=period_ms,
            )
            heapq.heappush(self._heap, _HeapEntry(handle.deadline_ms, handle.seq, handle))

        self._wakeup.set()
        return handle

    def cancel(self, handle: TimerHandle, /) -> None:
        """
        Mark 'handle' as cancelled. The worker drops it the next
        time it surfaces at the top of the heap. Idempotent; a
        no-op if the handle already fired or was already cancelled.
        """

        handle.cancelled = True
        self._wakeup.set()

    @override
    def stop(self) -> None:
        """
        Stop the subsystem. Sets the stop event and wakes the
        worker out of its 'Event.wait()' so teardown does not
        block for up to '_IDLE_WAKEUP__SEC' on an idle stack.
        """

        self._event__stop_subsystem.set()
        self._wakeup.set()
        super().stop()

    @override
    def _subsystem_loop(self) -> None:
        """
        Pop and dispatch every due heap entry, re-arm periodics,
        then block until the next deadline or a wakeup signal.
        """

        while True:
            self._wakeup.clear()

            with self._lock:
                now = self.now_ms

                due: list[TimerHandle] = []
                while self._heap and self._heap[0].deadline_ms <= now:
                    entry = heapq.heappop(self._heap)
                    if entry.handle.cancelled:
                        continue
                    due.append(entry.handle)

                for handle in due:
                    if handle.period_ms is not None and not handle.cancelled:
                        handle.deadline_ms += handle.period_ms
                        handle.seq = self._next_seq()
                        heapq.heappush(
                            self._heap,
                            _HeapEntry(handle.deadline_ms, handle.seq, handle),
                        )

                if self._heap:
                    wait_s = max(0.0, (self._heap[0].deadline_ms - now) / 1000.0)
                else:
                    wait_s = _IDLE_WAKEUP__SEC

            for handle in due:
                try:
                    handle.method(*handle.args, **handle.kwargs)
                except Exception:  # pylint: disable=broad-exception-caught
                    name = getattr(handle.method, "__name__", repr(handle.method))
                    __debug__ and log("timer", f"<r>Handler raised: {name}</>")

            if self._event__stop_subsystem.is_set():
                return

            self._wakeup.wait(timeout=wait_s)

            if self._event__stop_subsystem.is_set():
                return
