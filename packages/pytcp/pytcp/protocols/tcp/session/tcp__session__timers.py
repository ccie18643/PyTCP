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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains the per-session TCP timer service —
'TcpTimerService' — which owns the per-session logical-timer
deadline map and the coalesced service handle. It is the
collaborator that closes the no-GIL backlog item T2: the
deadline-map mutations and the service-handle re-arm cycle now
run under their own 'threading.Lock' instead of overloading the
session's '_lock__fsm' RLock, so a non-FSM caller (notably
'send()' kicking the tx pump) no longer needs to acquire the
FSM lock just to arm a timer.

Lock ordering is '_lock__fsm' -> '_lock__timer' (FSM-context
callers may hold the FSM lock then arm timers); never the
reverse. The service-handle 'call_later(..., self.tcp_fsm,
timer=True)' callback runs lock-free on the timer worker
thread and re-acquires '_lock__fsm' on entry to 'tcp_fsm',
so no ordering edge ever runs '_lock__timer' -> '_lock__fsm'.

packages/pytcp/pytcp/protocols/tcp/session/tcp__session__timers.py

ver 3.0.10
"""

import threading
from typing import TYPE_CHECKING

from pytcp import stack
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.timer import TimerHandle

if TYPE_CHECKING:
    from pytcp.protocols.tcp.session import TcpSession


# Which logical timers may wake the session in each FSM state
# (the §4.3 scope matrix as data; §5.6/§5.7). The matrix is
# read by '_reschedule_locked' to compute the soonest relevant
# deadline. Mirrors '_SERVICED_TIMERS_BY_STATE' on
# 'tcp__session.py' — the constant is duplicated here rather
# than imported so the service module can be reasoned about
# standalone.
_PUMP: str = "tx_pump"
_SERVICED_TIMERS_BY_STATE: dict[FsmState, frozenset[str]] = {
    FsmState.SYN_SENT: frozenset({"retransmit", "persist", _PUMP}),
    FsmState.SYN_RCVD: frozenset({"retransmit", "persist", _PUMP}),
    FsmState.ESTABLISHED: frozenset({"retransmit", "persist", "delayed_ack", "keepalive", "rack", "tlp", _PUMP}),
    FsmState.CLOSE_WAIT: frozenset({"retransmit", "persist", "delayed_ack", _PUMP}),
    FsmState.FIN_WAIT_1: frozenset({"retransmit", "persist", _PUMP}),
    FsmState.FIN_WAIT_2: frozenset({_PUMP}),
    FsmState.CLOSING: frozenset({_PUMP}),
    FsmState.LAST_ACK: frozenset({"retransmit", "persist", _PUMP}),
    FsmState.TIME_WAIT: frozenset({"time_wait", _PUMP}),
}


class TcpTimerService:
    """
    Per-session logical-timer + coalesced-service-handle owner.
    """

    def __init__(self, session: "TcpSession", /) -> None:
        """
        Initialize the per-session timer service with an empty
        deadline map, no coalesced service handle, and a fresh
        non-reentrant lock guarding the two.
        """

        self._session: TcpSession = session
        # Per-session logical-timer deadline map (absolute
        # monotonic ms; key absent == not armed). Keyed by bare
        # logical name ("retransmit", "time_wait", "persist",
        # "delayed_ack", "challenge_ack", "keepalive", "tlp",
        # "rack", "tx_pump").
        self._deadlines: dict[str, int] = {}
        # Coalesced per-session service handle. Re-armed by
        # '_reschedule_locked' to the soonest deadline among
        # logical timers in scope for the current FSM state.
        self._service_handle: TimerHandle | None = None
        # Non-reentrant: the public methods take it exactly once
        # and call '_reschedule_locked' which assumes the lock is
        # held. A plain 'threading.Lock' is preferred over
        # 'RLock' so a future re-entrant misuse fails loudly
        # instead of silently nesting.
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public surface — every mutator/accessor takes '_lock' once.
    # ------------------------------------------------------------------

    def arm(self, name: str, delay_ms: int, /) -> None:
        """
        Arm or re-arm the named logical timer to fire 'delay_ms'
        milliseconds from now.
        """

        with self._lock:
            self._deadlines[name] = stack.timer.now_ms + delay_ms
            self._reschedule_locked()

    def cancel(self, name: str, /) -> None:
        """
        Cancel the named logical timer if armed.
        """

        with self._lock:
            self._deadlines.pop(name, None)
            self._reschedule_locked()

    def cancel_all(self) -> None:
        """
        Cancel every logical timer for this session and release
        the coalesced service handle. The session-teardown sweep
        that drops all of this session's armed timers in one call.
        """

        with self._lock:
            self._deadlines.clear()
            if self._service_handle is not None:
                stack.timer.cancel(self._service_handle)
                self._service_handle = None

    def armed(self, name: str, /) -> bool:
        """
        Return True iff the named logical timer is armed and has
        not yet fired (the 'is it still running?' query).
        """

        with self._lock:
            deadline = self._deadlines.get(name)
        return deadline is not None and stack.timer.now_ms < deadline

    def expired(self, name: str, /) -> bool:
        """
        Return True iff the named logical timer is armed and its
        deadline has passed. An unarmed timer is NOT expired:
        'never armed' and 'fired' are distinct states (see
        'armed' for the complementary 'still running?' query).
        """

        with self._lock:
            deadline = self._deadlines.get(name)
        return deadline is not None and stack.timer.now_ms >= deadline

    def reschedule(self) -> None:
        """
        Re-arm the coalesced service handle to the soonest deadline
        among the logical timers in scope for the current FSM
        state. Public re-entry point used after an out-of-band
        state change moves the relevant-timer set; idempotent and
        cheap to call repeatedly.
        """

        with self._lock:
            self._reschedule_locked()

    # ------------------------------------------------------------------
    # Internal helper — assumes '_lock' is held.
    # ------------------------------------------------------------------

    def _reschedule_locked(self) -> None:
        """
        Re-arm the coalesced per-session service handle to the
        soonest deadline among the logical timers serviced in the
        current state. The 1 ms periodic is gone (Phase 4c); this
        is the sole driver of timer-tick servicing. Assumes the
        caller holds 'self._lock'.
        """

        if self._service_handle is not None:
            stack.timer.cancel(self._service_handle)
            self._service_handle = None

        relevant = _SERVICED_TIMERS_BY_STATE.get(self._session._state, frozenset())
        pending = [deadline for name, deadline in self._deadlines.items() if name in relevant]
        if not pending:
            return

        # Floor at 1 ms, never 0. The old 1 ms periodic NEVER
        # serviced a timer instantly — it ticked at 1 ms
        # granularity, so a due/overdue timer was acted on at
        # the next ms tick. Reproducing that floor (a) keeps the
        # cadence byte-identical to the periodic and (b)
        # guarantees every service fire advances the clock by
        # >= 1 ms, so a handler that no-ops on an expired timer
        # without re-arming/cancelling it (legal under the old
        # poll) cannot spin the coalesced handle at delay 0 —
        # 'advance(N)' terminates in <= N service fires.
        delay_ms = max(1, min(pending) - stack.timer.now_ms)
        self._service_handle = stack.timer.call_later(delay_ms, self._session.tcp_fsm, timer=True)
