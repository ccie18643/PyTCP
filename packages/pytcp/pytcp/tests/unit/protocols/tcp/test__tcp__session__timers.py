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
This module contains tests for the TcpSession logical-timer
deadline-map helpers (Phase 1 of the TCP timer-client migration).

pytcp/tests/unit/protocols/tcp/test__tcp__session__timers.py

ver 3.0.9
"""

import threading
from types import SimpleNamespace
from typing import override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.session.tcp__session import _PUMP
from pytcp.protocols.tcp.session.tcp__session__timers import TcpTimerService
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.timer import TimerHandle


class TestTcpSessionTimers(TestCase):
    """
    The TcpSession deadline-map timer-helper tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a bare TcpSession (no __init__) wired to a fake
        'stack.timer' with a controllable virtual clock, and
        attach a fresh 'TcpTimerService' so the delegator helper
        methods on the session have something to delegate to.
        """

        self._timer = SimpleNamespace(
            now_ms=1000,
            cancel=MagicMock(),
            call_later=MagicMock(return_value="HANDLE"),
        )
        # 'TcpTimerService' imports 'stack' via 'from pytcp import
        # stack' — patching 'stack.timer' on either consumer module
        # patches the same attribute, so a single patch covers both
        # the session module and the service module.
        self._stack_patch = patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.timer",
            self._timer,
            create=True,
        )
        self._stack_patch.start()
        self.addCleanup(self._stack_patch.stop)

        self._session = TcpSession.__new__(TcpSession)
        # Extra bare-session state for the §5.6/§5.7 mechanism
        # tests (harmless for the deadline-map helper tests).
        self._session._state = FsmState.ESTABLISHED
        self._session._lock__fsm = threading.RLock()
        self._session._tx = SimpleNamespace(buffer=bytearray())  # type: ignore[assignment]
        self._session._snd_seq = SimpleNamespace(una=0, max=0)  # type: ignore[assignment]
        self._session._closing = False
        # Wire the timer service AFTER the session state attributes
        # are populated — '_reschedule_locked' reads
        # 'self._session._state' on every public call.
        self._session._timers = TcpTimerService(self._session)

    def test__tcp__timers__arm_sets_absolute_deadline(self) -> None:
        """
        Ensure '_arm_timer' records an absolute deadline of
        'now_ms + delay_ms'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 200)
        self.assertEqual(
            self._session._timers._deadlines["retransmit"],
            1200,
            msg="_arm_timer must store now_ms + delay_ms as the absolute deadline.",
        )

    def test__tcp__timers__expired_false_when_unarmed(self) -> None:
        """
        Ensure '_timer_expired' is False for a timer that was
        never armed — an unarmed timer is not expired, a state
        distinct from the fired state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._session._timer_expired("retransmit"),
            msg="An unarmed timer must NOT report expired (de-conflation).",
        )

    def test__tcp__timers__expired_true_at_or_after_deadline(self) -> None:
        """
        Ensure '_timer_expired' becomes True exactly at the
        deadline and stays True after it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("tlp", 50)
        self._timer.now_ms = 1049
        self.assertFalse(
            self._session._timer_expired("tlp"),
            msg="Timer must not be expired one ms before its deadline.",
        )
        self._timer.now_ms = 1050
        self.assertTrue(
            self._session._timer_expired("tlp"),
            msg="Timer must be expired at its exact deadline.",
        )
        self._timer.now_ms = 1100
        self.assertTrue(
            self._session._timer_expired("tlp"),
            msg="Timer must remain expired after its deadline.",
        )

    def test__tcp__timers__armed_true_only_while_pending(self) -> None:
        """
        Ensure '_timer_armed' is True only while the timer is
        armed and has not yet fired (False unarmed, False once
        the deadline passes).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._session._timer_armed("rack"),
            msg="An unarmed timer must not report armed.",
        )
        self._session._arm_timer("rack", 30)
        self.assertTrue(
            self._session._timer_armed("rack"),
            msg="A pending timer must report armed.",
        )
        self._timer.now_ms = 1030
        self.assertFalse(
            self._session._timer_armed("rack"),
            msg="A fired timer must no longer report armed.",
        )

    def test__tcp__timers__cancel_clears_deadline(self) -> None:
        """
        Ensure '_cancel_timer' removes the deadline so the timer
        reports neither armed nor expired.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("persist", 100)
        self._session._cancel_timer("persist")
        self.assertNotIn(
            "persist",
            self._session._timers._deadlines,
            msg="_cancel_timer must drop the deadline entry.",
        )
        self.assertFalse(
            self._session._timer_armed("persist"),
            msg="A cancelled timer must not report armed.",
        )
        self.assertFalse(
            self._session._timer_expired("persist"),
            msg="A cancelled timer must not report expired.",
        )

    def test__tcp__timers__cancel_all_clears_map_and_handle(self) -> None:
        """
        Ensure '_cancel_all_timers' empties the deadline map and
        cancels and clears the coalesced service handle.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        self._session._arm_timer("delayed_ack", 40)
        handle = TimerHandle(method=MagicMock(), args=(), kwargs={}, deadline_ms=0, seq=0)
        self._session._timers._service_handle = handle

        self._session._cancel_all_timers()

        self.assertEqual(
            self._session._timers._deadlines,
            {},
            msg="_cancel_all_timers must empty the deadline map.",
        )
        # '_reschedule_service' (live since Phase 4c) also
        # cancels superseded intermediate handles, so assert the
        # contract — the final service handle was cancelled and
        # cleared — not an exact call count.
        self._timer.cancel.assert_any_call(handle)
        self.assertIsNone(
            self._session._timers._service_handle,
            msg="_cancel_all_timers must clear the service handle.",
        )

    def test__tcp__timers__rearm_overwrites_deadline(self) -> None:
        """
        Ensure re-arming an already-armed timer overwrites its
        deadline rather than keeping the stale one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        self._timer.now_ms = 1050
        self._session._arm_timer("retransmit", 100)
        self.assertEqual(
            self._session._timers._deadlines["retransmit"],
            1150,
            msg="Re-arm must overwrite the deadline with the fresh now_ms + delay_ms.",
        )

    def test__tcp__timers__challenge_ack_gate_truth_table(self) -> None:
        """
        Ensure the challenge-ACK gate decision the
        '_send_challenge_ack' path makes is exactly
        'not _timer_armed("challenge_ack")': emit when unarmed,
        suppress while armed-and-unfired, emit again once the
        rate-limit window has elapsed (then re-arm).

        Reference: RFC 5961 §3 (challenge-ACK rate-limit gate).
        """

        # Unarmed -> the gate would emit (not armed).
        self.assertFalse(
            self._session._timer_armed("challenge_ack"),
            msg="Unarmed gate must read not-armed so the first challenge ACK is emitted.",
        )

        # Emit path arms the window.
        self._session._arm_timer("challenge_ack", 1000)
        self.assertTrue(
            self._session._timer_armed("challenge_ack"),
            msg="Within the rate-limit window the gate must read armed so further ACKs are suppressed.",
        )

        # One ms before the window elapses -> still suppressed.
        self._timer.now_ms = 1999
        self.assertTrue(
            self._session._timer_armed("challenge_ack"),
            msg="One ms before the window elapses the gate must still read armed.",
        )

        # At the window boundary -> the gate re-opens (emit again).
        self._timer.now_ms = 2000
        self.assertFalse(
            self._session._timer_armed("challenge_ack"),
            msg="At the rate-limit boundary the gate must read not-armed so a fresh challenge ACK is emitted.",
        )

    def test__tcp__timers__reschedule_service_floors_delay_at_one(self) -> None:
        """
        Ensure '_reschedule_service' never arms the service
        handle at delay 0 — an overdue timer is scheduled at the
        1 ms floor, reproducing the periodic's 1 ms granularity
        and guaranteeing the coalesced handle cannot busy-loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Deadline already in the past (overdue).
        self._session._timers._deadlines["retransmit"] = self._timer.now_ms - 50
        self._session._reschedule_service()
        args, _ = self._timer.call_later.call_args
        self.assertEqual(
            args[0],
            1,
            msg="An overdue serviced timer MUST be scheduled at the 1 ms floor, never 0.",
        )

    def test__tcp__timers__reschedule_service_no_handle_when_nothing_armed(self) -> None:
        """
        Ensure '_reschedule_service' leaves no service handle
        when no serviced timer is armed — the zero-idle-CPU
        property.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._reschedule_service()
        self.assertIsNone(
            self._session._timers._service_handle,
            msg="With nothing armed there MUST be no coalesced service handle.",
        )
        self._timer.call_later.assert_not_called()

    def test__tcp__timers__reschedule_service_respects_state_scope(self) -> None:
        """
        Ensure '_reschedule_service' ignores a timer that is
        armed but not serviced in the current state, so an
        out-of-scope timer cannot wake the session.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # 'delayed_ack' is serviced in ESTABLISHED/CLOSE_WAIT,
        # NOT in SYN_SENT.
        self._session._state = FsmState.SYN_SENT
        self._session._timers._deadlines["delayed_ack"] = self._timer.now_ms + 10
        self._session._reschedule_service()
        self._timer.call_later.assert_not_called()
        self.assertIsNone(
            self._session._timers._service_handle,
            msg="A timer out of the current state's scope MUST NOT arm the service handle.",
        )

    def test__tcp__timers__has_pump_work(self) -> None:
        """
        Ensure '_has_pump_work' is True for unsent buffered
        data, in-flight data, or a pending close, and False when
        the session is fully quiescent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(self._session._has_pump_work(), msg="Quiescent session MUST have no pump work.")
        self._session._tx.buffer.extend(b"x")
        self.assertTrue(self._session._has_pump_work(), msg="Buffered data MUST be pump work.")
        self._session._tx.buffer.clear()
        self._session._snd_seq.una = 5
        self.assertTrue(self._session._has_pump_work(), msg="In-flight data MUST be pump work.")
        self._session._snd_seq.una = 0
        self._session._closing = True
        self.assertTrue(self._session._has_pump_work(), msg="A pending close MUST be pump work.")

    def test__tcp__timers__kick_pump_arms_tx_pump(self) -> None:
        """
        Ensure '_kick_pump' (the non-tcp_fsm-mutator hook used
        by 'send()') arms the 'tx_pump' one-shot at now + 1 ms.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._kick_pump()
        self.assertEqual(
            self._session._timers._deadlines.get(_PUMP),
            self._timer.now_ms + 1,
            msg="_kick_pump MUST arm tx_pump at now + 1 ms.",
        )

    def test__tcp__timers__kick_pump_noop_when_closed(self) -> None:
        """
        Ensure '_kick_pump' is a no-op once the session is
        CLOSED (terminal — never re-pumped).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._state = FsmState.CLOSED
        self._session._kick_pump()
        self.assertNotIn(
            _PUMP,
            self._session._timers._deadlines,
            msg="_kick_pump MUST NOT arm tx_pump on a CLOSED session.",
        )

    def test__tcp__timers__pump_tail_consumes_then_conditionally_rearms(self) -> None:
        """
        Ensure '_pump_tail' consumes tx_pump and re-arms it iff
        the dispatch was external, changed state, or left pump
        work — and otherwise leaves it cancelled (zero-idle).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Quiescent timer dispatch (not external, no state
        # change, no pump work) -> consumed, not re-armed.
        self._session._timers._deadlines[_PUMP] = self._timer.now_ms
        self._session._pump_tail(FsmState.ESTABLISHED, False)
        self.assertNotIn(
            _PUMP,
            self._session._timers._deadlines,
            msg="A fully quiescent dispatch MUST consume tx_pump and not re-arm it.",
        )

        # External dispatch -> re-armed at now + 1.
        self._session._pump_tail(FsmState.ESTABLISHED, True)
        self.assertEqual(
            self._session._timers._deadlines.get(_PUMP),
            self._timer.now_ms + 1,
            msg="An external dispatch MUST re-arm tx_pump at now + 1 ms.",
        )

        # Not external, no state change, but pump work pending
        # -> re-armed (pacing).
        self._session._timers._deadlines.pop(_PUMP, None)
        self._session._closing = True
        self._session._pump_tail(FsmState.ESTABLISHED, False)
        self.assertIn(
            _PUMP,
            self._session._timers._deadlines,
            msg="Pending pump work MUST keep tx_pump re-armed (pacing).",
        )
