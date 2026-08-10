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
This module contains the per-session TCP timer-service lock-discipline
tests — pinning that the '_timer_deadlines' deadline map and the
coalesced '_service_handle' are mutated only while holding the
TcpTimerService's dedicated lock, so the timer-worker thread and the
caller threads (send() / connect() / FSM dispatch) cannot tear the map
on a free-threaded build. Closes the no-GIL backlog item T2.

packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__timer_service.py

ver 3.0.10
"""

import threading
from typing import override

from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL__ISS: int = 0x0000_1000


class _TrackingLock:
    """
    A non-reentrant lock recording the maximum hold depth reached so a
    test can prove a timer-deadline mutation acquired the lock and
    released it afterwards.
    """

    def __init__(self) -> None:
        """
        Wrap a real lock and start at zero hold depth.
        """

        self._lock = threading.Lock()
        self.depth = 0
        self.max_depth = 0

    def __enter__(self) -> "_TrackingLock":
        """
        Acquire the underlying lock and record the deeper hold.
        """

        self._lock.acquire()
        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        return self

    def __exit__(self, *_: object) -> None:
        """
        Record the shallower hold and release the underlying lock.
        """

        self.depth -= 1
        self._lock.release()


class TestTcpTimerServiceLocking(TcpTestCase):
    """
    The per-session TCP timer-service lock-discipline tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness, construct an active TCP session, and install
        a depth-tracking lock in place of the timer service's real lock.
        """

        super().setUp()
        self._session = self._make_active_session(iss=_LOCAL__ISS)
        self._tracking = _TrackingLock()
        # Pre-refactor this raises AttributeError on '_timers' (or '_lock'),
        # which is the red signal: the dedicated timer-service lock does
        # not exist yet.
        setattr(self._session._timers, "_lock", self._tracking)

    def test__tcp__timers__arm_holds_the_timer_lock(self) -> None:
        """
        Ensure arming a logical timer mutates the per-session deadline
        map under the TcpTimerService lock, so the timer-worker thread
        and an arming caller thread cannot tear the dict on a
        free-threaded build.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)

        self.assertGreaterEqual(
            self._tracking.max_depth,
            1,
            msg="Arming a logical timer must acquire the timer-service lock.",
        )
        self.assertEqual(
            self._tracking.depth,
            0,
            msg="Arming a logical timer must release the timer-service lock.",
        )

    def test__tcp__timers__cancel_holds_the_timer_lock(self) -> None:
        """
        Ensure cancelling a logical timer mutates the per-session
        deadline map under the TcpTimerService lock.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Prime the deadline map so cancel has something to pop.
        self._session._arm_timer("retransmit", 100)
        depth_after_arm = self._tracking.depth
        max_after_arm = self._tracking.max_depth

        self._session._cancel_timer("retransmit")

        self.assertGreaterEqual(
            self._tracking.max_depth,
            max(max_after_arm, 1),
            msg="Cancelling a logical timer must acquire the timer-service lock.",
        )
        self.assertEqual(
            self._tracking.depth,
            depth_after_arm,
            msg="Cancelling a logical timer must release the timer-service lock.",
        )

    def test__tcp__timers__cancel_all_holds_the_timer_lock(self) -> None:
        """
        Ensure cancelling every per-session logical timer at session
        teardown mutates the deadline map and releases the coalesced
        service handle under the TcpTimerService lock.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        self._session._arm_timer("delayed_ack", 40)

        self._session._cancel_all_timers()

        self.assertGreaterEqual(
            self._tracking.max_depth,
            1,
            msg="Cancelling every logical timer must acquire the timer-service lock.",
        )
        self.assertEqual(
            self._tracking.depth,
            0,
            msg="Cancelling every logical timer must release the timer-service lock.",
        )


class TestTcpTimerServiceBehaviourParity(TcpTestCase):
    """
    The per-session TCP timer-service behaviour-parity tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and construct an active TCP session for the
        behaviour-parity round-trips.
        """

        super().setUp()
        self._session = self._make_active_session(iss=_LOCAL__ISS)

    def test__tcp__timers__arm_then_armed_is_true(self) -> None:
        """
        Ensure arming a logical timer leaves it observable as armed via
        '_timer_armed' until its deadline passes, matching the
        pre-refactor semantics so the FSM handlers' arm-then-check
        pattern keeps working.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)

        self.assertTrue(
            self._session._timer_armed("retransmit"),
            msg="An armed logical timer must report '_timer_armed' True before its deadline.",
        )
        self.assertFalse(
            self._session._timer_expired("retransmit"),
            msg="A logical timer must NOT report expired before its deadline.",
        )

    def test__tcp__timers__advance_past_deadline_expires(self) -> None:
        """
        Ensure advancing the FakeTimer past a logical timer's deadline
        flips '_timer_expired' to True while '_timer_armed' goes
        False, matching the pre-refactor semantics so the FSM
        handlers' expiry-check pattern keeps working.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        # Cancel the coalesced service handle so the FakeTimer advance
        # does not also drive the FSM tail (we want to observe the
        # deadline-map state directly).
        self._session._cancel_all_timers()
        self._session._timers._deadlines["retransmit"] = self._timer.now_ms + 50
        self._timer.advance(ms=60)

        self.assertTrue(
            self._session._timer_expired("retransmit"),
            msg="A logical timer must report '_timer_expired' True after its deadline passes.",
        )
        self.assertFalse(
            self._session._timer_armed("retransmit"),
            msg="An expired logical timer must NOT report '_timer_armed' True.",
        )

    def test__tcp__timers__cancel_clears_armed(self) -> None:
        """
        Ensure cancelling a logical timer clears '_timer_armed', so the
        pre-refactor invariant that '_cancel_timer' removes the
        deadline-map entry is preserved by the service extraction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        self._session._cancel_timer("retransmit")

        self.assertFalse(
            self._session._timer_armed("retransmit"),
            msg="A cancelled logical timer must NOT report '_timer_armed' True.",
        )

    def test__tcp__timers__cancel_all_clears_every_armed(self) -> None:
        """
        Ensure '_cancel_all_timers' drops every armed logical timer at
        once and releases the coalesced service handle, so the
        teardown sweep on the CLOSED transition still leaves the
        deadline map empty.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        self._session._arm_timer("delayed_ack", 40)
        self._session._arm_timer("persist", 1000)

        self._session._cancel_all_timers()

        self.assertEqual(
            self._session._timers._deadlines,
            {},
            msg="'_cancel_all_timers' must empty the deadline map.",
        )
        self.assertIsNone(
            self._session._timers._service_handle,
            msg="'_cancel_all_timers' must release the coalesced service handle.",
        )

    def test__tcp__timers__kick_pump_arms_when_not_closed(self) -> None:
        """
        Ensure '_kick_pump' arms the tx-pump logical timer when the
        session is in a non-CLOSED state and is a no-op when the
        session is CLOSED, matching the pre-refactor '_kick_pump'
        contract so 'send()' continues to drive the FSM-pump.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._state = FsmState.ESTABLISHED
        self._session._kick_pump()
        self.assertTrue(
            self._session._timer_armed("tx_pump"),
            msg="'_kick_pump' from a non-CLOSED state must arm the tx-pump timer.",
        )

        self._session._cancel_all_timers()
        self._session._state = FsmState.CLOSED
        self._session._kick_pump()
        self.assertFalse(
            self._session._timer_armed("tx_pump"),
            msg="'_kick_pump' from the CLOSED state must NOT arm the tx-pump timer.",
        )
