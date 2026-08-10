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
This module contains tests for the deterministic 'FakeTimer' fixture.

pytcp/tests/unit/lib/test__lib__fake_timer.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase
from unittest.mock import MagicMock, call

from pytcp.tests.lib.fake_timer import FakeTimer


class TestFakeTimer(TestCase):
    """
    The deterministic 'FakeTimer' clock and dispatch tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh 'FakeTimer'.
        """

        self._timer = FakeTimer()

    def test__fake_timer__now_ms_starts_at_zero(self) -> None:
        """
        Ensure a new 'FakeTimer' starts with its virtual clock at
        zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._timer.now_ms, 0, msg="now_ms must start at 0.")

    def test__fake_timer__advance_increments_now_ms(self) -> None:
        """
        Ensure 'advance' moves the virtual clock forward by the
        requested number of milliseconds.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.advance(100)
        self.assertEqual(self._timer.now_ms, 100, msg="advance(100) must set now_ms to 100.")

    def test__fake_timer__advance_negative_rejected(self) -> None:
        """
        Ensure a negative advance raises AssertionError — the
        virtual clock is monotonic.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            self._timer.advance(-1)

    def test__fake_timer__call_later_fires_at_advance(self) -> None:
        """
        Ensure a one-shot fires exactly once when the clock
        advances to its deadline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        self._timer.call_later(50, method)
        self._timer.advance(50)
        method.assert_called_once_with()

    def test__fake_timer__call_later_does_not_fire_before_deadline(self) -> None:
        """
        Ensure a one-shot does not fire while the clock is still
        short of its deadline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        self._timer.call_later(50, method)
        self._timer.advance(49)
        method.assert_not_called()

    def test__fake_timer__same_deadline_fires_in_registration_order(self) -> None:
        """
        Ensure entries sharing a deadline fire in registration
        order via the seq tiebreaker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        manager = MagicMock()
        self._timer.call_later(50, manager.m1)
        self._timer.call_later(50, manager.m2)
        self._timer.advance(50)
        self.assertEqual(
            manager.mock_calls,
            [call.m1(), call.m2()],
            msg="Same-deadline entries must fire in registration order.",
        )

    def test__fake_timer__advance_fires_periodics_multiple_times(self) -> None:
        """
        Ensure one long advance fires a periodic once per elapsed
        period.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        self._timer.call_periodic(50, method)
        self._timer.advance(150)
        self.assertEqual(method.call_count, 3, msg="A 50 ms periodic must fire 3 times across 150 ms.")

    def test__fake_timer__advance_partial_period_keeps_handle_live(self) -> None:
        """
        Ensure a periodic does not fire until a full period has
        elapsed even across split advances.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        self._timer.call_periodic(50, method)
        self._timer.advance(25)
        method.assert_not_called()
        self._timer.advance(25)
        method.assert_called_once_with()

    def test__fake_timer__cancel_prevents_fire(self) -> None:
        """
        Ensure cancelling a handle stops its callback from ever
        firing.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        handle = self._timer.call_later(50, method)
        self._timer.cancel(handle)
        self._timer.advance(100)
        method.assert_not_called()

    def test__fake_timer__callback_can_call_later_during_advance(self) -> None:
        """
        Ensure a callback may register a further entry mid-advance
        and that entry fires within the same advance window.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        inner = MagicMock()

        def outer() -> None:
            self._timer.call_later(0, inner)

        self._timer.call_later(10, outer)
        self._timer.advance(50)
        inner.assert_called_once_with()

    def test__fake_timer__now_ms_setter_rebases_pending_deadlines(self) -> None:
        """
        Ensure jumping the clock via the 'now_ms' setter shifts
        pending deadlines by the same delta so relative timing
        survives a clock-wrap jump.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        self._timer.call_later(50, method)
        self._timer.now_ms = 0xFFFF_FFFF
        method.assert_not_called()
        self._timer.advance(49)
        method.assert_not_called()
        self._timer.advance(1)
        method.assert_called_once_with()
        self.assertEqual(
            self._timer.now_ms,
            0xFFFF_FFFF + 50,
            msg="The clock must end at the rebased deadline window.",
        )
