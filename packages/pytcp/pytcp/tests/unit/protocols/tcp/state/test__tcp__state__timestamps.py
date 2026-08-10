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
Unit tests for TimestampsState.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__timestamps.py

ver 3.0.10
"""

import inspect
from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__timestamps import TimestampsState


class TestTimestampsState__Defaults(TestCase):
    """
    Defaults for 'TimestampsState'.
    """

    def test__timestamps__defaults(self) -> None:
        """
        Ensure send_ts defaults False and both ts_recent +
        ts_recent_updated_at_ms default to 0 — the canonical
        no-TSopt-negotiated state.

        Reference: RFC 7323 §2.2 (TSopt bilateral negotiation).
        """

        s = TimestampsState()
        self.assertFalse(s.send_ts, msg="send_ts must default to False.")
        self.assertEqual(s.ts_recent, 0, msg="ts_recent must default to 0.")
        self.assertEqual(s.ts_recent_updated_at_ms, 0, msg="ts_recent_updated_at_ms must default to 0.")


class TestTimestampsState__Update(TestCase):
    """
    Method behaviour for 'update'.
    """

    def test__timestamps__update_sets_both_fields(self) -> None:
        """
        Ensure 'update(tsval, now_ms)' sets both ts_recent and
        ts_recent_updated_at_ms in one call.

        Reference: RFC 7323 §4.3 (TS.Recent update rule).
        """

        s = TimestampsState()
        s.update(tsval=12345, now_ms=67890)
        self.assertEqual(s.ts_recent, 12345, msg="update must set ts_recent.")
        self.assertEqual(
            s.ts_recent_updated_at_ms,
            67890,
            msg="update must set ts_recent_updated_at_ms.",
        )


class TestTimestampsState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for TimestampsState.
    """

    def test__tcp_state__timestamps__is_slotted(self) -> None:
        """
        Ensure TimestampsState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(TimestampsState(), "__dict__"),
            msg="TimestampsState must be declared with slots=True (no per-instance __dict__).",
        )


class TestTimestampsState__KeywordOnlySignatures(TestCase):
    """
    Keyword-only enforcement on the TimestampsState mutator signatures.
    """

    def test__tcp_state__timestamps__methods_are_keyword_only(self) -> None:
        """
        Ensure the TimestampsState mutators reject positional arguments — their
        public parameters are keyword-only, pinning the call contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            inspect.signature(TimestampsState.update).parameters["tsval"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="TimestampsState.update 'tsval' must be keyword-only.",
        )
