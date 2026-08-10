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
Unit tests for RttSampleState dataclass.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__rtt_sample.py

ver 3.0.10
"""

import inspect
from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__rtt_sample import RttSampleState


class TestRttSampleState__Defaults(TestCase):
    """
    Per-field default values for 'RttSampleState'.
    """

    def test__rtt_sample__defaults(self) -> None:
        """
        Ensure seq, send_time_ms, last_send_time_ms default to
        None and retransmitted defaults to False — the canonical
        no-sample / fresh-session state.

        Reference: RFC 6298 §4 (sample collection).
        Reference: RFC 6298 §5.7 (idle-baseline tracker).
        """

        s = RttSampleState()
        self.assertIsNone(s.seq, msg="seq must default to None.")
        self.assertIsNone(s.send_time_ms, msg="send_time_ms must default to None.")
        self.assertFalse(s.retransmitted, msg="retransmitted must default to False.")
        self.assertIsNone(s.last_send_time_ms, msg="last_send_time_ms must default to None.")


class TestRttSampleState__Methods(TestCase):
    """
    Method behaviour for RttSampleState.
    """

    def test__rtt_sample__record_sets_fields(self) -> None:
        """
        Ensure 'record' stores seq + send_time_ms and clears the
        Karn taint flag (a fresh sample is by definition not
        retransmitted yet).

        Reference: RFC 6298 §4 (sample collection).
        """

        s = RttSampleState()
        s.retransmitted = True  # leftover from prior sample
        s.record(seq=1234, send_time_ms=5000)
        self.assertEqual(s.seq, 1234, msg="record must set seq.")
        self.assertEqual(s.send_time_ms, 5000, msg="record must set send_time_ms.")
        self.assertFalse(
            s.retransmitted,
            msg="record must clear retransmitted.",
        )

    def test__rtt_sample__taint_sets_flag(self) -> None:
        """
        Ensure 'taint' sets retransmitted True without touching
        the seq / send_time_ms fields (the original sample
        timestamps stay so the harvest still sees the full
        ambiguity).

        Reference: RFC 6298 §3 (Karn's algorithm).
        """

        s = RttSampleState()
        s.record(seq=1000, send_time_ms=2000)
        s.taint()
        self.assertTrue(s.retransmitted, msg="taint must set retransmitted True.")
        self.assertEqual(s.seq, 1000, msg="taint must NOT touch seq.")
        self.assertEqual(s.send_time_ms, 2000, msg="taint must NOT touch send_time_ms.")

    def test__rtt_sample__clear_resets_to_default(self) -> None:
        """
        Ensure 'clear' returns the tracker to its no-sample
        baseline so a fresh sample can be recorded.

        Reference: RFC 6298 §4 (sample turnover).
        """

        s = RttSampleState()
        s.record(seq=999, send_time_ms=8888)
        s.taint()
        s.clear()
        self.assertIsNone(s.seq, msg="clear must reset seq to None.")
        self.assertIsNone(s.send_time_ms, msg="clear must reset send_time_ms to None.")
        self.assertFalse(s.retransmitted, msg="clear must reset retransmitted to False.")

    def test__rtt_sample__last_send_time_ms_independent(self) -> None:
        """
        Ensure 'last_send_time_ms' is a separate field that
        survives 'clear' on the in-flight tracker — the §5.7
        idle baseline persists across sample turnover.

        Reference: RFC 6298 §5.7 (idle-baseline persistence).
        """

        s = RttSampleState()
        s.last_send_time_ms = 10000
        s.record(seq=1, send_time_ms=10000)
        s.clear()
        self.assertEqual(
            s.last_send_time_ms,
            10000,
            msg="clear must NOT touch last_send_time_ms.",
        )


class TestRttSampleState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for RttSampleState.
    """

    def test__tcp_state__rtt_sample__is_slotted(self) -> None:
        """
        Ensure RttSampleState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(RttSampleState(), "__dict__"),
            msg="RttSampleState must be declared with slots=True (no per-instance __dict__).",
        )


class TestRttSampleState__KeywordOnlySignatures(TestCase):
    """
    Keyword-only enforcement on the RttSampleState mutator signatures.
    """

    def test__tcp_state__rtt_sample__methods_are_keyword_only(self) -> None:
        """
        Ensure the RttSampleState mutators reject positional arguments — their
        public parameters are keyword-only, pinning the call contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            inspect.signature(RttSampleState.record).parameters["seq"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="RttSampleState.record 'seq' must be keyword-only.",
        )
