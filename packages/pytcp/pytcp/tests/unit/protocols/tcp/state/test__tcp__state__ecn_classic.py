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
Unit tests for ClassicEcnState dataclass.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__ecn_classic.py

ver 3.0.8
"""

import inspect
from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__ecn_classic import ClassicEcnState


class TestClassicEcnState__Defaults(TestCase):
    """
    Per-field default values for 'ClassicEcnState'.
    """

    def test__ecn_classic__defaults(self) -> None:
        """
        Ensure all four fields default to inactive: enabled
        False, send_ece False, send_cwr False, recovery_point 0.

        Reference: RFC 3168 §6.1.1 (ECN bilateral negotiation).
        """

        s = ClassicEcnState()
        self.assertFalse(s.enabled, msg="enabled must default to False.")
        self.assertFalse(s.send_ece, msg="send_ece must default to False.")
        self.assertFalse(s.send_cwr, msg="send_cwr must default to False.")
        self.assertEqual(
            s.recovery_point,
            0,
            msg="recovery_point must default to 0 (no one-shot gate active).",
        )


class TestClassicEcnState__Methods(TestCase):
    """
    Method behaviour for ClassicEcnState.
    """

    def test__ecn_classic__arm_cwr_response_sets_state(self) -> None:
        """
        Ensure 'arm_cwr_response' marks the per-RTT recovery
        point at SND.NXT and arms send_cwr.

        Reference: RFC 3168 §6.1.2 (ECE response).
        """

        s = ClassicEcnState()
        s.arm_cwr_response(snd_nxt=12345)
        self.assertTrue(s.send_cwr, msg="arm_cwr_response must set send_cwr.")
        self.assertEqual(
            s.recovery_point,
            12345,
            msg="arm_cwr_response must stamp recovery_point to snd_nxt.",
        )

    def test__ecn_classic__consume_cwr_clears_and_returns(self) -> None:
        """
        Ensure 'consume_cwr' returns True and clears the flag on
        first call, then returns False on subsequent calls — the
        per-segment one-shot semantics.

        Reference: RFC 3168 §6.1.2 (CWR cleared on emission).
        """

        s = ClassicEcnState()
        s.send_cwr = True
        first = s.consume_cwr()
        second = s.consume_cwr()
        self.assertTrue(first, msg="consume_cwr must return True when armed.")
        self.assertFalse(second, msg="consume_cwr must return False on second call.")
        self.assertFalse(s.send_cwr, msg="consume_cwr must clear send_cwr.")

    def test__ecn_classic__consume_cwr_when_unarmed(self) -> None:
        """
        Ensure 'consume_cwr' returns False without side-effects
        when send_cwr is False.

        Reference: RFC 3168 §6.1.2 (no-op when unarmed).
        """

        s = ClassicEcnState()
        self.assertFalse(s.consume_cwr(), msg="consume_cwr must return False when unarmed.")


class TestClassicEcnState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for ClassicEcnState.
    """

    def test__tcp_state__ecn_classic__is_slotted(self) -> None:
        """
        Ensure ClassicEcnState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(ClassicEcnState(), "__dict__"),
            msg="ClassicEcnState must be declared with slots=True (no per-instance __dict__).",
        )


class TestClassicEcnState__KeywordOnlySignatures(TestCase):
    """
    Keyword-only enforcement on the ClassicEcnState mutator signatures.
    """

    def test__tcp_state__ecn_classic__methods_are_keyword_only(self) -> None:
        """
        Ensure the ClassicEcnState mutators reject positional arguments — their
        public parameters are keyword-only, pinning the call contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            inspect.signature(ClassicEcnState.arm_cwr_response).parameters["snd_nxt"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="ClassicEcnState.arm_cwr_response 'snd_nxt' must be keyword-only.",
        )
