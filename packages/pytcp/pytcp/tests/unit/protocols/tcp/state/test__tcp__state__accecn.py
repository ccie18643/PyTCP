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
This module contains unit tests for the per-session AccECN state
container in 'pytcp/protocols/tcp/state/tcp__state__accecn.py'.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__accecn.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__accecn import (
    ACCECN__COUNTER_MASK,
    ACCECN__INITIAL_BYTE_COUNTER,
    ACCECN__INITIAL_CE_BYTE_COUNTER,
    ACCECN__INITIAL_CEP,
    ACCECN__LAST_EMIT_SENTINEL,
    AccEcnState,
)


class TestAccEcnState__Defaults(TestCase):
    """
    Per-field default values pinning the post-construction state
    of 'AccEcnState'.
    """

    def setUp(self) -> None:
        """
        Construct a default state instance for every test.
        """

        self._state = AccEcnState()

    def test__accecn_state__enabled_default_false(self) -> None:
        """
        Ensure 'enabled' defaults to False so a freshly-constructed
        session does not believe AccECN was negotiated. Only the
        SYN+ACK handshake path flips this.

        Reference: RFC 9768 §3.1.1 (AccECN bilateral negotiation).
        """

        self.assertFalse(
            self._state.enabled,
            msg="AccEcnState.enabled must default to False.",
        )

    def test__accecn_state__synack_codepoint_default_zero(self) -> None:
        """
        Ensure 'synack_codepoint' defaults to 0 (Not-ECT) so a
        fresh listener has no captured codepoint to encode into a
        SYN+ACK before an AccECN-setup SYN actually arrives.

        Reference: RFC 9768 §3.1.1 (passive-side codepoint capture).
        """

        self.assertEqual(
            self._state.synack_codepoint,
            0,
            msg="AccEcnState.synack_codepoint must default to 0 (Not-ECT).",
        )

    def test__accecn_state__handshake_ack_pending_default_none(self) -> None:
        """
        Ensure 'handshake_ack_pending' defaults to None so post-
        handshake segments fall back to the regular 'r.cep & 7'
        ACE encoding rather than reusing a stale Table-3 value.

        Reference: RFC 9768 §3.2.2.1 (active-side handshake ACE).
        """

        self.assertIsNone(
            self._state.handshake_ack_pending,
            msg="AccEcnState.handshake_ack_pending must default to None.",
        )

    def test__accecn_state__r_cep_default_five(self) -> None:
        """
        Ensure 'r_cep' defaults to 5 (binary 101) so a freshly-
        negotiated session is distinguishable from value 0
        (special meaning) and from middlebox-zeroed fields. The
        low 3 bits 101 are the wire-emitted ACE on the third-leg
        ACK before any CE marks are seen.

        Reference: RFC 9768 §3.2.1 (initial cep value).
        """

        self.assertEqual(
            self._state.r_cep,
            5,
            msg="AccEcnState.r_cep must default to 5.",
        )
        self.assertEqual(
            ACCECN__INITIAL_CEP,
            5,
            msg="ACCECN__INITIAL_CEP constant must equal 5.",
        )

    def test__accecn_state__receiver_byte_counters_default_initial(self) -> None:
        """
        Ensure receiver-side per-codepoint byte counters default
        to (1, 0, 1) for (ECT(0), CE, ECT(1)) so a freshly-
        negotiated session is distinguishable from middlebox-
        zeroed fields. r.ce_b starts at 0 because zero CE marks
        is the expected steady state at connection start; r.e0b
        and r.e1b start at 1 to seed the §3.2.1 initial state.

        Reference: RFC 9768 §3.2.1 (initial byte counter values).
        """

        self.assertEqual(
            self._state.r_ect0_b,
            1,
            msg="AccEcnState.r_ect0_b must default to 1.",
        )
        self.assertEqual(
            self._state.r_ce_b,
            0,
            msg="AccEcnState.r_ce_b must default to 0.",
        )
        self.assertEqual(
            self._state.r_ect1_b,
            1,
            msg="AccEcnState.r_ect1_b must default to 1.",
        )
        self.assertEqual(
            ACCECN__INITIAL_BYTE_COUNTER,
            1,
            msg="ACCECN__INITIAL_BYTE_COUNTER constant must equal 1.",
        )
        self.assertEqual(
            ACCECN__INITIAL_CE_BYTE_COUNTER,
            0,
            msg="ACCECN__INITIAL_CE_BYTE_COUNTER constant must equal 0.",
        )

    def test__accecn_state__last_emit_default_sentinel(self) -> None:
        """
        Ensure last-emit trackers default to the -1 sentinel
        (outside the uint24 range of real counters) so the very
        first AccECN-option emission always sees 'changed' for
        all three slots and emits the full Length=11 form,
        seeding the peer with our initial state.

        Reference: RFC 9768 §3.2.3 (last-emit tracker semantics).
        """

        self.assertEqual(
            self._state.r_last_emit_e0b,
            -1,
            msg="AccEcnState.r_last_emit_e0b must default to -1.",
        )
        self.assertEqual(
            self._state.r_last_emit_ceb,
            -1,
            msg="AccEcnState.r_last_emit_ceb must default to -1.",
        )
        self.assertEqual(
            self._state.r_last_emit_e1b,
            -1,
            msg="AccEcnState.r_last_emit_e1b must default to -1.",
        )
        self.assertEqual(
            ACCECN__LAST_EMIT_SENTINEL,
            -1,
            msg="ACCECN__LAST_EMIT_SENTINEL constant must equal -1.",
        )

    def test__accecn_state__sender_state_default(self) -> None:
        """
        Ensure sender-side fields default to the §3.2.1 initial
        state: s.cep=5, s.e0b=1, s.e1b=1, s.ce_b=0, s.disabled
        False, mangling_detected False. A fresh session must
        compute deltas against a baseline matching what the peer
        would report on its first emission.

        Reference: RFC 9768 §3.2.1 (sender-side initial counters).
        Reference: RFC 9768 §3.2.2.1 (s.disabled sentinel).
        Reference: RFC 9768 §3.2.2.3 (mangling detector).
        """

        self.assertEqual(
            self._state.s_cep,
            5,
            msg="AccEcnState.s_cep must default to 5.",
        )
        self.assertEqual(
            self._state.s_ect0_b,
            1,
            msg="AccEcnState.s_ect0_b must default to 1.",
        )
        self.assertEqual(
            self._state.s_ect1_b,
            1,
            msg="AccEcnState.s_ect1_b must default to 1.",
        )
        self.assertEqual(
            self._state.s_ce_b,
            0,
            msg="AccEcnState.s_ce_b must default to 0.",
        )
        self.assertFalse(
            self._state.s_disabled,
            msg="AccEcnState.s_disabled must default to False.",
        )
        self.assertFalse(
            self._state.mangling_detected,
            msg="AccEcnState.mangling_detected must default to False.",
        )

    def test__accecn_state__counter_mask_is_uint24(self) -> None:
        """
        Ensure ACCECN__COUNTER_MASK encodes the 24-bit width of
        the AccECN option's counter slots. All r.* / s.* counter
        increments mask against this so they wrap at 2^24 per
        the option wire format.

        Reference: RFC 9768 §3.2.3 (counter wire-format width).
        """

        self.assertEqual(
            ACCECN__COUNTER_MASK,
            0xFF_FFFF,
            msg="ACCECN__COUNTER_MASK must equal 0xFF_FFFF (uint24).",
        )

    def test__accecn_state__instances_are_independent(self) -> None:
        """
        Ensure two distinct 'AccEcnState' instances do not share
        mutable state — each session must own its own counters.
        Slots-based dataclasses use fresh integer fields per
        instance; this test guards against accidental class-level
        defaults that would alias across sessions.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        state_a = AccEcnState()
        state_b = AccEcnState()
        state_a.r_cep = 99
        state_a.r_ce_b = 42
        self.assertEqual(
            state_b.r_cep,
            5,
            msg="Mutating one AccEcnState must not affect another.",
        )
        self.assertEqual(
            state_b.r_ce_b,
            0,
            msg="Mutating one AccEcnState must not affect another.",
        )


class TestAccEcnState__RecordReceivedCodepoint(TestCase):
    """
    'record_received_codepoint' increments the receiver-side r.*
    counters per the inbound IP-ECN codepoint.
    """

    def test__accecn_state__record_ce_bumps_cep_and_ceb(self) -> None:
        """
        Ensure ip_ecn=3 (CE) increments r.cep by 1 and r.ce_b by
        the payload length, and leaves r.ect0_b / r.ect1_b
        untouched.

        Reference: RFC 9768 §3.2.2 (r.cep increment on CE).
        Reference: RFC 9768 §3.2.3 (r.ce_b accumulation).
        """

        state = AccEcnState()
        baseline_cep = state.r_cep
        baseline_ect0 = state.r_ect0_b
        baseline_ect1 = state.r_ect1_b

        state.record_received_codepoint(ip_ecn=3, payload_len=1000)

        self.assertEqual(
            state.r_cep,
            baseline_cep + 1,
            msg="CE codepoint must advance r.cep by 1.",
        )
        self.assertEqual(
            state.r_ce_b,
            1000,
            msg="CE codepoint must accumulate payload bytes into r.ce_b.",
        )
        self.assertEqual(
            state.r_ect0_b,
            baseline_ect0,
            msg="CE codepoint must not touch r.ect0_b.",
        )
        self.assertEqual(
            state.r_ect1_b,
            baseline_ect1,
            msg="CE codepoint must not touch r.ect1_b.",
        )

    def test__accecn_state__record_ect0_bumps_ect0b_only(self) -> None:
        """
        Ensure ip_ecn=2 (ECT(0)) accumulates payload bytes into
        r.ect0_b only and does not advance r.cep.

        Reference: RFC 9768 §3.2.3 (per-codepoint byte accumulation).
        """

        state = AccEcnState()
        baseline_cep = state.r_cep

        state.record_received_codepoint(ip_ecn=2, payload_len=500)

        self.assertEqual(
            state.r_ect0_b,
            ACCECN__INITIAL_BYTE_COUNTER + 500,
            msg="ECT(0) must accumulate payload bytes into r.ect0_b.",
        )
        self.assertEqual(
            state.r_cep,
            baseline_cep,
            msg="ECT(0) must not advance r.cep.",
        )

    def test__accecn_state__record_ect1_bumps_ect1b_only(self) -> None:
        """
        Ensure ip_ecn=1 (ECT(1)) accumulates payload bytes into
        r.ect1_b only and does not advance r.cep.

        Reference: RFC 9768 §3.2.3 (per-codepoint byte accumulation).
        """

        state = AccEcnState()
        state.record_received_codepoint(ip_ecn=1, payload_len=200)
        self.assertEqual(
            state.r_ect1_b,
            ACCECN__INITIAL_BYTE_COUNTER + 200,
            msg="ECT(1) must accumulate payload bytes into r.ect1_b.",
        )

    def test__accecn_state__record_counter_wraps_at_uint24(self) -> None:
        """
        Ensure r.cep wraps modulo 2^24 per the AccECN option's
        counter width. A r.cep value of 2^24 - 1 followed by a CE
        increment must wrap to 0, not 2^24.

        Reference: RFC 9768 §3.2.3 (counter wire-format width).
        """

        state = AccEcnState()
        state.r_cep = ACCECN__COUNTER_MASK
        state.record_received_codepoint(ip_ecn=3, payload_len=1)
        self.assertEqual(
            state.r_cep,
            0,
            msg="r.cep must wrap modulo 2^24 on CE increment past max.",
        )


class TestAccEcnState__NextAceField(TestCase):
    """
    'next_ace_field' returns the 3-bit ACE value, consuming
    handshake_ack_pending if set.
    """

    def test__accecn_state__next_ace_consumes_handshake_pending(self) -> None:
        """
        Ensure 'next_ace_field' returns the Table-3 handshake
        value when 'handshake_ack_pending' is set, and clears the
        pending field so subsequent calls fall back to the
        regular form.

        Reference: RFC 9768 §3.2.2.1 (handshake ACE consumption).
        """

        state = AccEcnState()
        state.handshake_ack_pending = 0b110
        state.r_cep = 5

        first = state.next_ace_field()
        second = state.next_ace_field()

        self.assertEqual(
            first,
            0b110,
            msg="next_ace_field must return the handshake-pending value.",
        )
        self.assertEqual(
            second,
            5 & 0b111,
            msg="next_ace_field must fall back to r.cep & 7 once consumed.",
        )
        self.assertIsNone(
            state.handshake_ack_pending,
            msg="next_ace_field must clear handshake_ack_pending on consumption.",
        )

    def test__accecn_state__next_ace_uses_r_cep_low_three(self) -> None:
        """
        Ensure 'next_ace_field' returns 'r.cep & 0b111' when no
        handshake-pending value is set. Higher bits of r.cep are
        masked off because ACE is a 3-bit field.

        Reference: RFC 9768 §3.2.2.1 (ACE = r.cep mod 8).
        """

        state = AccEcnState()
        state.r_cep = 0b1011_010
        ace = state.next_ace_field()
        self.assertEqual(
            ace,
            0b010,
            msg="next_ace_field must return only the low 3 bits of r.cep.",
        )


class TestAccEcnState__NextEmitCounters(TestCase):
    """
    'next_emit_counters' picks the AccECN0 vs AccECN1 ordering and
    Length 11/8/5/2 abbreviation per §3.2.3.
    """

    def test__accecn_state__first_emission_picks_length_11(self) -> None:
        """
        Ensure the first call after construction picks AccECN0
        Length 11 (all three counters on wire) because all
        last-emit trackers are at the -1 sentinel and every
        counter is "changed" relative to it.

        Reference: RFC 9768 §3.2.3 (initial-emission seeding).
        """

        state = AccEcnState()
        accecn0, accecn1 = state.next_emit_counters()
        self.assertEqual(
            accecn0,
            (1, 0, 1),
            msg="First emission must pick AccECN0 with all three counters.",
        )
        self.assertIsNone(
            accecn1,
            msg="AccECN1 must be None when AccECN0 is selected.",
        )

    def test__accecn_state__subsequent_unchanged_picks_length_2(self) -> None:
        """
        Ensure that when no counter changed since the last
        emission the method returns AccECN0 with all-None slots
        (Length 2, the empty-counters wire form).

        Reference: RFC 9768 §3.2.3.3 (Length 2 abbreviation).
        """

        state = AccEcnState()
        state.next_emit_counters()  # seed last-emit trackers
        accecn0, accecn1 = state.next_emit_counters()
        self.assertEqual(
            accecn0,
            (None, None, None),
            msg="Unchanged-since-last-emit must yield AccECN0 Length 2.",
        )
        self.assertIsNone(
            accecn1,
            msg="AccECN1 must be None.",
        )

    def test__accecn_state__advances_last_emit_trackers(self) -> None:
        """
        Ensure 'next_emit_counters' advances the last-emit
        trackers to the current r.* values, so the next call
        compares against the freshly-emitted state.

        Reference: RFC 9768 §3.2.3 (last-emit tracker semantics).
        """

        state = AccEcnState()
        state.r_ect0_b = 100
        state.r_ce_b = 50
        state.r_ect1_b = 75
        state.next_emit_counters()
        self.assertEqual(
            state.r_last_emit_e0b,
            100,
            msg="r_last_emit_e0b must advance to current r_ect0_b.",
        )
        self.assertEqual(
            state.r_last_emit_ceb,
            50,
            msg="r_last_emit_ceb must advance to current r_ce_b.",
        )
        self.assertEqual(
            state.r_last_emit_e1b,
            75,
            msg="r_last_emit_e1b must advance to current r_ect1_b.",
        )


class TestAccEcnState__ApparentCeDelta(TestCase):
    """
    'apparent_ce_delta' computes the §3.2.2.5 fallback CE-delta
    for an inbound ACK without an AccECN option.
    """

    def test__accecn_state__apparent_delta_advances_s_cep(self) -> None:
        """
        Ensure a positive ACE delta advances s.cep by the delta
        and returns the delta. With s.cep low 3 bits = 0b101 and
        incoming ACE = 0b111, the apparent delta is 0b010 = 2.

        Reference: RFC 9768 §3.2.2.5 (ACE-based fallback).
        """

        state = AccEcnState()
        state.s_cep = 0b101
        delta = state.apparent_ce_delta(incoming_ace=0b111)
        self.assertEqual(
            delta,
            2,
            msg="apparent_ce_delta must return the 3-bit modular delta.",
        )
        self.assertEqual(
            state.s_cep,
            0b101 + 2,
            msg="apparent_ce_delta must advance s.cep by the delta.",
        )

    def test__accecn_state__apparent_delta_zero_when_idempotent(self) -> None:
        """
        Ensure a repeated ACE value (one whose low 3 bits match
        s.cep & 7) yields delta 0 and leaves s.cep unchanged.
        Subsequent ACKs reporting the same ACE are idempotent.

        Reference: RFC 9768 §3.2.2.5 (idempotency).
        """

        state = AccEcnState()
        state.s_cep = 0b101
        delta = state.apparent_ce_delta(incoming_ace=0b101)
        self.assertEqual(
            delta,
            0,
            msg="Matching ACE must yield delta 0.",
        )
        self.assertEqual(
            state.s_cep,
            0b101,
            msg="Matching ACE must leave s.cep unchanged.",
        )
