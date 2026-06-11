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

from typing import override
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

    @override
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


class TestAccEcnState__RecordReceivedCodepointPerCodepoint(TestCase):
    """
    Exact per-codepoint byte-counter coverage of
    'record_received_codepoint' — the ECT(0) / ECT(1) / Not-ECT
    dispatch arms and the 2^24 wrap, which the CE-only existing
    test leaves unpinned.
    """

    def test__accecn_state__record_ect0_bumps_only_ect0_b(self) -> None:
        """
        Ensure ip_ecn=2 (ECT0) accumulates the payload length into
        r.ect0_b alone and leaves r.ce_b / r.ect1_b / r.cep untouched.

        Reference: RFC 9768 §3.2.3 (per-codepoint byte counters).
        """

        state = AccEcnState()
        state.record_received_codepoint(ip_ecn=2, payload_len=40)

        self.assertEqual(state.r_ect0_b, ACCECN__INITIAL_BYTE_COUNTER + 40, msg="ECT0 must add to r.ect0_b.")
        self.assertEqual(state.r_ce_b, ACCECN__INITIAL_CE_BYTE_COUNTER, msg="ECT0 must not touch r.ce_b.")
        self.assertEqual(state.r_ect1_b, ACCECN__INITIAL_BYTE_COUNTER, msg="ECT0 must not touch r.ect1_b.")
        self.assertEqual(state.r_cep, ACCECN__INITIAL_CEP, msg="ECT0 must not bump r.cep.")

    def test__accecn_state__record_ect1_bumps_only_ect1_b(self) -> None:
        """
        Ensure ip_ecn=1 (ECT1) accumulates the payload length into
        r.ect1_b alone and leaves r.ce_b / r.ect0_b / r.cep untouched.

        Reference: RFC 9768 §3.2.3 (per-codepoint byte counters).
        """

        state = AccEcnState()
        state.record_received_codepoint(ip_ecn=1, payload_len=60)

        self.assertEqual(state.r_ect1_b, ACCECN__INITIAL_BYTE_COUNTER + 60, msg="ECT1 must add to r.ect1_b.")
        self.assertEqual(state.r_ect0_b, ACCECN__INITIAL_BYTE_COUNTER, msg="ECT1 must not touch r.ect0_b.")
        self.assertEqual(state.r_ce_b, ACCECN__INITIAL_CE_BYTE_COUNTER, msg="ECT1 must not touch r.ce_b.")

    def test__accecn_state__record_not_ect_bumps_nothing(self) -> None:
        """
        Ensure ip_ecn=0 (Not-ECT) accumulates into none of the
        receiver byte counters.

        Reference: RFC 9768 §3.2.3 (only ECN-capable codepoints counted).
        """

        state = AccEcnState()
        state.record_received_codepoint(ip_ecn=0, payload_len=99)

        self.assertEqual(state.r_ect0_b, ACCECN__INITIAL_BYTE_COUNTER, msg="Not-ECT must not touch r.ect0_b.")
        self.assertEqual(state.r_ect1_b, ACCECN__INITIAL_BYTE_COUNTER, msg="Not-ECT must not touch r.ect1_b.")
        self.assertEqual(state.r_ce_b, ACCECN__INITIAL_CE_BYTE_COUNTER, msg="Not-ECT must not touch r.ce_b.")
        self.assertEqual(state.r_cep, ACCECN__INITIAL_CEP, msg="Not-ECT must not bump r.cep.")

    def test__accecn_state__record_ce_byte_counter_wraps_modulo_2_24(self) -> None:
        """
        Ensure the CE byte counter wraps modulo 2^24 (the AccECN
        option counter width).

        Reference: RFC 9768 §3.2.3 (24-bit counter wrap).
        """

        state = AccEcnState()
        state.r_ce_b = ACCECN__COUNTER_MASK
        state.record_received_codepoint(ip_ecn=3, payload_len=5)

        self.assertEqual(
            state.r_ce_b,
            4,
            msg="r.ce_b must wrap: (0xFFFFFF + 5) & 0xFFFFFF == 4.",
        )


class TestAccEcnState__SenderOptionCounters(TestCase):
    """
    'update_sender_counters_from_option' — the §3.2.3 abbreviation
    rule (omitted slots are None and leave the mirror unchanged).
    """

    def test__accecn_state__option_full_tuple_updates_all_mirrors(self) -> None:
        """
        Ensure a fully-populated option tuple installs all three
        sender byte-counter mirrors in (ect0, ce, ect1) order.

        Reference: RFC 9768 §3.2.1 (sender mirror state).
        """

        state = AccEcnState()
        state.update_sender_counters_from_option((11, 22, 33))

        self.assertEqual(state.s_ect0_b, 11, msg="Slot 0 must map to s.ect0_b.")
        self.assertEqual(state.s_ce_b, 22, msg="Slot 1 must map to s.ce_b.")
        self.assertEqual(state.s_ect1_b, 33, msg="Slot 2 must map to s.ect1_b.")

    def test__accecn_state__option_none_slots_leave_mirrors_unchanged(self) -> None:
        """
        Ensure an omitted (None) option slot leaves its sender mirror
        at the prior value — only the present slot is applied.

        Reference: RFC 9768 §3.2.3 (abbreviation rule slot omission).
        """

        state = AccEcnState()
        state.update_sender_counters_from_option((None, 99, None))

        self.assertEqual(state.s_ce_b, 99, msg="The present slot 1 must update s.ce_b.")
        self.assertEqual(state.s_ect0_b, ACCECN__INITIAL_BYTE_COUNTER, msg="An omitted slot 0 must leave s.ect0_b.")
        self.assertEqual(state.s_ect1_b, ACCECN__INITIAL_BYTE_COUNTER, msg="An omitted slot 2 must leave s.ect1_b.")


class TestAccEcnState__ApparentCeDeltaArithmetic(TestCase):
    """
    'apparent_ce_delta' — the 3-bit modular ACE subtraction, its
    wrap, and the s.cep accumulation.
    """

    def test__accecn_state__apparent_delta_simple(self) -> None:
        """
        Ensure a forward ACE field yields the straight 3-bit
        difference and advances s.cep by it.

        Reference: RFC 9768 §3.2.2.5 (ACE-based fallback).
        """

        state = AccEcnState()  # s.cep default 5 (0b101)
        delta = state.apparent_ce_delta(7)

        self.assertEqual(delta, 2, msg="apparent delta must be (7 - 5) & 0b111 == 2.")
        self.assertEqual(state.s_cep, 7, msg="s.cep must advance by the apparent delta to 7.")

    def test__accecn_state__apparent_delta_wraps_modulo_8(self) -> None:
        """
        Ensure an ACE field that has wrapped below the stored low 3
        bits is interpreted modulo 8 (a small forward delta), not as
        a negative jump.

        Reference: RFC 9768 §3.2.2.5 (3-bit modular ACE arithmetic).
        """

        state = AccEcnState()
        state.s_cep = 7
        delta = state.apparent_ce_delta(1)

        self.assertEqual(delta, 2, msg="apparent delta must be (1 - 7) & 0b111 == 2 (modular wrap).")
        self.assertEqual(state.s_cep, 9, msg="s.cep must advance to (7 + 2) & MASK == 9.")


class TestAccEcnState__CounterWrapAndMaskShape(TestCase):
    """
    Mask-shape coverage that distinguishes the AccECN 24-bit
    bitwise '& mask' from a modular '% mask' on the ECT(0) /
    ECT(1) byte counters and the 3-bit ACE field, plus the
    slotted-dataclass invariant.
    """

    def test__accecn_state__is_slotted(self) -> None:
        """
        Ensure AccEcnState is a slotted dataclass so it grows no
        per-instance __dict__ on the TcpSession.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(AccEcnState(), "__dict__"),
            msg="AccEcnState must be declared with slots=True.",
        )

    def test__accecn_state__ect0_byte_counter_masks_not_mods_on_wrap(self) -> None:
        """
        Ensure r.ect0_b wraps with a 24-bit bitmask, not a modulo
        2^24-1: at 0xFFFFFF + 40 the masked result is 39, whereas a
        '% mask' would yield 40.

        Reference: RFC 9768 §3.2.3 (24-bit counter bitmask wrap).
        """

        state = AccEcnState()
        state.r_ect0_b = ACCECN__COUNTER_MASK
        state.record_received_codepoint(ip_ecn=2, payload_len=40)

        self.assertEqual(state.r_ect0_b, 39, msg="r.ect0_b must wrap via '& 0xFFFFFF' to 39, not '% mask'.")

    def test__accecn_state__ect1_byte_counter_masks_not_mods_on_wrap(self) -> None:
        """
        Ensure r.ect1_b wraps with a 24-bit bitmask, not a modulo
        2^24-1, on overflow.

        Reference: RFC 9768 §3.2.3 (24-bit counter bitmask wrap).
        """

        state = AccEcnState()
        state.r_ect1_b = ACCECN__COUNTER_MASK
        state.record_received_codepoint(ip_ecn=1, payload_len=40)

        self.assertEqual(state.r_ect1_b, 39, msg="r.ect1_b must wrap via '& 0xFFFFFF' to 39, not '% mask'.")

    def test__accecn_state__ace_delta_uses_bitmask_not_modulo(self) -> None:
        """
        Ensure the 3-bit ACE delta is computed with '& 0b111', not
        '% 0b111': a full-7 delta survives as 7 under a bitmask but
        would collapse to 0 under a modulo.

        Reference: RFC 9768 §3.2.2.5 (3-bit modular ACE via bitmask).
        """

        state = AccEcnState()
        state.s_cep = 8  # low 3 bits == 0
        delta = state.apparent_ce_delta(7)

        self.assertEqual(delta, 7, msg="(7 - 0) & 0b111 must be 7 (a '% 0b111' would give 0).")
        self.assertEqual(state.s_cep, 15, msg="s.cep must advance to (8 + 7) & MASK == 15.")


class TestAccEcnState__NextEmitCountersSelection(TestCase):
    """
    The outbound AccECN-option counter selection
    ('next_emit_counters') — change detection against the
    last-emit trackers and the AccECN0 / AccECN1 ordering.
    """

    def test__accecn_state__first_emit_sends_all_three_via_accecn0(self) -> None:
        """
        Ensure the first emission (last-emit sentinels at -1, so all
        three counters read 'changed') sends the full
        (ect0, ce, ect1) tuple via AccECN0 and advances the trackers.

        Reference: RFC 9768 §3.2.3 (Length-11 first emission).
        """

        state = AccEcnState()

        accecn0, accecn1 = state.next_emit_counters()

        self.assertEqual(accecn0, (1, 0, 1), msg="First emit must send the full AccECN0 (ect0, ce, ect1) tuple.")
        self.assertIsNone(accecn1, msg="AccECN1 must be None when AccECN0 is selected.")

    def test__accecn_state__second_emit_with_no_change_is_empty(self) -> None:
        """
        Ensure a second emission with no counter change since the
        first yields the empty (None, None, None) AccECN0 tuple.

        Reference: RFC 9768 §3.2.3.3 (Length-2 empty option).
        """

        state = AccEcnState()
        state.next_emit_counters()  # sync trackers

        accecn0, accecn1 = state.next_emit_counters()

        self.assertEqual(accecn0, (None, None, None), msg="Unchanged second emit must be the empty AccECN0 tuple.")
        self.assertIsNone(accecn1, msg="AccECN1 must be None.")

    def test__accecn_state__ect1_only_change_selects_accecn1(self) -> None:
        """
        Ensure an ECT(1)-only advance since the last emission selects
        the AccECN1 ordering (ECT(1) first) with only the e1b slot
        populated.

        Reference: RFC 9768 §3.2.3 (AccECN1 ordering when ECT(1) leads).
        """

        state = AccEcnState()
        state.next_emit_counters()  # sync trackers
        state.record_received_codepoint(ip_ecn=1, payload_len=50)  # r.ect1_b: 1 -> 51

        accecn0, accecn1 = state.next_emit_counters()

        self.assertIsNone(accecn0, msg="AccECN0 must be None when ECT(1) leads.")
        self.assertEqual(accecn1, (None, None, 51), msg="An ECT(1)-only change must emit AccECN1 with only e1b.")
