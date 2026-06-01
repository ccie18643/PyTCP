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
This module contains unit tests for the per-session RACK + TLP
state container in 'pytcp/protocols/tcp/state/tcp__state__rack_tlp.py'.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__rack_tlp.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__rack_tlp import (
    RACK__REO_WND_MULT_INITIAL,
    RACK__REO_WND_PERSIST_DEFAULT,
    TLP__MAX_ACK_DELAY_MS_DEFAULT,
    RackTlpState,
)
from pytcp.protocols.tcp.tcp__rack import RackSegment


class TestRackTlpState__Defaults(TestCase):
    """
    Per-field default values pinning the post-construction state
    of 'RackTlpState'.
    """

    def setUp(self) -> None:
        """
        Construct a default state instance for every test.
        """

        self._state = RackTlpState()

    def test__rack_tlp_state__rack_segments_default_empty(self) -> None:
        """
        Ensure 'rack_segments' defaults to an empty dict so a
        freshly-constructed session has no scoreboard entries
        before any outbound segment fires.

        Reference: RFC 8985 §5.2 (per-segment scoreboard).
        """

        self.assertEqual(
            self._state.rack_segments,
            {},
            msg="RackTlpState.rack_segments must default to {}.",
        )

    def test__rack_tlp_state__rack_scalars_default_zero(self) -> None:
        """
        Ensure the §6.2 step 1-2 RACK scalars (min_rtt_ms,
        rtt_ms, xmit_ts, end_seq) all default to 0 — the
        uninitialised sentinel until the first newly-acked
        segment is observed and rack_update fires.

        Reference: RFC 8985 §6.2 step 1 (RACK scalar init).
        """

        self.assertEqual(
            self._state.rack_min_rtt_ms,
            0,
            msg="rack_min_rtt_ms must default to 0.",
        )
        self.assertEqual(
            self._state.rack_rtt_ms,
            0,
            msg="rack_rtt_ms must default to 0.",
        )
        self.assertEqual(
            self._state.rack_xmit_ts,
            0,
            msg="rack_xmit_ts must default to 0.",
        )
        self.assertEqual(
            self._state.rack_end_seq,
            0,
            msg="rack_end_seq must default to 0.",
        )

    def test__rack_tlp_state__acked_seqs_default_empty(self) -> None:
        """
        Ensure 'rack_acked_seqs' defaults to an empty set so
        every newly-acked segment on the first ACK contributes
        to the rack_update scalars.

        Reference: RFC 8985 §6.2 step 1-2 (newly-acknowledged guard).
        """

        self.assertEqual(
            self._state.rack_acked_seqs,
            set(),
            msg="rack_acked_seqs must default to set().",
        )

    def test__rack_tlp_state__reordering_state_default(self) -> None:
        """
        Ensure 'rack_reordering_seen' defaults to False and
        'rack_fack' to 0 so the §6.2 step 4 reo_wnd computation
        starts on the dup-ACK trigger path (reo_wnd=0) and
        switches to the time-based trigger only after the first
        observed reorder.

        Reference: RFC 8985 §6.2 step 3 (reordering detection).
        """

        self.assertFalse(
            self._state.rack_reordering_seen,
            msg="rack_reordering_seen must default to False.",
        )
        self.assertEqual(
            self._state.rack_fack,
            0,
            msg="rack_fack must default to 0.",
        )

    def test__rack_tlp_state__reo_wnd_persist_defaults(self) -> None:
        """
        Ensure the §6.2 step 4 reo_wnd_mult / reo_wnd_persist
        defaults are 1 and 16 respectively — the multiplier
        starts at the canonical neutral value and the persist
        counter at 16 consecutive-recoveries-without-DSACK
        decay window.

        Reference: RFC 8985 §6.2 step 4 (reo_wnd_persist decay).
        """

        self.assertEqual(
            self._state.rack_reo_wnd_mult,
            1,
            msg="rack_reo_wnd_mult must default to 1.",
        )
        self.assertEqual(
            self._state.rack_reo_wnd_persist,
            16,
            msg="rack_reo_wnd_persist must default to 16.",
        )
        self.assertEqual(
            RACK__REO_WND_MULT_INITIAL,
            1,
            msg="RACK__REO_WND_MULT_INITIAL must equal 1.",
        )
        self.assertEqual(
            RACK__REO_WND_PERSIST_DEFAULT,
            16,
            msg="RACK__REO_WND_PERSIST_DEFAULT must equal 16.",
        )

    def test__rack_tlp_state__dsack_round_default_none(self) -> None:
        """
        Ensure 'rack_dsack_round' defaults to None so a
        freshly-constructed session has no in-progress DSACK
        round; the next DSACK observation opens one and the
        next post-marker SND.UNA advance closes it.

        Reference: RFC 8985 §6.2 step 4 (DSACK-round marker).
        """

        self.assertIsNone(
            self._state.rack_dsack_round,
            msg="rack_dsack_round must default to None.",
        )

    def test__rack_tlp_state__tlp_state_default(self) -> None:
        """
        Ensure TLP state defaults to "no probe armed, no probe
        in flight": tlp_armed False, tlp_end_seq None,
        tlp_is_retrans False, tlp_max_ack_delay_ms 25 (Linux's
        canonical receiver-delay upper bound).

        Reference: RFC 8985 §7 (TLP per-connection state).
        """

        self.assertFalse(
            self._state.tlp_armed,
            msg="tlp_armed must default to False.",
        )
        self.assertIsNone(
            self._state.tlp_end_seq,
            msg="tlp_end_seq must default to None.",
        )
        self.assertFalse(
            self._state.tlp_is_retrans,
            msg="tlp_is_retrans must default to False.",
        )
        self.assertEqual(
            self._state.tlp_max_ack_delay_ms,
            25,
            msg="tlp_max_ack_delay_ms must default to 25 (Linux default).",
        )
        self.assertEqual(
            TLP__MAX_ACK_DELAY_MS_DEFAULT,
            25,
            msg="TLP__MAX_ACK_DELAY_MS_DEFAULT must equal 25.",
        )

    def test__rack_tlp_state__instances_own_independent_collections(self) -> None:
        """
        Ensure two distinct 'RackTlpState' instances own
        independent 'rack_segments' dicts and 'rack_acked_seqs'
        sets via 'default_factory'. A test fixture that replaces
        a session's state must not share the scoreboard with
        another session.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        state_a = RackTlpState()
        state_b = RackTlpState()
        self.assertIsNot(
            state_a.rack_segments,
            state_b.rack_segments,
            msg="Distinct RackTlpState instances must own distinct rack_segments.",
        )
        self.assertIsNot(
            state_a.rack_acked_seqs,
            state_b.rack_acked_seqs,
            msg="Distinct RackTlpState instances must own distinct rack_acked_seqs.",
        )


class TestRackTlpState__RecordSegment(TestCase):
    """
    'record_segment' inserts a RackSegment for an outbound
    sequence-consuming segment, tagging retransmits via the
    seq-already-present check.
    """

    def test__rack_tlp_state__record_segment_inserts_fresh(self) -> None:
        """
        Ensure 'record_segment' inserts a RackSegment with
        retransmitted=False when the seq is not already in the
        scoreboard.

        Reference: RFC 8985 §5.2 (per-segment xmit_ts tagging).
        """

        state = RackTlpState()
        state.record_segment(seq=100, end_seq=200, xmit_ts=1000)
        self.assertIn(
            100,
            state.rack_segments,
            msg="record_segment must insert at the seq key.",
        )
        seg = state.rack_segments[100]
        self.assertEqual(seg.end_seq, 200, msg="end_seq must match.")
        self.assertEqual(seg.xmit_ts, 1000, msg="xmit_ts must match.")
        self.assertFalse(
            seg.retransmitted,
            msg="Fresh seq must record retransmitted=False.",
        )
        self.assertFalse(
            seg.lost,
            msg="Fresh seq must record lost=False.",
        )

    def test__rack_tlp_state__record_segment_marks_retransmit(self) -> None:
        """
        Ensure 'record_segment' tags the entry retransmitted=True
        when the seq already exists in the scoreboard (the
        re-entered _transmit_packet path after walkback).

        Reference: RFC 8985 §6.1 (retransmit-tag for sample selection).
        """

        state = RackTlpState()
        state.record_segment(seq=100, end_seq=200, xmit_ts=1000)
        state.record_segment(seq=100, end_seq=200, xmit_ts=2000)
        seg = state.rack_segments[100]
        self.assertEqual(
            seg.xmit_ts,
            2000,
            msg="record_segment must overwrite xmit_ts on retransmit.",
        )
        self.assertTrue(
            seg.retransmitted,
            msg="Re-entered seq must record retransmitted=True.",
        )


class TestRackTlpState__PruneSegments(TestCase):
    """
    'prune_segments' drops scoreboard entries fully covered by
    SND.UNA + the parallel acked_seqs set.
    """

    def test__rack_tlp_state__prune_drops_covered_entries(self) -> None:
        """
        Ensure 'prune_segments' removes entries whose end_seq is
        at or below SND.UNA and discards the matching acked_seqs
        entries. Higher entries stay in the scoreboard.

        Reference: RFC 8985 §5.2 (per-segment dict pruning).
        """

        state = RackTlpState()
        state.rack_segments[100] = RackSegment(end_seq=200, xmit_ts=1, retransmitted=False, lost=False)
        state.rack_segments[200] = RackSegment(end_seq=300, xmit_ts=2, retransmitted=False, lost=False)
        state.rack_segments[300] = RackSegment(end_seq=400, xmit_ts=3, retransmitted=False, lost=False)
        state.rack_acked_seqs.update({100, 200, 300})

        state.prune_segments(snd_una=300)

        self.assertNotIn(
            100,
            state.rack_segments,
            msg="prune_segments must drop entries with end_seq <= snd_una.",
        )
        self.assertNotIn(
            200,
            state.rack_segments,
            msg="prune_segments must drop entries with end_seq <= snd_una.",
        )
        self.assertIn(
            300,
            state.rack_segments,
            msg="prune_segments must keep entries whose end_seq > snd_una.",
        )
        self.assertNotIn(
            100,
            state.rack_acked_seqs,
            msg="prune_segments must discard pruned entries from acked_seqs.",
        )
        self.assertIn(
            300,
            state.rack_acked_seqs,
            msg="prune_segments must keep acked_seqs entries whose seg survived.",
        )


class TestRackTlpState__DecayReoWndPersist(TestCase):
    """
    'decay_reo_wnd_persist' decrements the persist counter and
    resets when it reaches zero.
    """

    def test__rack_tlp_state__decay_decrements_persist(self) -> None:
        """
        Ensure a single 'decay_reo_wnd_persist' call decrements
        the persist counter by 1 without touching the multiplier.

        Reference: RFC 8985 §6.2 step 4 (reo_wnd_persist decay).
        """

        state = RackTlpState()
        state.rack_reo_wnd_persist = 16
        state.rack_reo_wnd_mult = 4
        state.decay_reo_wnd_persist()
        self.assertEqual(
            state.rack_reo_wnd_persist,
            15,
            msg="decay_reo_wnd_persist must decrement the counter.",
        )
        self.assertEqual(
            state.rack_reo_wnd_mult,
            4,
            msg="Decay must not touch the multiplier above zero.",
        )

    def test__rack_tlp_state__decay_resets_at_zero(self) -> None:
        """
        Ensure that when the persist counter reaches zero the
        multiplier resets to 1 and the persist counter refreshes
        to its default. The next decay then operates on the
        canonical baseline.

        Reference: RFC 8985 §6.2 step 4 (reorder-window reset).
        """

        state = RackTlpState()
        state.rack_reo_wnd_persist = 1
        state.rack_reo_wnd_mult = 8
        state.decay_reo_wnd_persist()
        self.assertEqual(
            state.rack_reo_wnd_mult,
            1,
            msg="Reaching zero must reset the multiplier to 1.",
        )
        self.assertEqual(
            state.rack_reo_wnd_persist,
            16,
            msg="Reaching zero must refresh persist to 16.",
        )


class TestRackTlpState__MaybeCloseDsackRound(TestCase):
    """
    'maybe_close_dsack_round' opens / closes the §6.2 step 4
    DSACK round on first observation and snd_una crossing.
    """

    def test__rack_tlp_state__first_dsack_arms_round(self) -> None:
        """
        Ensure the first DSACK observation (rack_dsack_round is
        None) increments the multiplier and arms a new round at
        SND.MAX.

        Reference: RFC 8985 §6.2 step 4 (DSACK-round arming).
        """

        state = RackTlpState()
        state.maybe_close_dsack_round(snd_una=1000, snd_max=2000)
        self.assertEqual(
            state.rack_reo_wnd_mult,
            2,
            msg="First DSACK observation must increment the multiplier.",
        )
        self.assertEqual(
            state.rack_dsack_round,
            2000,
            msg="First DSACK observation must arm the round at SND.MAX.",
        )

    def test__rack_tlp_state__same_round_dsack_burst_collapses(self) -> None:
        """
        Ensure a second DSACK observation while SND.UNA is still
        below the prior round's marker does NOT increment the
        multiplier (collapsed to one increment per round).

        Reference: RFC 8985 §6.2 step 4 (round-collapse semantics).
        """

        state = RackTlpState()
        state.maybe_close_dsack_round(snd_una=1000, snd_max=2000)
        state.maybe_close_dsack_round(snd_una=1500, snd_max=3000)
        self.assertEqual(
            state.rack_reo_wnd_mult,
            2,
            msg="DSACK burst within one round must collapse to one increment.",
        )
        self.assertEqual(
            state.rack_dsack_round,
            2000,
            msg="DSACK burst within one round must keep the prior marker.",
        )

    def test__rack_tlp_state__post_round_dsack_increments(self) -> None:
        """
        Ensure a DSACK observation AFTER SND.UNA has crossed the
        prior round's marker opens a new round (multiplier
        incremented again, marker advanced to current SND.MAX).

        Reference: RFC 8985 §6.2 step 4 (round closure + next round).
        """

        state = RackTlpState()
        state.maybe_close_dsack_round(snd_una=1000, snd_max=2000)
        state.maybe_close_dsack_round(snd_una=2500, snd_max=4000)
        self.assertEqual(
            state.rack_reo_wnd_mult,
            3,
            msg="Post-marker DSACK must increment the multiplier again.",
        )
        self.assertEqual(
            state.rack_dsack_round,
            4000,
            msg="Post-marker DSACK must advance the round marker.",
        )


class TestRackTlpState__CancelTlp(TestCase):
    """
    'cancel_tlp' clears the per-session TLP state on cum-ACK
    drain.
    """

    def test__rack_tlp_state__cancel_clears_state(self) -> None:
        """
        Ensure 'cancel_tlp' clears tlp_end_seq, tlp_is_retrans,
        and tlp_armed without touching tlp_max_ack_delay_ms (the
        receiver-delay tunable persists across probes).

        Reference: RFC 8985 §7.2 (TLP cancellation on cum-ACK drain).
        """

        state = RackTlpState()
        state.tlp_armed = True
        state.tlp_end_seq = 5000
        state.tlp_is_retrans = True
        state.tlp_max_ack_delay_ms = 50

        state.cancel_tlp()

        self.assertFalse(
            state.tlp_armed,
            msg="cancel_tlp must clear tlp_armed.",
        )
        self.assertIsNone(
            state.tlp_end_seq,
            msg="cancel_tlp must clear tlp_end_seq.",
        )
        self.assertFalse(
            state.tlp_is_retrans,
            msg="cancel_tlp must clear tlp_is_retrans.",
        )
        self.assertEqual(
            state.tlp_max_ack_delay_ms,
            50,
            msg="cancel_tlp must NOT touch tlp_max_ack_delay_ms.",
        )
