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
This module contains unit tests for the RFC 8985 RACK per-segment
state primitives in 'pytcp/protocols/tcp/tcp__rack.py'.

The module ships:

    INFINITE_TS                 0xFFFF_FFFF (RFC 8985 §5.2 marker)
    RackSegment                 frozen dataclass with end_seq,
                                xmit_ts, retransmitted, lost

See 'docs/rfc/tcp/rfc8985__rack_tlp/adherence.md' for the per-
clause spec audit.

The dataclass mirrors the RFC 8985 §5.2 'Segment' tuple. The
'INFINITE_TS' constant marks segments that are not currently in
flight (lost or pruned); RACK_sent_after lexicographic compare in
later phases skips segments whose xmit_ts equals INFINITE_TS.

Reference RFCs:
    RFC 8985 §5.2  Per-Segment Variables

pytcp/tests/unit/protocols/tcp/test__tcp__rack.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__rack import (
    INFINITE_TS,
    RackSegment,
    rack_compute_reo_wnd,
    rack_detect_loss,
    rack_sent_after,
    rack_update,
    tlp_calc_pto,
    tlp_process_ack,
)


class TestRackConstants(TestCase):
    """
    Spot-checks on the module-level constants.
    """

    def test__rack__infinite_ts_is_uint32_max(self) -> None:
        """
        Ensure 'INFINITE_TS' equals 0xFFFF_FFFF so a lost or
        pruned segment's 'xmit_ts' field signals "not currently
        in flight" via the maximum 32-bit unsigned value.

        Reference: RFC 8985 §5.2 (invalid timestamp marker).
        """

        self.assertEqual(
            INFINITE_TS,
            0xFFFF_FFFF,
            msg=(
                "RFC 8985 §5.2 mandates an invalid-timestamp "
                "marker for segments that are not currently in "
                "flight; the canonical value is 0xFFFF_FFFF."
            ),
        )


class TestRackSegmentConstruction(TestCase):
    """
    Construction-time invariants of the 'RackSegment' frozen
    dataclass.
    """

    def test__rack__segment__construction_with_all_fields(self) -> None:
        """
        Ensure 'RackSegment' constructs with the four canonical
        fields (end_seq, xmit_ts, retransmitted, lost) and
        exposes them via attribute access.

        Reference: RFC 8985 §5.2 (Segment tuple fields).
        """

        seg = RackSegment(
            end_seq=0x0000_2000,
            xmit_ts=12345,
            retransmitted=False,
            lost=False,
        )

        self.assertEqual(
            seg.end_seq,
            0x0000_2000,
            msg="'end_seq' field must round-trip through construction.",
        )
        self.assertEqual(
            seg.xmit_ts,
            12345,
            msg="'xmit_ts' field must round-trip through construction.",
        )
        self.assertFalse(
            seg.retransmitted,
            msg="'retransmitted' field must round-trip through construction.",
        )
        self.assertFalse(
            seg.lost,
            msg="'lost' field must round-trip through construction.",
        )

    def test__rack__segment__retransmitted_and_lost_flags(self) -> None:
        """
        Ensure 'RackSegment' accepts True for 'retransmitted'
        and 'lost' so later RACK phases can mark a segment as
        retransmitted (Phase 2 Karn-style guard) or lost
        (Phase 3 time-based loss detection).

        Reference: RFC 8985 §5.2 (Segment.retransmitted, Segment.lost).
        """

        seg = RackSegment(
            end_seq=0,
            xmit_ts=0,
            retransmitted=True,
            lost=True,
        )

        self.assertTrue(
            seg.retransmitted,
            msg="'retransmitted=True' must round-trip.",
        )
        self.assertTrue(
            seg.lost,
            msg="'lost=True' must round-trip.",
        )

    def test__rack__segment__is_frozen(self) -> None:
        """
        Ensure 'RackSegment' is frozen so the per-segment state
        is immutable - mutations require constructing a fresh
        instance and replacing the dict entry. Mirrors the
        'RtoState' / 'SackBlock' immutability convention.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        seg = RackSegment(end_seq=0, xmit_ts=0, retransmitted=False, lost=False)

        with self.assertRaises(
            AttributeError,
            msg="RackSegment must be frozen; attribute writes must raise.",
        ):
            seg.lost = True  # type: ignore[misc]

    def test__rack__segment__equality_by_value(self) -> None:
        """
        Ensure two 'RackSegment' instances with identical field
        values compare equal so dict-like comparisons in tests
        work without identity-coupling.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = RackSegment(end_seq=100, xmit_ts=200, retransmitted=False, lost=False)
        b = RackSegment(end_seq=100, xmit_ts=200, retransmitted=False, lost=False)
        c = RackSegment(end_seq=100, xmit_ts=201, retransmitted=False, lost=False)

        self.assertEqual(
            a,
            b,
            msg="Two RackSegment instances with identical fields must compare equal.",
        )
        self.assertNotEqual(
            a,
            c,
            msg="RackSegment instances differing in 'xmit_ts' must compare unequal.",
        )

    def test__rack__segment__xmit_ts_can_be_infinite_ts(self) -> None:
        """
        Ensure 'RackSegment' accepts 'xmit_ts == INFINITE_TS'
        so a lost-marked segment's xmit_ts can be set to the
        invalid-timestamp marker.

        Reference: RFC 8985 §5.2 (xmit_ts = INFINITE_TS for lost segments).
        """

        seg = RackSegment(
            end_seq=0,
            xmit_ts=INFINITE_TS,
            retransmitted=False,
            lost=True,
        )

        self.assertEqual(
            seg.xmit_ts,
            INFINITE_TS,
            msg="A lost segment's xmit_ts must be settable to INFINITE_TS.",
        )


class TestRackSentAfter(TestCase):
    """
    The 'rack_sent_after' lexicographic comparison tests
    (RFC 8985 §6.2 step 2).
    """

    def test__rack__sent_after__later_xmit_ts_wins(self) -> None:
        """
        Ensure a later 'xmit_ts' makes one segment count as
        'sent after' another, regardless of seq.

        Reference: RFC 8985 §6.2 (RACK_sent_after by xmit_ts).
        """

        self.assertTrue(
            rack_sent_after(t1_xmit_ts=200, t1_end_seq=0, t2_xmit_ts=100, t2_end_seq=999),
            msg=("Later xmit_ts must win regardless of seq."),
        )

    def test__rack__sent_after__earlier_xmit_ts_loses(self) -> None:
        """
        Ensure an earlier 'xmit_ts' is NOT 'sent after' a
        later one.

        Reference: RFC 8985 §6.2 (RACK_sent_after by xmit_ts).
        """

        self.assertFalse(
            rack_sent_after(t1_xmit_ts=100, t1_end_seq=999, t2_xmit_ts=200, t2_end_seq=0),
            msg="Earlier xmit_ts must lose to a later one.",
        )

    def test__rack__sent_after__tie_broken_by_end_seq(self) -> None:
        """
        Ensure a tie on 'xmit_ts' breaks by modular comparison
        on 'end_seq': segment with higher end_seq is 'sent
        after'.

        Reference: RFC 8985 §6.2 (RACK_sent_after end_seq tiebreaker).
        """

        self.assertTrue(
            rack_sent_after(t1_xmit_ts=100, t1_end_seq=2000, t2_xmit_ts=100, t2_end_seq=1000),
            msg="On xmit_ts tie, higher end_seq must win.",
        )

    def test__rack__sent_after__identical_returns_false(self) -> None:
        """
        Ensure two identical (xmit_ts, end_seq) pairs are
        NOT 'sent after' each other (strict-greater semantics).

        Reference: RFC 8985 §6.2 (RACK_sent_after strict order).
        """

        self.assertFalse(
            rack_sent_after(t1_xmit_ts=100, t1_end_seq=1000, t2_xmit_ts=100, t2_end_seq=1000),
            msg="Identical pair must not be 'sent after' itself.",
        )


class TestRackUpdate(TestCase):
    """
    The 'rack_update' RFC 8985 §6.2 step 1-2 update tests.
    """

    def test__rack__update__empty_segments_returns_priors(self) -> None:
        """
        Ensure an empty 'newly_acked_segments' list leaves all
        scalars unchanged.

        Reference: RFC 8985 §6.2 (no update without newly-acked).
        """

        result = rack_update(
            newly_acked_segments=[],
            now_ms=12345,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=100,
            prior_rack_rtt_ms=120,
            prior_rack_xmit_ts=10000,
            prior_rack_end_seq=5000,
        )

        self.assertEqual(
            result,
            (100, 120, 10000, 5000),
            msg="Empty newly_acked must yield the prior scalars unchanged.",
        )

    def test__rack__update__single_fresh_sample_seeds_min_rtt(self) -> None:
        """
        Ensure a single non-retransmitted sample seeds
        'min_rtt' even when the prior min_rtt is the
        uninitialized sentinel (0).

        Reference: RFC 8985 §B.1 (min_RTT update).
        """

        seg = RackSegment(end_seq=1000, xmit_ts=200, retransmitted=False, lost=False)
        min_rtt_ms, rack_rtt_ms, rack_xmit_ts, rack_end_seq = rack_update(
            newly_acked_segments=[seg],
            now_ms=400,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=0,
            prior_rack_rtt_ms=0,
            prior_rack_xmit_ts=0,
            prior_rack_end_seq=0,
        )

        self.assertEqual(min_rtt_ms, 200, msg="First sample must seed min_rtt.")
        self.assertEqual(rack_rtt_ms, 200, msg="RACK.rtt must equal the sample RTT.")
        self.assertEqual(rack_xmit_ts, 200, msg="RACK.xmit_ts must advance.")
        self.assertEqual(rack_end_seq, 1000, msg="RACK.end_seq must advance.")

    def test__rack__update__retransmitted_with_stale_tsecr_skipped(self) -> None:
        """
        Ensure a retransmitted segment whose TSecr predates
        the segment's xmit_ts is skipped (step 2 condition 1
        of the Karn-style guard) and does not perturb the
        scalars.

        Reference: RFC 8985 §6.2 (Karn-style spurious-retransmit guard via TSecr).
        """

        seg = RackSegment(end_seq=1000, xmit_ts=200, retransmitted=True, lost=False)
        result = rack_update(
            newly_acked_segments=[seg],
            now_ms=400,
            ts_recent_echo_ms=100,  # < seg.xmit_ts -> skip
            prior_min_rtt_ms=50,
            prior_rack_rtt_ms=60,
            prior_rack_xmit_ts=10,
            prior_rack_end_seq=20,
        )

        self.assertEqual(
            result,
            (50, 60, 10, 20),
            msg="Stale-TSecr retransmit must leave scalars unchanged.",
        )

    def test__rack__update__retransmitted_with_small_rtt_skipped(self) -> None:
        """
        Ensure a retransmitted segment with rtt < min_rtt is
        skipped (step 2 condition 2 of the Karn-style guard
        heuristic).

        Reference: RFC 8985 §6.2 (Karn-style guard via rtt < min_rtt).
        """

        # rtt = 400 - 350 = 50; min_rtt = 100; 50 < 100 -> skip.
        seg = RackSegment(end_seq=1000, xmit_ts=350, retransmitted=True, lost=False)
        result = rack_update(
            newly_acked_segments=[seg],
            now_ms=400,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=100,
            prior_rack_rtt_ms=110,
            prior_rack_xmit_ts=10,
            prior_rack_end_seq=20,
        )

        self.assertEqual(
            result,
            (100, 110, 10, 20),
            msg="Retransmit with rtt < min_rtt must be skipped.",
        )

    def test__rack__update__min_rtt_tracks_smallest(self) -> None:
        """
        Ensure 'min_rtt' tracks the smallest rtt across a
        burst of acked segments.

        Reference: RFC 8985 §B.1 (min_RTT minimum tracking).
        """

        segs = [
            RackSegment(end_seq=1000, xmit_ts=100, retransmitted=False, lost=False),
            RackSegment(end_seq=2000, xmit_ts=300, retransmitted=False, lost=False),
            RackSegment(end_seq=3000, xmit_ts=200, retransmitted=False, lost=False),
        ]
        min_rtt_ms, _, _, _ = rack_update(
            newly_acked_segments=segs,
            now_ms=400,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=0,
            prior_rack_rtt_ms=0,
            prior_rack_xmit_ts=0,
            prior_rack_end_seq=0,
        )

        # rtts: 300, 100, 200 -> min = 100.
        self.assertEqual(
            min_rtt_ms,
            100,
            msg="min_rtt must track the smallest rtt across a burst.",
        )

    def test__rack__update__rack_xmit_ts_tracks_latest_sent(self) -> None:
        """
        Ensure 'RACK.xmit_ts' / 'RACK.end_seq' track the
        segment with the latest 'sent_after' lexicographic
        order across a burst (not necessarily the highest
        seq, since RACK uses xmit_ts as the primary key).

        Reference: RFC 8985 §6.2 (RACK_sent_after primary).
        """

        # Three segments transmitted at 100, 300, 200 ms with
        # increasing seq. The lexicographically-latest is the
        # one at xmit_ts=300 with end_seq=2000.
        segs = [
            RackSegment(end_seq=1000, xmit_ts=100, retransmitted=False, lost=False),
            RackSegment(end_seq=2000, xmit_ts=300, retransmitted=False, lost=False),
            RackSegment(end_seq=3000, xmit_ts=200, retransmitted=False, lost=False),
        ]
        _, _, rack_xmit_ts, rack_end_seq = rack_update(
            newly_acked_segments=segs,
            now_ms=400,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=0,
            prior_rack_rtt_ms=0,
            prior_rack_xmit_ts=0,
            prior_rack_end_seq=0,
        )

        self.assertEqual(rack_xmit_ts, 300, msg="RACK.xmit_ts must equal max xmit_ts.")
        self.assertEqual(rack_end_seq, 2000, msg="RACK.end_seq must pair with RACK.xmit_ts.")


class TestRackDetectLoss(TestCase):
    """
    The 'rack_detect_loss' RFC 8985 §6.2 step 5 tests.
    """

    def test__rack__detect_loss__sent_before_segment_marked_lost_with_zero_reo_wnd(self) -> None:
        """
        Ensure a segment that RACK was 'sent after' AND whose
        reordering window has elapsed (zero in this case) is
        marked lost, with xmit_ts overwritten to INFINITE_TS.

        Reference: RFC 8985 §6.2 step 5 (mark segment lost).
        """

        # seg1 sent at t=100; seg2 sent at t=200 and delivered.
        # RACK.xmit_ts = 200, RACK.end_seq = 2000.
        segments = {
            1000: RackSegment(end_seq=2000, xmit_ts=100, retransmitted=False, lost=False),
        }
        new_segments, timeout = rack_detect_loss(
            segments=segments,
            rack_xmit_ts=200,
            rack_end_seq=3000,
            reo_wnd_ms=0,
            now_ms=300,
        )

        self.assertTrue(
            new_segments[1000].lost,
            msg="A 'sent before' segment past reo_wnd MUST be marked lost.",
        )
        self.assertEqual(
            new_segments[1000].xmit_ts,
            INFINITE_TS,
            msg="A lost segment's xmit_ts MUST be set to INFINITE_TS.",
        )
        self.assertEqual(timeout, 0, msg="No timer needed when all candidates marked lost.")

    def test__rack__detect_loss__within_reo_wnd_arms_timer(self) -> None:
        """
        Ensure that a 'sent before' segment whose reo_wnd has
        not yet elapsed is NOT marked lost; the helper instead
        returns the timeout to arm a reordering timer.

        Reference: RFC 8985 §6.2 step 5 (timer arming on pending candidate).
        """

        # seg1 sent at t=200; reo_wnd=100; now=250.
        # 250 - 200 = 50 < 100 -> within reo_wnd.
        # Timeout = 200 + 100 - 250 = 50.
        segments = {
            1000: RackSegment(end_seq=2000, xmit_ts=200, retransmitted=False, lost=False),
        }
        new_segments, timeout = rack_detect_loss(
            segments=segments,
            rack_xmit_ts=240,
            rack_end_seq=3000,
            reo_wnd_ms=100,
            now_ms=250,
        )

        self.assertFalse(
            new_segments[1000].lost,
            msg="A 'sent before' segment within reo_wnd MUST NOT be marked lost.",
        )
        self.assertEqual(
            timeout,
            50,
            msg="The returned timer MUST equal the earliest pending xmit_ts + reo_wnd - now.",
        )

    def test__rack__detect_loss__sent_after_segment_unaffected(self) -> None:
        """
        Ensure a segment that was sent AFTER RACK is not a
        loss candidate and remains unchanged.

        Reference: RFC 8985 §6.2 step 5 (rack_sent_after gate).
        """

        # seg sent at t=300 > RACK.xmit_ts=200; RACK was sent
        # before this segment, so it's not a candidate.
        segments = {
            1000: RackSegment(end_seq=2000, xmit_ts=300, retransmitted=False, lost=False),
        }
        new_segments, timeout = rack_detect_loss(
            segments=segments,
            rack_xmit_ts=200,
            rack_end_seq=1500,
            reo_wnd_ms=0,
            now_ms=400,
        )

        self.assertFalse(
            new_segments[1000].lost,
            msg="A 'sent after' segment MUST NOT be marked lost.",
        )
        self.assertEqual(timeout, 0, msg="No timer needed when no candidates exist.")

    def test__rack__detect_loss__already_lost_segment_unchanged(self) -> None:
        """
        Ensure an already-lost segment ('seg.lost is True') is
        skipped: the algorithm only acts on first-time loss
        detection.

        Reference: RFC 8985 §6.2 step 5 (already-lost skip).
        """

        segments = {
            1000: RackSegment(end_seq=2000, xmit_ts=INFINITE_TS, retransmitted=True, lost=True),
        }
        new_segments, timeout = rack_detect_loss(
            segments=segments,
            rack_xmit_ts=300,
            rack_end_seq=4000,
            reo_wnd_ms=0,
            now_ms=400,
        )

        self.assertEqual(
            new_segments,
            segments,
            msg="An already-lost segment MUST be returned unchanged.",
        )
        self.assertEqual(timeout, 0, msg="Already-lost segments do not contribute to the timer.")


class TestRackComputeReoWnd(TestCase):
    """
    The 'rack_compute_reo_wnd' RFC 8985 §6.2 step 4 tests.
    """

    def test__rack__compute_reo_wnd__no_reordering_returns_zero(self) -> None:
        """
        Ensure that when no reordering has been observed, the
        helper returns 0 so the caller falls back to the
        dup-ACK trigger.

        Reference: RFC 8985 §6.2 step 4 (reo_wnd = 0 when no reordering).
        """

        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=False, reo_wnd_mult=1, min_rtt_ms=100),
            0,
            msg="No-reordering case MUST return 0.",
        )

    def test__rack__compute_reo_wnd__base_quarter_min_rtt(self) -> None:
        """
        Ensure that with 'reordering_seen=True' and
        'reo_wnd_mult=1', the helper returns 'min_RTT / 4'.

        Reference: RFC 8985 §6.2 step 4 (min_RTT / 4 base).
        """

        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=True, reo_wnd_mult=1, min_rtt_ms=100),
            25,
            msg="Base reo_wnd MUST equal min_RTT / 4.",
        )

    def test__rack__compute_reo_wnd__multiplier_scales_linearly(self) -> None:
        """
        Ensure that 'reo_wnd_mult' scales the base reo_wnd
        linearly (DSACK-driven adaptation).

        Reference: RFC 8985 §6.2 step 4 (reo_wnd_mult scaling).
        """

        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=True, reo_wnd_mult=2, min_rtt_ms=100),
            50,
            msg="reo_wnd_mult=2 MUST double the reo_wnd.",
        )
        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=True, reo_wnd_mult=4, min_rtt_ms=100),
            100,
            msg="reo_wnd_mult=4 MUST quadruple the reo_wnd.",
        )

    def test__rack__compute_reo_wnd__zero_min_rtt_returns_zero(self) -> None:
        """
        Ensure that an uninitialized min_RTT (=0) yields 0
        regardless of 'reordering_seen' so the algorithm does
        not rely on a stale RTT.

        Reference: RFC 8985 §6.2 step 4 (gate on min_RTT availability).
        """

        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=True, reo_wnd_mult=4, min_rtt_ms=0),
            0,
            msg="Uninitialized min_RTT MUST yield reo_wnd=0.",
        )


class TestTlpCalcPto(TestCase):
    """
    The 'tlp_calc_pto' RFC 8985 §7.2 tests.
    """

    def test__tlp__pto__no_srtt_uses_1000_ms(self) -> None:
        """
        Ensure that without an SRTT sample, the PTO falls
        back to the 1000 ms initial RTO.

        Reference: RFC 8985 §7.2 (PTO fallback when SRTT unavailable).
        """

        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=None,
                flight_size=1460,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=None,
                now_ms=0,
            ),
            1000,
            msg="No-SRTT case MUST return the 1000 ms fallback.",
        )

    def test__tlp__pto__multi_segment_flight_uses_2_srtt(self) -> None:
        """
        Ensure that with FlightSize > 1 segment, the PTO is
        2 * SRTT (no max_ack_delay inflation).

        Reference: RFC 8985 §7.2 (PTO = 2 * SRTT base).
        """

        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=2 * 1460,  # 2 segments
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=None,
                now_ms=0,
            ),
            200,
            msg="Multi-segment FlightSize PTO MUST be 2 * SRTT.",
        )

    def test__tlp__pto__single_segment_flight_adds_max_ack_delay(self) -> None:
        """
        Ensure that with FlightSize == 1 segment, the PTO
        absorbs the max_ack_delay so the receiver's delayed-
        ACK timer does not preempt the probe.

        Reference: RFC 8985 §7.2 (PTO += max_ack_delay).
        """

        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=1460,  # 1 segment
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=None,
                now_ms=0,
            ),
            225,
            msg="Single-segment FlightSize PTO MUST be 2 * SRTT + max_ack_delay.",
        )

    def test__tlp__pto__capped_by_rto_remaining(self) -> None:
        """
        Ensure that the PTO is clamped strictly below 'RTO -
        now' so TLP always fires at least one ms before the
        RTO timer when both would otherwise expire on the
        same tick.

        Reference: RFC 8985 §7.2 (do-not-outlast-RTO clamp).
        """

        # PTO = 200, RTO remaining = 50 -> clamp to 49.
        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=2 * 1460,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=50,
                now_ms=0,
            ),
            49,
            msg="PTO MUST clamp strictly below RTO remaining when smaller.",
        )


class TestTlpProcessAck(TestCase):
    """
    The 'tlp_process_ack' RFC 8985 §7.4 tests.
    """

    def test__tlp__process_ack__no_probe_outstanding_returns_none(self) -> None:
        """
        Ensure that when no probe is outstanding (tlp_end_seq
        is None), the helper returns (None, False) without
        triggering CC response.

        Reference: RFC 8985 §7.4 (no outcome to determine).
        """

        result = tlp_process_ack(
            tlp_end_seq=None,
            tlp_is_retrans=False,
            ack_seq=1000,
            has_dsack_for_probe=False,
            has_sack_blocks=False,
        )
        self.assertEqual(result, (None, False), msg="No probe -> no state change.")

    def test__tlp__process_ack__new_data_probe_delivered_clears_state(self) -> None:
        """
        Ensure that when the probe sent new data and an ACK
        covers it (ack >= tlp_end_seq), state is cleared
        with no CC response (no tail loss occurred).

        Reference: RFC 8985 §7.4 (new-data probe delivered).
        """

        new_tlp_end, cc = tlp_process_ack(
            tlp_end_seq=1000,
            tlp_is_retrans=False,
            ack_seq=1000,
            has_dsack_for_probe=False,
            has_sack_blocks=False,
        )
        self.assertIsNone(new_tlp_end, msg="State MUST clear on new-data probe delivery.")
        self.assertFalse(cc, msg="No CC response on new-data probe.")

    def test__tlp__process_ack__dsack_match_clears_no_cc(self) -> None:
        """
        Ensure that a DSACK matching the probe clears state
        without invoking CC response (Case 1: spurious
        retransmit; the original was already received).

        Reference: RFC 8985 §7.4 (Case 1: DSACK match).
        """

        new_tlp_end, cc = tlp_process_ack(
            tlp_end_seq=1000,
            tlp_is_retrans=True,
            ack_seq=900,
            has_dsack_for_probe=True,
            has_sack_blocks=False,
        )
        self.assertIsNone(new_tlp_end, msg="State MUST clear on DSACK match.")
        self.assertFalse(cc, msg="DSACK match MUST NOT invoke CC.")

    def test__tlp__process_ack__case_3_single_loss_repair_invokes_cc(self) -> None:
        """
        Ensure that an ACK advancing strictly past the probe's
        end_seq invokes the CC response (Case 3: single tail
        loss repaired by the probe).

        Reference: RFC 8985 §7.4 (Case 3: probe repaired single loss).
        """

        new_tlp_end, cc = tlp_process_ack(
            tlp_end_seq=1000,
            tlp_is_retrans=True,
            ack_seq=1100,
            has_dsack_for_probe=False,
            has_sack_blocks=False,
        )
        self.assertIsNone(new_tlp_end, msg="State MUST clear after probe-repair.")
        self.assertTrue(cc, msg="Probe-repair MUST invoke CC response (cwnd halving).")

    def test__tlp__process_ack__case_2_bare_dup_ack_clears_no_cc(self) -> None:
        """
        Ensure that a bare duplicate ACK at probe's end_seq
        with no SACK blocks clears state without CC (Case 2:
        the probe's retransmit was useless, the original was
        already received).

        Reference: RFC 8985 §7.4 (Case 2: bare dup-ACK).
        """

        new_tlp_end, cc = tlp_process_ack(
            tlp_end_seq=1000,
            tlp_is_retrans=True,
            ack_seq=1000,
            has_dsack_for_probe=False,
            has_sack_blocks=False,
        )
        self.assertIsNone(new_tlp_end, msg="Bare dup-ACK MUST clear state.")
        self.assertFalse(cc, msg="Bare dup-ACK MUST NOT invoke CC.")

    def test__tlp__process_ack__indeterminate_preserves_state(self) -> None:
        """
        Ensure that an inbound ACK whose state does not match
        any of the four canonical cases preserves
        'tlp_end_seq' so subsequent ACKs can clarify.

        Reference: RFC 8985 §7.4 (indeterminate -> preserve).
        """

        # ACK below probe's end_seq, retransmit probe, no DSACK,
        # SACK blocks present -> doesn't match any case.
        new_tlp_end, cc = tlp_process_ack(
            tlp_end_seq=1000,
            tlp_is_retrans=True,
            ack_seq=900,
            has_dsack_for_probe=False,
            has_sack_blocks=True,
        )
        self.assertEqual(new_tlp_end, 1000, msg="Indeterminate ACK MUST preserve state.")
        self.assertFalse(cc, msg="Indeterminate ACK MUST NOT invoke CC.")


class TestRackMutationGoldens(TestCase):
    """
    Exact-value, branch-boundary, and argument-guard goldens closing
    the remaining killable RACK / TLP mutation survivors across the
    five helpers.
    """

    def test__rack__sent_after_strict_ordering(self) -> None:
        """
        Ensure RACK_sent_after compares (xmit_ts, end_seq)
        lexicographically with a strict '>' on the timestamp and the
        modular '>' on end_seq for ties.

        Reference: RFC 8985 §6.2 step 2 (RACK_sent_after).
        """

        self.assertTrue(
            rack_sent_after(200, 5, 100, 5),
            msg="later xmit_ts must be 'sent after'.",
        )
        self.assertFalse(
            rack_sent_after(100, 5, 200, 5),
            msg="earlier xmit_ts must NOT be 'sent after' (kills '>'→'!=').",
        )
        self.assertTrue(
            rack_sent_after(100, 10, 100, 5),
            msg="equal xmit_ts must break the tie on end_seq (kills '!='→'==').",
        )
        self.assertFalse(
            rack_sent_after(100, 5, 100, 10),
            msg="equal xmit_ts, lower end_seq must NOT be 'sent after'.",
        )

    def test__rack__update_normal_sample(self) -> None:
        """
        Ensure a single non-retransmitted acked segment seeds min_RTT
        and RACK.rtt with rtt = now - xmit_ts and advances RACK.xmit_ts
        / end_seq.

        Reference: RFC 8985 §6.2 step 2 (RACK update).
        """

        self.assertEqual(
            rack_update(
                newly_acked_segments=[RackSegment(100, 500, False, False)],
                now_ms=1000,
                ts_recent_echo_ms=None,
                prior_min_rtt_ms=0,
                prior_rack_rtt_ms=0,
                prior_rack_xmit_ts=0,
                prior_rack_end_seq=0,
            ),
            (500, 500, 500, 100),
            msg="normal sample must yield (min_rtt, rack_rtt, xmit_ts, end_seq) = (500,500,500,100).",
        )

    def test__rack__update_skips_infinite_ts_segment(self) -> None:
        """
        Ensure a lost segment (xmit_ts == INFINITE_TS) is skipped
        entirely, leaving the prior RACK scalars unchanged.

        Reference: RFC 8985 §5.2 (lost segments carry INFINITE_TS).
        """

        self.assertEqual(
            rack_update(
                newly_acked_segments=[RackSegment(100, INFINITE_TS, False, False)],
                now_ms=1000,
                ts_recent_echo_ms=None,
                prior_min_rtt_ms=7,
                prior_rack_rtt_ms=8,
                prior_rack_xmit_ts=9,
                prior_rack_end_seq=10,
            ),
            (7, 8, 9, 10),
            msg="INFINITE_TS segment must be skipped, leaving priors unchanged.",
        )

    def test__rack__update_retransmit_skip_conditions(self) -> None:
        """
        Ensure a retransmitted segment is skipped when the peer's
        TSecr predates its xmit_ts, and when its rtt is below the
        established min_RTT.

        Reference: RFC 8985 §6.2 step 2 (retransmit skip conditions).
        """

        self.assertEqual(
            rack_update(
                newly_acked_segments=[RackSegment(100, 500, True, False)],
                now_ms=1000,
                ts_recent_echo_ms=400,
                prior_min_rtt_ms=0,
                prior_rack_rtt_ms=0,
                prior_rack_xmit_ts=0,
                prior_rack_end_seq=0,
            ),
            (0, 0, 0, 0),
            msg="retransmit with TSecr < xmit_ts must be skipped.",
        )
        self.assertEqual(
            rack_update(
                newly_acked_segments=[RackSegment(100, 900, True, False)],
                now_ms=1000,
                ts_recent_echo_ms=None,
                prior_min_rtt_ms=600,
                prior_rack_rtt_ms=600,
                prior_rack_xmit_ts=50,
                prior_rack_end_seq=20,
            ),
            (600, 600, 50, 20),
            msg="retransmit with rtt < min_RTT must be skipped.",
        )

    def test__rack__detect_loss_marks_lost_past_reo_window(self) -> None:
        """
        Ensure a segment RACK was sent after is marked lost (xmit_ts
        replaced with INFINITE_TS) once now - xmit_ts exceeds the
        reordering window.

        Reference: RFC 8985 §6.2 step 5 (time-based loss detection).
        """

        new_segs, timeout = rack_detect_loss(
            segments={10: RackSegment(100, 500, False, False)},
            rack_xmit_ts=700,
            rack_end_seq=300,
            reo_wnd_ms=100,
            now_ms=700,
        )
        self.assertTrue(new_segs[10].lost, msg="segment past reo-window must be lost.")
        self.assertEqual(
            new_segs[10].xmit_ts,
            INFINITE_TS,
            msg="lost segment must carry INFINITE_TS.",
        )
        self.assertEqual(timeout, 0, msg="no pending candidate → no reorder timer.")

    def test__rack__detect_loss_pending_at_reo_boundary(self) -> None:
        """
        Ensure a segment exactly at the reordering-window boundary
        (now - xmit_ts == reo_wnd) is NOT marked lost (strict '>'),
        so a '>'→'>=' edit is caught.

        Reference: RFC 8985 §6.2 step 5 (strict reordering tolerance).
        """

        new_segs, _ = rack_detect_loss(
            segments={10: RackSegment(100, 500, False, False)},
            rack_xmit_ts=700,
            rack_end_seq=300,
            reo_wnd_ms=100,
            now_ms=600,
        )
        self.assertFalse(
            new_segs[10].lost,
            msg="segment exactly at the reo-window boundary must NOT be lost.",
        )

    def test__rack__detect_loss_earliest_pending_timer(self) -> None:
        """
        Ensure the returned reorder timer is the minimum
        'xmit_ts + reo_wnd - now' across all pending candidates.

        Reference: RFC 8985 §6.2 step 5 (earliest reorder timer).
        """

        _, timeout = rack_detect_loss(
            segments={
                10: RackSegment(100, 520, False, False),
                20: RackSegment(200, 550, False, False),
            },
            rack_xmit_ts=700,
            rack_end_seq=300,
            reo_wnd_ms=100,
            now_ms=600,
        )
        self.assertEqual(
            timeout,
            20,
            msg="reorder timer must be the minimum pending timeout (20), not 50.",
        )

    def test__rack__detect_loss_not_sent_after_preserved(self) -> None:
        """
        Ensure a segment RACK was NOT sent after is preserved
        unchanged (not a loss candidate).

        Reference: RFC 8985 §6.2 step 5 (only sent-after segments are candidates).
        """

        new_segs, timeout = rack_detect_loss(
            segments={10: RackSegment(100, 500, False, False)},
            rack_xmit_ts=400,
            rack_end_seq=50,
            reo_wnd_ms=100,
            now_ms=700,
        )
        self.assertFalse(new_segs[10].lost, msg="non-sent-after segment must be preserved.")
        self.assertEqual(timeout, 0, msg="non-candidate must not arm a timer.")

    def test__rack__compute_reo_wnd_exact_values(self) -> None:
        """
        Ensure the reordering window is min_RTT * mult // 4 when
        reordering has been seen, 0 when it has not, and 0 when
        min_RTT is uninitialized; the floor division is integer (odd
        min_RTT does not yield a float).

        Reference: RFC 8985 §6.2 step 4 (reordering window).
        """

        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=True, reo_wnd_mult=2, min_rtt_ms=100),
            50,
            msg="reo_wnd = 100 * 2 // 4 = 50.",
        )
        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=False, reo_wnd_mult=2, min_rtt_ms=100),
            0,
            msg="no reordering seen must yield 0.",
        )
        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=True, reo_wnd_mult=2, min_rtt_ms=0),
            0,
            msg="uninitialized min_RTT must yield 0.",
        )
        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=True, reo_wnd_mult=1, min_rtt_ms=101),
            25,
            msg="odd min_RTT 101 must floor to 25 (kills '//'→'/').",
        )

    def test__rack__compute_reo_wnd_guards(self) -> None:
        """
        Ensure rack_compute_reo_wnd accepts its argument boundaries
        (mult=1, min_rtt=0) and rejects below them.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            rack_compute_reo_wnd(reordering_seen=False, reo_wnd_mult=1, min_rtt_ms=0),
            0,
            msg="boundary mult=1, min_rtt=0 must be accepted.",
        )
        with self.assertRaises(AssertionError):
            rack_compute_reo_wnd(reordering_seen=True, reo_wnd_mult=0, min_rtt_ms=100)
        with self.assertRaises(AssertionError):
            rack_compute_reo_wnd(reordering_seen=True, reo_wnd_mult=1, min_rtt_ms=-1)

    def test__tlp__calc_pto_exact_values(self) -> None:
        """
        Ensure the TLP PTO is 2*SRTT, inflated by max_ack_delay only
        when FlightSize is a single segment, falls back to 1000 ms
        without an SRTT sample, and is capped to strictly below the
        RTO remaining.

        Reference: RFC 8985 §7.2 (TLP PTO computation).
        """

        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=2920,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=None,
                now_ms=0,
            ),
            200,
            msg="multi-segment flight: PTO = 2*SRTT = 200.",
        )
        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=1460,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=None,
                now_ms=0,
            ),
            225,
            msg="single-segment flight: PTO = 2*SRTT + max_ack_delay = 225.",
        )
        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=None,
                flight_size=2920,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=None,
                now_ms=0,
            ),
            1000,
            msg="no SRTT sample: PTO = 1000 ms.",
        )
        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=2920,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=150,
                now_ms=0,
            ),
            149,
            msg="PTO must be capped to RTO_remaining - 1 = 149.",
        )
        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=2920,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=200,
                now_ms=0,
            ),
            199,
            msg="PTO == RTO_remaining must be pulled back to 199 (strict '>=').",
        )

    def test__tlp__calc_pto_guards(self) -> None:
        """
        Ensure tlp_calc_pto accepts its argument boundaries
        (flight_size=0, smss=1, max_ack_delay=0) and rejects below
        them.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tlp_calc_pto(
            srtt_ms=100,
            flight_size=0,
            smss=1,
            max_ack_delay_ms=0,
            rto_expiration_ms=None,
            now_ms=0,
        )
        with self.assertRaises(AssertionError):
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=-1,
                smss=1,
                max_ack_delay_ms=0,
                rto_expiration_ms=None,
                now_ms=0,
            )
        with self.assertRaises(AssertionError):
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=0,
                smss=0,
                max_ack_delay_ms=0,
                rto_expiration_ms=None,
                now_ms=0,
            )
        with self.assertRaises(AssertionError):
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=0,
                smss=1,
                max_ack_delay_ms=-1,
                rto_expiration_ms=None,
                now_ms=0,
            )

    def test__tlp__process_ack_case2_requires_no_sack(self) -> None:
        """
        Ensure the Case-2 bare-dup-ACK clear requires both ack ==
        tlp_end_seq AND no SACK blocks: with SACK blocks present the
        outcome is indeterminate and the probe state is preserved.

        Reference: RFC 8985 §7.4 (Case 2: bare dup-ACK with no SACK).
        """

        self.assertEqual(
            tlp_process_ack(
                tlp_end_seq=100,
                tlp_is_retrans=True,
                ack_seq=100,
                has_dsack_for_probe=False,
                has_sack_blocks=False,
            ),
            (None, False),
            msg="bare dup-ACK with no SACK must clear state (Case 2).",
        )
        self.assertEqual(
            tlp_process_ack(
                tlp_end_seq=100,
                tlp_is_retrans=True,
                ack_seq=100,
                has_dsack_for_probe=False,
                has_sack_blocks=True,
            ),
            (100, False),
            msg="dup-ACK WITH SACK blocks must preserve state (kills 'and not sack').",
        )


class TestRackMutationGoldens2(TestCase):
    """
    Multi-segment continue/break, RTT-skip boundary, and TLP PTO
    boundary goldens closing the second-pass RACK survivors.
    """

    def test__rack__update_multi_segment_skip_then_process(self) -> None:
        """
        Ensure the update loop continues past a skipped segment to
        process a later one: an INFINITE_TS segment and a
        TSecr-disqualified retransmit each precede a valid segment that
        must still be folded (kills 'continue'→'break').

        Reference: RFC 8985 §6.2 step 2 (per-segment update loop).
        """

        self.assertEqual(
            rack_update(
                newly_acked_segments=[
                    RackSegment(50, INFINITE_TS, False, False),
                    RackSegment(100, 500, False, False),
                ],
                now_ms=1000,
                ts_recent_echo_ms=None,
                prior_min_rtt_ms=0,
                prior_rack_rtt_ms=0,
                prior_rack_xmit_ts=0,
                prior_rack_end_seq=0,
            ),
            (500, 500, 500, 100),
            msg="INFINITE_TS segment must be skipped, the next still processed.",
        )
        self.assertEqual(
            rack_update(
                newly_acked_segments=[
                    RackSegment(50, 500, True, False),
                    RackSegment(100, 600, False, False),
                ],
                now_ms=1000,
                ts_recent_echo_ms=400,
                prior_min_rtt_ms=0,
                prior_rack_rtt_ms=0,
                prior_rack_xmit_ts=0,
                prior_rack_end_seq=0,
            ),
            (400, 400, 600, 100),
            msg="TSecr-skipped retransmit must not break the loop; next still processed.",
        )

    def test__rack__update_tsecr_skip_boundary_is_strict(self) -> None:
        """
        Ensure the TSecr retransmit skip uses a strict '<': a TSecr
        exactly equal to the segment's xmit_ts does NOT skip (kills
        '<'→'<=').

        Reference: RFC 8985 §6.2 step 2 (TSecr < xmit_ts disambiguation).
        """

        self.assertEqual(
            rack_update(
                newly_acked_segments=[RackSegment(100, 500, True, False)],
                now_ms=1000,
                ts_recent_echo_ms=500,
                prior_min_rtt_ms=0,
                prior_rack_rtt_ms=0,
                prior_rack_xmit_ts=0,
                prior_rack_end_seq=0,
            ),
            (500, 500, 500, 100),
            msg="TSecr == xmit_ts must NOT skip the segment (strict '<').",
        )

    def test__rack__detect_loss_multi_segment_skip_then_mark(self) -> None:
        """
        Ensure detect_loss continues past an already-lost segment and
        past a not-sent-after segment to still mark a later loss
        candidate (kills 'continue'→'break').

        Reference: RFC 8985 §6.2 step 5 (per-segment loss walk).
        """

        already_lost, _ = rack_detect_loss(
            segments={
                10: RackSegment(100, INFINITE_TS, False, True),
                20: RackSegment(200, 500, False, False),
            },
            rack_xmit_ts=700,
            rack_end_seq=300,
            reo_wnd_ms=100,
            now_ms=700,
        )
        self.assertTrue(
            already_lost[20].lost,
            msg="candidate after an already-lost segment must still be marked.",
        )
        not_after, _ = rack_detect_loss(
            segments={
                10: RackSegment(100, 900, False, False),
                20: RackSegment(200, 500, False, False),
            },
            rack_xmit_ts=700,
            rack_end_seq=300,
            reo_wnd_ms=100,
            now_ms=700,
        )
        self.assertFalse(not_after[10].lost, msg="not-sent-after segment preserved.")
        self.assertTrue(
            not_after[20].lost,
            msg="candidate after a not-sent-after segment must still be marked.",
        )

    def test__tlp__calc_pto_branch_boundaries(self) -> None:
        """
        Ensure the TLP PTO branches at their exact boundaries: a zero
        SRTT falls through to the 1000 ms default (strict '> 0'), a
        FlightSize strictly below one segment still inflates by
        max_ack_delay (kills '<='→'=='), the RTO-remaining uses
        subtraction with a non-zero now, and a non-positive RTO
        remaining applies no cap.

        Reference: RFC 8985 §7.2 (TLP PTO branches).
        """

        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=0,
                flight_size=2920,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=None,
                now_ms=0,
            ),
            1000,
            msg="SRTT == 0 must fall through to the 1000 ms default (strict '> 0').",
        )
        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=700,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=None,
                now_ms=0,
            ),
            225,
            msg="FlightSize below one segment must inflate by max_ack_delay (kills '<='→'==').",
        )
        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=2920,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=250,
                now_ms=100,
            ),
            149,
            msg="RTO remaining = 250 - 100 = 150; PTO capped to 149 (kills '-'→'+').",
        )
        self.assertEqual(
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=2920,
                smss=1460,
                max_ack_delay_ms=25,
                rto_expiration_ms=50,
                now_ms=100,
            ),
            200,
            msg="non-positive RTO remaining must not cap (kills '> 0'→'!= 0').",
        )

    def test__tlp__calc_pto_smss_guard_rejects_negative(self) -> None:
        """
        Ensure the smss guard rejects a negative value (kills '> 0'→'!= 0').

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            tlp_calc_pto(
                srtt_ms=100,
                flight_size=0,
                smss=-1,
                max_ack_delay_ms=0,
                rto_expiration_ms=None,
                now_ms=0,
            )
