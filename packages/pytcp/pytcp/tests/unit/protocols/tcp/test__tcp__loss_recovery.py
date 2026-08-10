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
This module contains tests for the RFC 6675 Conservative Loss
Recovery predicates (IsLost, NextSeg, Pipe) in
'pytcp.protocols.tcp.tcp__loss_recovery', covering both triggers of IsLost
(count threshold, byte threshold), NextSeg's gap-then-is-lost
gate, and Pipe's in-flight-minus-sacked accounting.

pytcp/tests/unit/protocols/tcp/test__tcp__loss_recovery.py

ver 3.0.10
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__loss_recovery import is_lost, next_seg, pipe
from pytcp.protocols.tcp.tcp__sack import SackScoreboard

# Canonical IPv4-Ethernet MSS used across the helper tests.
MSS: int = 1460


class TestIsLost(TestCase):
    """
    The 'is_lost' RFC 6675 §3 IsLost(SeqNum) predicate tests.
    """

    def test__is_lost__empty_scoreboard_returns_false(self) -> None:
        """
        Ensure 'is_lost' returns False when the scoreboard has no
        blocks - neither the count nor the byte threshold can fire.
        Reference: RFC 6675 §3 (IsLost predicate).
        """

        scoreboard = SackScoreboard()
        self.assertFalse(
            is_lost(0, scoreboard=scoreboard, snd_una=0, mss=MSS),
            msg="An empty scoreboard cannot trigger IsLost.",
        )

    def test__is_lost__three_blocks_above_seq_triggers_count_rule(self) -> None:
        """
        Ensure 'is_lost' fires on the count rule when at least
        'dup_thresh' (default 3) discontiguous SACK blocks lie
        at or above 'seq'.

        Reference: RFC 6675 §3 (IsLost count rule, condition (1)).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1000, 1100)
        scoreboard.add_block(1200, 1300)
        scoreboard.add_block(1400, 1500)
        self.assertTrue(
            is_lost(500, scoreboard=scoreboard, snd_una=500, mss=MSS),
            msg="Three discontiguous SACK blocks above seq must trigger IsLost via the count rule.",
        )

    def test__is_lost__two_blocks_below_count_threshold_returns_false(self) -> None:
        """
        Ensure 'is_lost' is False with two blocks of small
        total size - count rule needs three blocks, byte rule
        needs more than '(dup_thresh-1) * mss' bytes.

        Reference: RFC 6675 §3 (IsLost neither rule satisfied).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1000, 1100)
        scoreboard.add_block(1200, 1300)
        self.assertFalse(
            is_lost(500, scoreboard=scoreboard, snd_una=500, mss=MSS),
            msg=(
                "Two small blocks (200 bytes total) cannot trigger IsLost: "
                "below count threshold AND below byte threshold."
            ),
        )

    def test__is_lost__single_block_byte_threshold_triggers_byte_rule(self) -> None:
        """
        Ensure 'is_lost' fires on the byte rule when a single
        SACK block above 'seq' carries more than
        '(dup_thresh - 1) * mss' bytes (default = '2 * mss').

        Reference: RFC 6675 §3 (IsLost byte rule, condition (2)).
        """

        scoreboard = SackScoreboard()
        # 2 * mss + 1 bytes - just over the byte threshold.
        scoreboard.add_block(1000, 1000 + 2 * MSS + 1)
        self.assertTrue(
            is_lost(500, scoreboard=scoreboard, snd_una=500, mss=MSS),
            msg="A single SACK block carrying > 2*MSS bytes above seq must trigger IsLost via the byte rule.",
        )

    def test__is_lost__single_block_at_byte_threshold_returns_false(self) -> None:
        """
        Ensure 'is_lost' returns False when bytes above 'seq'
        equal exactly '(dup_thresh - 1) * mss' - the spec
        requires STRICTLY MORE than that (the inequality is
        '>', not '>=').

        Reference: RFC 6675 §3 (IsLost byte-rule strict inequality).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1000, 1000 + 2 * MSS)  # exactly at threshold.
        self.assertFalse(
            is_lost(500, scoreboard=scoreboard, snd_una=500, mss=MSS),
            msg=(
                "A single SACK block carrying exactly 2*MSS bytes above seq must NOT trigger IsLost; "
                "the byte threshold uses '>' not '>='."
            ),
        )

    def test__is_lost__custom_dup_thresh_lowers_count_trigger(self) -> None:
        """
        Ensure a caller-supplied 'dup_thresh' lowers the count
        trigger - two blocks fire IsLost when 'dup_thresh = 2'.

        Reference: RFC 6675 §3 (IsLost DupThresh parameter).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1000, 1100)
        scoreboard.add_block(1200, 1300)
        self.assertTrue(
            is_lost(500, scoreboard=scoreboard, snd_una=500, mss=MSS, dup_thresh=2),
            msg="With 'dup_thresh=2' two blocks must trigger IsLost via the count rule.",
        )

    def test__is_lost__blocks_below_seq_ignored(self) -> None:
        """
        Ensure 'is_lost' ignores blocks whose left edge falls
        below 'seq' - only blocks at or above 'seq' contribute
        to either threshold.

        Reference: RFC 6675 §3 (IsLost considers blocks above the candidate seq).
        """

        scoreboard = SackScoreboard()
        # Three blocks all below seq=2000.
        scoreboard.add_block(100, 200)
        scoreboard.add_block(300, 400)
        scoreboard.add_block(500, 600)
        self.assertFalse(
            is_lost(2000, scoreboard=scoreboard, snd_una=0, mss=MSS),
            msg="Blocks below 'seq' must not contribute to either IsLost rule.",
        )

    def test__is_lost__rejects_non_uint32_seq(self) -> None:
        """
        Ensure 'is_lost' asserts when 'seq' is outside the
        32-bit unsigned range.

        Reference: RFC 9293 §3.4 (32-bit sequence number space).
        """

        scoreboard = SackScoreboard()
        with self.assertRaises(AssertionError):
            is_lost(-1, scoreboard=scoreboard, snd_una=0, mss=MSS)


class TestNextSeg(TestCase):
    """
    The 'next_seg' RFC 6675 §3 NextSeg() procedure tests.
    """

    def test__next_seg__empty_scoreboard_no_loss_returns_none(self) -> None:
        """
        Ensure 'next_seg' returns None when the scoreboard is
        empty - even though there is a gap at SND.UNA, IsLost
        cannot fire without any SACK info, so no retransmit is
        warranted.

        Reference: RFC 6675 §3 (NextSeg procedure, no candidate when IsLost False).
        """

        scoreboard = SackScoreboard()
        self.assertIsNone(
            next_seg(scoreboard=scoreboard, snd_una=1000, snd_max=2000, mss=MSS),
            msg="Empty scoreboard means IsLost cannot fire and 'next_seg' must return None.",
        )

    def test__next_seg__three_blocks_above_gap_returns_gap(self) -> None:
        """
        Ensure 'next_seg' returns the gap (= SND.UNA in this
        scenario) when three blocks above it trigger IsLost
        via the count rule.

        Reference: RFC 6675 §3 (NextSeg returns first IsLost-positive seq).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1100, 1200)
        scoreboard.add_block(1300, 1400)
        scoreboard.add_block(1500, 1600)
        self.assertEqual(
            next_seg(scoreboard=scoreboard, snd_una=1000, snd_max=2000, mss=MSS),
            1000,
            msg="With three blocks above the gap, 'next_seg' must return the gap (= SND.UNA here).",
        )

    def test__next_seg__below_thresh_blocks_return_none(self) -> None:
        """
        Ensure 'next_seg' returns None when only one small
        block is above the gap - IsLost is not satisfied.

        Reference: RFC 6675 §3 (NextSeg returns no candidate when IsLost False).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1100, 1200)
        self.assertIsNone(
            next_seg(scoreboard=scoreboard, snd_una=1000, snd_max=2000, mss=MSS),
            msg="A single small block above the gap is below IsLost's thresholds; 'next_seg' must return None.",
        )

    def test__next_seg__gap_above_snd_max_returns_none(self) -> None:
        """
        Ensure 'next_seg' returns None when the gap is at or
        above SND.MAX - there is no in-flight byte at that
        seq.

        Reference: RFC 6675 §3 (NextSeg upper bound at SND.MAX).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1000, 2000)
        # Gap is at 2000 but SND.MAX is also 2000 - nothing to
        # retransmit.
        self.assertIsNone(
            next_seg(scoreboard=scoreboard, snd_una=1000, snd_max=2000, mss=MSS),
            msg="A gap at or above SND.MAX has no in-flight byte; 'next_seg' must return None.",
        )

    def test__next_seg__byte_rule_triggers_with_one_large_block(self) -> None:
        """
        Ensure 'next_seg' returns the gap when IsLost's byte
        rule fires from a single large block above the gap.

        Reference: RFC 6675 §3 (NextSeg using byte-rule IsLost).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1100, 1100 + 2 * MSS + 1)  # > 2*MSS bytes.
        self.assertEqual(
            next_seg(scoreboard=scoreboard, snd_una=1000, snd_max=10000, mss=MSS),
            1000,
            msg="A single block carrying > 2*MSS bytes above the gap must trigger 'next_seg' via the byte rule.",
        )


class TestPipe(TestCase):
    """
    The 'pipe' RFC 6675 §4 Pipe() in-flight estimate tests.
    """

    def test__pipe__empty_scoreboard_returns_full_in_flight(self) -> None:
        """
        Ensure 'pipe' returns 'snd_max - snd_una' when the
        scoreboard is empty - nothing has been SACKed, so
        every sent-but-uncum-acked byte is still considered
        in flight.

        Reference: RFC 6675 §4 (Pipe estimate of FlightSize).
        """

        scoreboard = SackScoreboard()
        self.assertEqual(
            pipe(scoreboard=scoreboard, snd_una=1000, snd_max=4000),
            3000,
            msg="An empty scoreboard means in-flight = SND.MAX - SND.UNA.",
        )

    def test__pipe__one_block_subtracts_sacked_bytes(self) -> None:
        """
        Ensure 'pipe' subtracts SACKed bytes from the
        in-flight estimate.

        Reference: RFC 6675 §4 (Pipe subtracts SACKed bytes).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(2000, 3000)  # 1000 bytes sacked.
        self.assertEqual(
            pipe(scoreboard=scoreboard, snd_una=1000, snd_max=4000),
            2000,
            msg="With 1000 bytes SACKed of a 3000-byte in-flight range, pipe = 2000.",
        )

    def test__pipe__multiple_blocks_subtract_total_sacked_bytes(self) -> None:
        """
        Ensure 'pipe' sums the bytes across multiple SACK
        blocks and subtracts the total.

        Reference: RFC 6675 §4 (Pipe sums all SACKed bytes).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1100, 1300)  # 200 bytes
        scoreboard.add_block(1500, 1700)  # 200 bytes
        scoreboard.add_block(1900, 2100)  # 200 bytes
        self.assertEqual(
            pipe(scoreboard=scoreboard, snd_una=1000, snd_max=2200),
            1200 - 600,
            msg="Pipe must sum across all in-window blocks and subtract the total (600 bytes).",
        )

    def test__pipe__out_of_window_blocks_ignored(self) -> None:
        """
        Ensure 'pipe' ignores blocks whose edges fall outside
        '[SND.UNA, SND.MAX]' - a defensive sum that cannot
        make the result negative.

        Reference: RFC 6675 §4 (Pipe operates on in-flight window only).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(2000, 3000)  # in-window, 1000 bytes.
        scoreboard.add_block(5000, 6000)  # entirely above SND.MAX.
        self.assertEqual(
            pipe(scoreboard=scoreboard, snd_una=1000, snd_max=4000),
            2000,
            msg="Out-of-window SACK blocks must be ignored by Pipe; only in-window bytes are subtracted.",
        )

    def test__pipe__rejects_non_uint32_snd_una(self) -> None:
        """
        Ensure 'pipe' asserts when 'snd_una' is outside the
        32-bit unsigned range.

        Reference: RFC 9293 §3.4 (32-bit sequence number space).
        """

        scoreboard = SackScoreboard()
        with self.assertRaises(AssertionError):
            pipe(scoreboard=scoreboard, snd_una=-1, snd_max=4000)


class TestLossRecoveryMutationGoldens(TestCase):
    """
    Branch-boundary and argument-guard goldens closing the remaining
    is_lost / next_seg / pipe mutation survivors.
    """

    def test__is_lost__block_count_at_exact_dup_thresh(self) -> None:
        """
        Ensure IsLost rule 1 fires at exactly dup_thresh discontiguous
        SACK blocks (a '>='→'>' edit would require one more block).

        Reference: RFC 6675 §3 (IsLost: >= dup_thresh blocks above seq).
        """

        scoreboard = SackScoreboard()
        for left in (2000, 2200, 2400):
            scoreboard.add_block(left, left + 100)
        self.assertTrue(
            is_lost(1000, scoreboard=scoreboard, snd_una=1000, mss=1460, dup_thresh=3),
            msg="exactly 3 blocks above seq with dup_thresh=3 must be lost.",
        )

    def test__is_lost__byte_rule_uses_dup_thresh_minus_one(self) -> None:
        """
        Ensure IsLost rule 2 threshold is (dup_thresh - 1) * mss: with
        dup_thresh=4 a single SACK block of 3*mss+1 bytes exceeds
        3*mss and is lost, where a '-'→'^' edit (4^1=5) would raise
        the bar to 5*mss.

        Reference: RFC 6675 §3 (IsLost: > (dup_thresh-1)*mss bytes above seq).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(2000, 2000 + 3 * 1460 + 1)
        self.assertTrue(
            is_lost(1000, scoreboard=scoreboard, snd_una=1000, mss=1460, dup_thresh=4),
            msg="3*mss+1 SACKed bytes with dup_thresh=4 must be lost (kills '-'→'^').",
        )

    def test__is_lost__argument_guards(self) -> None:
        """
        Ensure the mss and dup_thresh guards accept their exact lower
        bound of 1 and reject 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        scoreboard = SackScoreboard()
        is_lost(1000, scoreboard=scoreboard, snd_una=1000, mss=1, dup_thresh=1)
        with self.assertRaises(AssertionError):
            is_lost(1000, scoreboard=scoreboard, snd_una=1000, mss=0, dup_thresh=1)
        with self.assertRaises(AssertionError):
            is_lost(1000, scoreboard=scoreboard, snd_una=1000, mss=1460, dup_thresh=0)

    def test__next_seg_none_when_gap_not_below_snd_max(self) -> None:
        """
        Ensure next_seg short-circuits to None when the gap is not
        strictly below SND.MAX, even when that gap would itself be
        'lost' — pinning the 'or' against an 'and' edit that would
        fall through to is_lost and return the gap.

        Reference: RFC 6675 §3 (NextSeg: gap must be below SND.MAX).
        """

        scoreboard = SackScoreboard()
        for left in (2000, 2200, 2400):
            scoreboard.add_block(left, left + 100)
        self.assertIsNone(
            next_seg(scoreboard=scoreboard, snd_una=1000, snd_max=1000, mss=1460),
            msg="gap == snd_max must yield None (kills 'or'→'and').",
        )

    def test__pipe_continues_past_out_of_window_block(self) -> None:
        """
        Ensure pipe continues scanning after skipping an out-of-window
        block: a leading out-of-window block must not break the loop
        and drop a later in-window block from the SACKed total.

        Reference: RFC 6675 §4 (Pipe sums all in-window SACKed bytes).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(500, 600)
        scoreboard.add_block(2000, 2100)
        self.assertEqual(
            pipe(scoreboard=scoreboard, snd_una=1000, snd_max=3000),
            1900,
            msg="out-of-window block must be skipped (continue), not break: pipe=1900.",
        )

    def test__is_lost__block_count_above_dup_thresh_still_lost(self) -> None:
        """
        Ensure IsLost rule 1 fires when MORE than dup_thresh blocks lie
        above seq (4 blocks, dup_thresh=3), pinning the '>=' against an
        '==' edit that would only fire at exactly dup_thresh.

        Reference: RFC 6675 §3 (IsLost: >= dup_thresh blocks above seq).
        """

        scoreboard = SackScoreboard()
        for left in (2000, 2200, 2400, 2600):
            scoreboard.add_block(left, left + 50)
        self.assertTrue(
            is_lost(1000, scoreboard=scoreboard, snd_una=1000, mss=1460, dup_thresh=3),
            msg="4 blocks above seq with dup_thresh=3 must be lost (kills '>='→'==').",
        )

    def test__is_lost__guards_reject_negative(self) -> None:
        """
        Ensure the mss and dup_thresh guards reject negative values
        (kills '> 0'→'!= 0').

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        scoreboard = SackScoreboard()
        with self.assertRaises(AssertionError):
            is_lost(1000, scoreboard=scoreboard, snd_una=1000, mss=-1, dup_thresh=3)
        with self.assertRaises(AssertionError):
            is_lost(1000, scoreboard=scoreboard, snd_una=1000, mss=1460, dup_thresh=-1)
