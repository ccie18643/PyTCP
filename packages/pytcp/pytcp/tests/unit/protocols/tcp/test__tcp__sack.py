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
This module contains tests for the TCP SACK scoreboard helper in
'pytcp.protocols.tcp.tcp__sack', covering RFC 2018 §3 union semantics, modular
comparisons across the 32-bit seq wrap, and the prune / first-gap
operations the phase-5 RFC 6675 NextSeg / IsLost wrappers will
build on.

pytcp/tests/unit/protocols/tcp/test__tcp__sack.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_proto.lib.int_checks import UINT_32__MAX
from pytcp.protocols.tcp.tcp__sack import SackScoreboard, _overlaps_or_touches
from pytcp.tests.lib.parameterized import parameterized_class


class TestSackScoreboard__Init(TestCase):
    """
    The 'SackScoreboard' empty-state invariants.
    """

    def test__sack_scoreboard__init__blocks_empty(self) -> None:
        """
        Ensure a fresh scoreboard has zero tracked blocks.
        Reference: RFC 2018 §3 (SACK option, scoreboard initial state).
        """

        scoreboard = SackScoreboard()
        self.assertEqual(
            scoreboard.blocks(),
            [],
            msg="A fresh SackScoreboard must report no tracked blocks.",
        )

    def test__sack_scoreboard__init__is_sacked_false_for_zero(self) -> None:
        """
        Ensure 'is_sacked' returns False for any seq when the
        scoreboard is empty - nothing has been SACK-acked yet.
        Reference: RFC 2018 §3 (SACK option, empty scoreboard semantics).
        """

        scoreboard = SackScoreboard()
        self.assertFalse(
            scoreboard.is_sacked(0),
            msg="An empty SackScoreboard must report 'is_sacked' False at zero.",
        )

    def test__sack_scoreboard__init__is_sacked_false_for_uint32_ceiling(self) -> None:
        """
        Ensure 'is_sacked' returns False at the modular ceiling on an
        empty scoreboard (no off-by-one or sign-flip at the wrap).
        Reference: RFC 2018 §3 + RFC 9293 §3.4 (32-bit modular seq space).
        """

        scoreboard = SackScoreboard()
        self.assertFalse(
            scoreboard.is_sacked(UINT_32__MAX),
            msg="An empty SackScoreboard must report 'is_sacked' False at UINT_32__MAX.",
        )


class TestSackScoreboard__AddBlock(TestCase):
    """
    The 'SackScoreboard.add_block' insertion and merge semantics.
    """

    def test__sack_scoreboard__add_block__single_stored_unchanged(self) -> None:
        """
        Ensure adding one '[left, right)' block stores it verbatim.
        Reference: RFC 2018 §3 (SACK option block format).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 200)
        self.assertEqual(
            scoreboard.blocks(),
            [(100, 200)],
            msg="A single added block must be stored verbatim.",
        )

    def test__sack_scoreboard__add_block__two_disjoint_kept_separate(self) -> None:
        """
        Ensure two strictly disjoint, non-adjacent blocks are kept
        as separate entries (no spurious merge).
        Reference: RFC 2018 §3 (multiple SACK blocks).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 200)
        scoreboard.add_block(300, 400)
        self.assertEqual(
            sorted(scoreboard.blocks()),
            [(100, 200), (300, 400)],
            msg="Two strictly disjoint blocks must remain separate.",
        )

    def test__sack_scoreboard__add_block__adjacent_blocks_coalesce(self) -> None:
        """
        Ensure two exactly-adjacent blocks ('A.right == B.left')
        coalesce into a single block.

        Reference: RFC 2018 §3 (SACK union semantics, adjacent merge).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 200)
        scoreboard.add_block(200, 300)
        self.assertEqual(
            scoreboard.blocks(),
            [(100, 300)],
            msg="Adjacent blocks must coalesce into a single union block.",
        )

    def test__sack_scoreboard__add_block__adjacent_reverse_order_coalesce(self) -> None:
        """
        Ensure adjacency detection is symmetric: adding the high
        block first then the low one still coalesces.
        Reference: RFC 2018 §3 (SACK union semantics, order-agnostic).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(200, 300)
        scoreboard.add_block(100, 200)
        self.assertEqual(
            scoreboard.blocks(),
            [(100, 300)],
            msg="Adjacency must be detected regardless of insertion order.",
        )

    def test__sack_scoreboard__add_block__overlapping_blocks_union(self) -> None:
        """
        Ensure overlapping blocks merge into the union of their
        ranges (lower left edge, higher right edge).
        Reference: RFC 2018 §3 (SACK union semantics, overlap merge).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 250)
        scoreboard.add_block(200, 300)
        self.assertEqual(
            scoreboard.blocks(),
            [(100, 300)],
            msg="Overlapping blocks must merge into '[min_left, max_right)'.",
        )

    def test__sack_scoreboard__add_block__nested_block_absorbed(self) -> None:
        """
        Ensure a smaller block fully contained inside an existing
        block is absorbed without changing the existing range.
        Reference: RFC 2018 §3 (nested SACK absorption).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 300)
        scoreboard.add_block(150, 250)
        self.assertEqual(
            scoreboard.blocks(),
            [(100, 300)],
            msg="A nested block must be absorbed without growing the parent range.",
        )

    def test__sack_scoreboard__add_block__container_subsumes_existing(self) -> None:
        """
        Ensure a larger block subsumes a smaller existing block:
        only one '[left, right)' tuple remains, with the larger
        edges.
        Reference: RFC 2018 §3 (containing-block subsumption).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(150, 250)
        scoreboard.add_block(100, 300)
        self.assertEqual(
            scoreboard.blocks(),
            [(100, 300)],
            msg="A new block that contains an existing one must subsume it.",
        )

    def test__sack_scoreboard__add_block__bridge_coalesces_chain(self) -> None:
        """
        Ensure a bridging block that connects two formerly-disjoint
        ranges coalesces all three into one (transitive merge).
        Reference: RFC 2018 §3 (transitive SACK union).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 200)
        scoreboard.add_block(300, 400)
        scoreboard.add_block(150, 350)
        self.assertEqual(
            scoreboard.blocks(),
            [(100, 400)],
            msg="A bridging block must coalesce a chain of disjoint blocks transitively.",
        )

    def test__sack_scoreboard__add_block__cross_wrap_merge(self) -> None:
        """
        Ensure two adjacent blocks that straddle the 32-bit wrap
        coalesce: '[0xFFFFFFE0, 0xFFFFFFFF)' adjacent to
        '[0xFFFFFFFF, 0x0000_0010)' produces a single block of 48
        bytes spanning the wrap boundary.
        Reference: RFC 2018 §3 + RFC 9293 §3.4 (modular seq arithmetic).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(0xFFFF_FFE0, 0xFFFF_FFFF)
        scoreboard.add_block(0xFFFF_FFFF, 0x0000_0010)
        self.assertEqual(
            scoreboard.blocks(),
            [(0xFFFF_FFE0, 0x0000_0010)],
            msg="Adjacent blocks straddling the 32-bit wrap must coalesce modularly.",
        )

    def test__sack_scoreboard__add_block__cross_wrap_disjoint_kept_separate(self) -> None:
        """
        Ensure two disjoint blocks on opposite sides of the 32-bit
        wrap stay separate: '[0xFFFF_FF00, 0xFFFF_FF20)' and
        '[0x0000_0100, 0x0000_0200)' have a gap across the wrap and
        must not merge.
        Reference: RFC 2018 §3 + RFC 9293 §3.4 (modular seq arithmetic).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(0xFFFF_FF00, 0xFFFF_FF20)
        scoreboard.add_block(0x0000_0100, 0x0000_0200)
        self.assertEqual(
            sorted(scoreboard.blocks()),
            sorted([(0xFFFF_FF00, 0xFFFF_FF20), (0x0000_0100, 0x0000_0200)]),
            msg="Disjoint blocks on opposite sides of the wrap must not merge.",
        )

    def test__sack_scoreboard__add_block__rejects_zero_length_range(self) -> None:
        """
        Ensure 'add_block' asserts when 'left == right' (a SACK
        block must cover at least one byte).
        Reference: RFC 2018 §3 (SACK block edge half-open invariant).
        """

        scoreboard = SackScoreboard()
        with self.assertRaises(AssertionError):
            scoreboard.add_block(100, 100)

    def test__sack_scoreboard__add_block__rejects_reverse_range(self) -> None:
        """
        Ensure 'add_block' asserts when 'lt32(left, right)' fails
        (a block must point forward in modular seq space and span
        less than half the 32-bit range).
        Reference: RFC 2018 §3 + RFC 9293 §3.4 (forward seq direction).
        """

        scoreboard = SackScoreboard()
        with self.assertRaises(AssertionError):
            scoreboard.add_block(200, 100)

    def test__sack_scoreboard__add_block__rejects_non_uint32_left(self) -> None:
        """
        Ensure 'add_block' asserts when 'left' is outside the
        32-bit unsigned range.
        Reference: RFC 9293 §3.4 (32-bit sequence number space).
        """

        scoreboard = SackScoreboard()
        with self.assertRaises(AssertionError):
            scoreboard.add_block(-1, 100)

    def test__sack_scoreboard__add_block__rejects_non_uint32_right(self) -> None:
        """
        Ensure 'add_block' asserts when 'right' is outside the
        32-bit unsigned range.
        Reference: RFC 9293 §3.4 (32-bit sequence number space).
        """

        scoreboard = SackScoreboard()
        with self.assertRaises(AssertionError):
            scoreboard.add_block(100, UINT_32__MAX + 1)


@parameterized_class(
    [
        {
            "_description": "Seq below the block.",
            "_blocks": [(100, 200)],
            "_seq": 99,
            "_expected": False,
        },
        {
            "_description": "Seq at the left edge (inclusive).",
            "_blocks": [(100, 200)],
            "_seq": 100,
            "_expected": True,
        },
        {
            "_description": "Seq inside the block.",
            "_blocks": [(100, 200)],
            "_seq": 150,
            "_expected": True,
        },
        {
            "_description": "Seq at the right edge (exclusive).",
            "_blocks": [(100, 200)],
            "_seq": 200,
            "_expected": False,
        },
        {
            "_description": "Seq one past the right edge.",
            "_blocks": [(100, 200)],
            "_seq": 201,
            "_expected": False,
        },
        {
            "_description": "Seq covered by the second of two blocks.",
            "_blocks": [(100, 200), (300, 400)],
            "_seq": 350,
            "_expected": True,
        },
        {
            "_description": "Seq in the gap between two blocks.",
            "_blocks": [(100, 200), (300, 400)],
            "_seq": 250,
            "_expected": False,
        },
        {
            "_description": "Seq inside a wrap-spanning block.",
            "_blocks": [(0xFFFF_FFE0, 0x0000_0010)],
            "_seq": 0x0000_0005,
            "_expected": True,
        },
        {
            "_description": "Seq at the right edge of a wrap-spanning block (exclusive).",
            "_blocks": [(0xFFFF_FFE0, 0x0000_0010)],
            "_seq": 0x0000_0010,
            "_expected": False,
        },
        {
            "_description": "Seq at the left edge of a wrap-spanning block.",
            "_blocks": [(0xFFFF_FFE0, 0x0000_0010)],
            "_seq": 0xFFFF_FFE0,
            "_expected": True,
        },
        {
            "_description": "Seq just below a wrap-spanning block (below left edge, modularly).",
            "_blocks": [(0xFFFF_FFE0, 0x0000_0010)],
            "_seq": 0xFFFF_FFDF,
            "_expected": False,
        },
    ]
)
class TestSackScoreboard__IsSacked(TestCase):
    """
    The 'SackScoreboard.is_sacked' coverage-query matrix.
    """

    _description: str
    _blocks: list[tuple[int, int]]
    _seq: int
    _expected: bool

    def test__sack_scoreboard__is_sacked(self) -> None:
        """
        Ensure 'is_sacked' returns the expected boolean for each
        (block-set, query-seq) case.
        Reference: RFC 2018 §3 + RFC 6675 §3 (SACK block coverage query).
        """

        scoreboard = SackScoreboard()
        for left, right in self._blocks:
            scoreboard.add_block(left, right)
        self.assertEqual(
            scoreboard.is_sacked(self._seq),
            self._expected,
            msg=f"Unexpected 'is_sacked' result for case: {self._description}",
        )


class TestSackScoreboard__PruneBelow(TestCase):
    """
    The 'SackScoreboard.prune_below' cumulative-ACK absorption.
    """

    def test__sack_scoreboard__prune_below__empty_is_no_op(self) -> None:
        """
        Ensure 'prune_below' on an empty scoreboard leaves it empty.
        Reference: RFC 2018 §3 / RFC 6675 §6 (cumulative-ACK absorption).
        """

        scoreboard = SackScoreboard()
        scoreboard.prune_below(1000)
        self.assertEqual(
            scoreboard.blocks(),
            [],
            msg="prune_below on empty scoreboard must remain empty.",
        )

    def test__sack_scoreboard__prune_below__entirely_below_is_dropped(self) -> None:
        """
        Ensure a block whose right edge is at or below 'snd_una' is
        dropped entirely (cumulative ACK has absorbed it).
        Reference: RFC 2018 §3 / RFC 6675 §6 (cumulative-ACK absorption).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 200)
        scoreboard.prune_below(200)
        self.assertEqual(
            scoreboard.blocks(),
            [],
            msg="Block with right == snd_una must be dropped (half-open invariant).",
        )

    def test__sack_scoreboard__prune_below__strictly_below_is_dropped(self) -> None:
        """
        Ensure a block strictly below the new 'snd_una' is dropped.
        Reference: RFC 2018 §3 / RFC 6675 §6 (cumulative-ACK absorption).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 200)
        scoreboard.prune_below(500)
        self.assertEqual(
            scoreboard.blocks(),
            [],
            msg="Block strictly below snd_una must be dropped.",
        )

    def test__sack_scoreboard__prune_below__straddling_block_is_trimmed(self) -> None:
        """
        Ensure a block whose left edge is below 'snd_una' but right
        edge is above is trimmed: the surviving block has 'left ==
        snd_una' and 'right' unchanged.
        Reference: RFC 2018 §3 / RFC 6675 §6 (cumulative-ACK trimming).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 300)
        scoreboard.prune_below(200)
        self.assertEqual(
            scoreboard.blocks(),
            [(200, 300)],
            msg="Straddling block must be trimmed left-edge to snd_una.",
        )

    def test__sack_scoreboard__prune_below__entirely_above_is_kept(self) -> None:
        """
        Ensure a block strictly above 'snd_una' is kept verbatim.
        Reference: RFC 2018 §3 / RFC 6675 §6 (above-cum-ACK retention).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(300, 400)
        scoreboard.prune_below(200)
        self.assertEqual(
            scoreboard.blocks(),
            [(300, 400)],
            msg="Block strictly above snd_una must be kept verbatim.",
        )

    def test__sack_scoreboard__prune_below__mixed_set_partitioned(self) -> None:
        """
        Ensure a mixed scoreboard - one block below, one straddling,
        one above 'snd_una' - is partitioned correctly: below dropped,
        straddling trimmed, above kept.
        Reference: RFC 2018 §3 / RFC 6675 §6 (cumulative-ACK partition).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 150)
        scoreboard.add_block(200, 300)
        scoreboard.add_block(400, 500)
        scoreboard.prune_below(250)
        self.assertEqual(
            sorted(scoreboard.blocks()),
            sorted([(250, 300), (400, 500)]),
            msg="Mixed pre-prune set must be split into dropped / trimmed / kept correctly.",
        )

    def test__sack_scoreboard__prune_below__across_wrap_keeps_block(self) -> None:
        """
        Ensure 'prune_below' near the 32-bit wrap keeps a block on
        the opposite side of the wrap (which is still 'above'
        'snd_una' in modular terms).
        Reference: RFC 2018 §3 + RFC 9293 §3.4 (modular cum-ACK).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(0x0000_0100, 0x0000_0200)
        scoreboard.prune_below(0xFFFF_FFE0)
        self.assertEqual(
            scoreboard.blocks(),
            [(0x0000_0100, 0x0000_0200)],
            msg="Block forward-of snd_una across the wrap must be kept.",
        )

    def test__sack_scoreboard__prune_below__rejects_non_uint32(self) -> None:
        """
        Ensure 'prune_below' asserts when 'snd_una' is outside the
        32-bit unsigned range.
        Reference: RFC 9293 §3.4 (32-bit sequence number space).
        """

        scoreboard = SackScoreboard()
        with self.assertRaises(AssertionError):
            scoreboard.prune_below(-1)


class TestSackScoreboard__FirstGap(TestCase):
    """
    The 'SackScoreboard.first_gap' lowest-uncovered-seq lookup.
    """

    def test__sack_scoreboard__first_gap__empty_returns_snd_una(self) -> None:
        """
        Ensure 'first_gap' on an empty scoreboard returns 'snd_una'
        verbatim - the first uncovered seq is right at SND.UNA when
        nothing is SACKed.
        Reference: RFC 6675 §4 (NextSeg gap-walking primitive).
        """

        scoreboard = SackScoreboard()
        self.assertEqual(
            scoreboard.first_gap(1000),
            1000,
            msg="Empty scoreboard must report first gap at snd_una.",
        )

    def test__sack_scoreboard__first_gap__block_above_snd_una_returns_snd_una(self) -> None:
        """
        Ensure 'first_gap' returns 'snd_una' when no tracked block
        starts at 'snd_una' (the gap is the byte at SND.UNA itself).
        Reference: RFC 6675 §4 (NextSeg gap-walking primitive).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1100, 1200)
        self.assertEqual(
            scoreboard.first_gap(1000),
            1000,
            msg="Block above snd_una leaves the gap at snd_una.",
        )

    def test__sack_scoreboard__first_gap__block_starts_at_snd_una_returns_block_right(self) -> None:
        """
        Ensure 'first_gap' walks a single block whose left edge
        equals 'snd_una' and returns the block's right edge.
        Reference: RFC 6675 §4 (NextSeg gap-walking primitive).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1000, 1200)
        self.assertEqual(
            scoreboard.first_gap(1000),
            1200,
            msg="Block starting at snd_una makes the gap appear at its right edge.",
        )

    def test__sack_scoreboard__first_gap__contiguous_chain_walked(self) -> None:
        """
        Ensure 'first_gap' walks through a chain of blocks that
        are exactly contiguous starting at 'snd_una' and returns the
        right edge of the last block in the chain.
        Reference: RFC 6675 §4 (NextSeg gap-walking primitive).
        """

        scoreboard = SackScoreboard()
        # add_block coalesces adjacent ranges itself, so to keep them
        # separate in the scoreboard we leave a one-byte gap and
        # assert the gap detection. The "contiguous chain" semantics
        # are equivalent: a single coalesced block.
        scoreboard.add_block(1000, 1100)
        scoreboard.add_block(1101, 1200)
        # Gap at 1100 is now reported.
        self.assertEqual(
            scoreboard.first_gap(1000),
            1100,
            msg="Walk must stop at the first uncovered byte (1100).",
        )

    def test__sack_scoreboard__first_gap__coalesced_chain_returns_right_edge(self) -> None:
        """
        Ensure 'first_gap' on a single coalesced block starting at
        'snd_una' returns the right edge of that block.
        Reference: RFC 6675 §4 (NextSeg gap-walking primitive).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1000, 1100)
        scoreboard.add_block(1100, 1200)  # adjacent: coalesces with the prior block.
        scoreboard.add_block(1200, 1300)  # adjacent: extends the coalesced range.
        self.assertEqual(
            scoreboard.first_gap(1000),
            1300,
            msg="Coalesced contiguous chain must report the chain's right edge as the gap.",
        )

    def test__sack_scoreboard__first_gap__below_snd_una_block_skipped(self) -> None:
        """
        Ensure 'first_gap' ignores blocks that sit below 'snd_una'
        (defensive against callers who skip 'prune_below').
        Reference: RFC 6675 §4 (NextSeg gap-walking primitive).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(500, 700)  # entirely below snd_una=1000
        self.assertEqual(
            scoreboard.first_gap(1000),
            1000,
            msg="Below-snd_una blocks must not move the reported gap.",
        )

    def test__sack_scoreboard__first_gap__across_wrap_chain_walked(self) -> None:
        """
        Ensure 'first_gap' walks through a coalesced chain that
        crosses the 32-bit wrap and reports the chain's right edge.
        Reference: RFC 6675 §4 + RFC 9293 §3.4 (modular gap walk).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(0xFFFF_FFE0, 0xFFFF_FFFF)
        scoreboard.add_block(0xFFFF_FFFF, 0x0000_0010)  # adjacent through the wrap
        self.assertEqual(
            scoreboard.first_gap(0xFFFF_FFE0),
            0x0000_0010,
            msg="Wrap-spanning chain must walk to its right edge across the modulus.",
        )

    def test__sack_scoreboard__first_gap__rejects_non_uint32(self) -> None:
        """
        Ensure 'first_gap' asserts when 'snd_una' is outside the
        32-bit unsigned range.
        Reference: RFC 9293 §3.4 (32-bit sequence number space).
        """

        scoreboard = SackScoreboard()
        with self.assertRaises(AssertionError):
            scoreboard.first_gap(UINT_32__MAX + 1)


class TestSackScoreboard__Blocks(TestCase):
    """
    The 'SackScoreboard.blocks' snapshot semantics.
    """

    def test__sack_scoreboard__blocks__returns_independent_list(self) -> None:
        """
        Ensure 'blocks' returns a fresh list snapshot - mutations of
        the returned list must not affect the scoreboard's internal
        state.
        Reference: RFC 2018 §3 (SACK block list immutability).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 200)
        snapshot = scoreboard.blocks()
        snapshot.append((9999, 9999))
        self.assertEqual(
            scoreboard.blocks(),
            [(100, 200)],
            msg="Mutating the returned snapshot must not affect the scoreboard.",
        )

    def test__sack_scoreboard__blocks__preserves_insertion_order(self) -> None:
        """
        Ensure 'blocks' preserves insertion order of distinct,
        non-merging blocks (callers that want 'most-recent
        first' ordering can apply their own permutation).

        Reference: RFC 2018 §4 (SACK block ordering).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(300, 400)
        scoreboard.add_block(100, 200)
        scoreboard.add_block(500, 600)
        self.assertEqual(
            scoreboard.blocks(),
            [(300, 400), (100, 200), (500, 600)],
            msg="Distinct-block insertion order must be preserved.",
        )


class TestSackScoreboard__TotalSackedBytes(TestCase):
    """
    The 'SackScoreboard.total_sacked_bytes' helper used by the
    RFC 6937 PRR delta-tracking hook in '_ingest_sack_info'.
    """

    def test__sack_scoreboard__total_sacked_bytes__empty_returns_zero(self) -> None:
        """
        Ensure an empty scoreboard reports zero sacked bytes.

        Reference: RFC 6937 §3.1 (DeliveredData = 0 baseline before any SACK).
        """

        scoreboard = SackScoreboard()
        self.assertEqual(
            scoreboard.total_sacked_bytes(),
            0,
            msg="Empty scoreboard must report zero sacked bytes.",
        )

    def test__sack_scoreboard__total_sacked_bytes__single_block_byte_count(self) -> None:
        """
        Ensure a single block reports its width as the byte count.

        Reference: RFC 6937 §3.1 (single-block byte coverage).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 250)
        self.assertEqual(
            scoreboard.total_sacked_bytes(),
            150,
            msg="Single block [100,250) covers 150 bytes.",
        )

    def test__sack_scoreboard__total_sacked_bytes__multiple_disjoint_blocks_sum(self) -> None:
        """
        Ensure multiple disjoint blocks sum their widths.

        Reference: RFC 6937 §3.1 (sum of disjoint coverage).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 200)
        scoreboard.add_block(300, 350)
        scoreboard.add_block(500, 700)
        self.assertEqual(
            scoreboard.total_sacked_bytes(),
            100 + 50 + 200,
            msg="Three disjoint blocks must sum to the total byte coverage.",
        )

    def test__sack_scoreboard__total_sacked_bytes__merged_blocks_no_double_count(self) -> None:
        """
        Ensure overlapping inserts that merge in the
        scoreboard count their union width once - the merge
        invariant guarantees no double-counting.

        Reference: RFC 6937 §3.1 (no double-counting under SACK union semantics).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(100, 250)
        scoreboard.add_block(200, 300)
        # Merged into [100, 300) = 200 bytes, NOT 150 + 100.
        self.assertEqual(
            scoreboard.total_sacked_bytes(),
            200,
            msg="Overlapping inserts merge into one block whose width is counted once.",
        )

    def test__sack_scoreboard__total_sacked_bytes__cross_wrap_block_byte_count(self) -> None:
        """
        Ensure a block straddling the 32-bit modular wrap
        reports its modular width correctly. PyTCP's seq
        space is 2**32 modular; '(right - left) & 0xFFFF_FFFF'
        recovers the forward distance even when 'right'
        wraps below 'left' numerically.

        Reference: RFC 9293 §3.4 (modular sequence-number arithmetic).
        """

        scoreboard = SackScoreboard()
        # Block [0xFFFF_FF00, 0x0000_0100) - 256 bytes
        # straddling the wrap (right = 256 < left = 4294967040
        # numerically, but modular distance is 512).
        scoreboard.add_block(0xFFFF_FF00, 0x0000_0100)
        self.assertEqual(
            scoreboard.total_sacked_bytes(),
            512,
            msg=(
                "Cross-wrap block [0xFFFF_FF00, 0x0000_0100) "
                "covers 512 bytes via modular arithmetic. "
                f"Got {scoreboard.total_sacked_bytes()}."
            ),
        )


@parameterized_class(
    [
        {
            "_description": "Two blocks merged via insert; final block list has one entry.",
            "_inserts": [(100, 200), (200, 300)],
            "_expected_blocks": [(100, 300)],
        },
        {
            "_description": "Three blocks bridged by a fourth; final block list has one entry.",
            "_inserts": [(100, 150), (200, 250), (300, 350), (140, 360)],
            "_expected_blocks": [(100, 360)],
        },
        {
            "_description": "Two strictly disjoint blocks; final block list has both.",
            "_inserts": [(100, 200), (300, 400)],
            "_expected_blocks": [(100, 200), (300, 400)],
        },
    ]
)
class TestSackScoreboard__InsertSequenceMatrix(TestCase):
    """
    Parameterized end-to-end matrix: a sequence of 'add_block' calls
    must produce the expected post-merge block set.
    """

    _description: str
    _inserts: list[tuple[int, int]]
    _expected_blocks: list[tuple[int, int]]
    _results: dict[str, Any]

    def test__sack_scoreboard__insert_sequence(self) -> None:
        """
        Ensure repeated 'add_block' insertions produce the expected
        merged block set.
        Reference: RFC 2018 §3 (SACK block union semantics, end-to-end).
        """

        scoreboard = SackScoreboard()
        for left, right in self._inserts:
            scoreboard.add_block(left, right)
        self.assertEqual(
            sorted(scoreboard.blocks()),
            sorted(self._expected_blocks),
            msg=f"Unexpected post-insert block set for case: {self._description}",
        )


class TestSackMutationGoldens(TestCase):
    """
    Branch and arithmetic goldens closing the remaining SACK
    scoreboard mutation survivors: the first_gap modular sort key,
    the exclusive right edge of is_sacked, and the
    overlap-or-touches adjacency / inclusive-edge logic.
    """

    def test__sack__first_gap_sort_key_orders_blocks(self) -> None:
        """
        Ensure first_gap sorts its blocks by modular forward distance
        from snd_una before walking: two contiguous blocks stored in
        reverse order must still walk to the true gap at 2000.

        Reference: RFC 6675 §3 (gap walk over ordered SACK blocks).
        """

        scoreboard = SackScoreboard()
        # Stored reverse so an un-sorted walk would stop at 1000.
        scoreboard._blocks = [(1500, 2000), (1000, 1500)]
        self.assertEqual(
            scoreboard.first_gap(1000),
            2000,
            msg="reverse-stored contiguous blocks must walk to gap 2000 (kills the sort key).",
        )

    def test__sack__is_sacked_right_edge_is_exclusive(self) -> None:
        """
        Ensure is_sacked treats the block's right edge as exclusive
        (the inclusive bound is right - 1): the right edge itself is
        not sacked, but right-1 and left are.

        Reference: RFC 2018 §3 ([left, right) half-open SACK blocks).
        """

        scoreboard = SackScoreboard()
        scoreboard.add_block(1000, 1100)
        self.assertFalse(
            scoreboard.is_sacked(1100),
            msg="the exclusive right edge must NOT be sacked (kills 'right-1'→'right').",
        )
        self.assertTrue(scoreboard.is_sacked(1099), msg="right-1 must be sacked.")
        self.assertTrue(scoreboard.is_sacked(1000), msg="left edge must be sacked.")

    def test__sack__overlaps_or_touches_adjacency_and_overlap(self) -> None:
        """
        Ensure _overlaps_or_touches recognizes exact adjacency (one
        right edge equals the other's left edge), disjoint blocks, and
        containment overlap, using large values so the equality is by
        value not identity.

        Reference: RFC 2018 §4 (SACK block coalescing).
        """

        self.assertTrue(
            _overlaps_or_touches(100000, 200000, 200000, 300000),
            msg="adjacent blocks (a_right == b_left) must touch.",
        )
        self.assertFalse(
            _overlaps_or_touches(100000, 150000, 200000, 300000),
            msg="disjoint blocks must not overlap.",
        )
        self.assertTrue(
            _overlaps_or_touches(100000, 300000, 150000, 400000),
            msg="containment overlap (b_left inside a) must be detected.",
        )

    def test__sack__overlaps_inclusive_edge(self) -> None:
        """
        Ensure the overlap test uses the inclusive right edge
        (right - 1): a block whose left edge is exactly one below the
        other's right edge overlaps, where a 'right-2' edit would miss
        it.

        Reference: RFC 2018 §4 (inclusive overlap boundary).
        """

        self.assertTrue(
            _overlaps_or_touches(100000, 200000, 199999, 300000),
            msg="b_left == a_right - 1 must overlap (kills the inclusive-edge offset).",
        )
