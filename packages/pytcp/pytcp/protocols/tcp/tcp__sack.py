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
This module contains the 'SackScoreboard' helper class tracking
non-contiguous SACK-acked seq ranges in 32-bit modular space, per
RFC 2018 §3 / RFC 6675 §3.

pytcp/protocols/tcp/tcp__sack.py

ver 3.0.8
"""

from net_proto.lib.int_checks import UINT_32__MAX, is_uint32
from pytcp.protocols.tcp.tcp__seq import Seq32, ge32, in_range32, le32, lt32, sub32


class SackScoreboard:
    """
    The TCP SACK scoreboard tracks the set of seq ranges the peer
    has SACK-acknowledged but not yet cumulatively acknowledged, per
    RFC 2018 §3 and RFC 6675 §3. Ranges are stored as half-open
    '[left, right)' intervals in 32-bit modular sequence space,
    merged on insert so the stored set is always disjoint and
    minimal.

    The scoreboard does not know 'SND.UNA' or 'SND.MAX' itself; the
    caller passes them in to operations that need that context
    ('prune_below', 'first_gap'). The invariant the caller is
    expected to uphold is that every block in the scoreboard lives
    in the forward half-window above 'SND.UNA' (i.e. SACK never
    covers cumulatively-ACKed bytes), so all comparisons reduce to
    the modular helpers in 'pytcp.protocols.tcp.tcp__seq' without sign
    ambiguity at the diametric midpoint.
    """

    _blocks: list[tuple[Seq32, Seq32]]

    def __init__(self) -> None:
        """
        Initialize an empty scoreboard.
        """

        self._blocks = []

    def clear(self) -> None:
        """
        Drop every SACK block, returning the scoreboard to its
        empty state. Called from the RTO retransmit path per
        RFC 2018 §5 (turn off SACKed bits + ignore prior SACK
        info on retransmit) so the post-RTO loss recovery does
        not skip seq ranges the receiver may have reneged.
        """

        self._blocks.clear()

    def add_block(self, left: Seq32, right: Seq32) -> None:
        """
        Add a '[left, right)' SACK block to the scoreboard, merging
        it with any existing block it overlaps or is adjacent to per
        RFC 2018's union semantics. Both edges are 32-bit unsigned
        seq numbers; 'lt32(left, right)' must hold (a SACK block is
        always non-empty and never spans more than half the seq
        space).
        """

        assert is_uint32(left), f"The 'left' argument must be a 32-bit unsigned integer. Got: {left!r}"
        assert is_uint32(right), f"The 'right' argument must be a 32-bit unsigned integer. Got: {right!r}"
        assert lt32(left, right), (
            "A SACK block must be non-empty and span less than half the seq space "
            f"('lt32(left, right)' must hold). Got: {left=}, {right=}"
        )

        # Iteratively absorb every existing block that overlaps or is
        # adjacent to the new range, growing the new range to the
        # union as we go. The remaining blocks - those strictly
        # disjoint from the new range - are kept as-is. This is the
        # full transitive merge: a single new block can coalesce a
        # whole chain of formerly-disjoint blocks if it bridges them.
        survivors: list[tuple[Seq32, Seq32]] = []
        for block_left, block_right in self._blocks:
            if _overlaps_or_touches(left, right, block_left, block_right):
                left, right = _merge(left, right, block_left, block_right)
            else:
                survivors.append((block_left, block_right))

        survivors.append((left, right))
        self._blocks = survivors

    def is_sacked(self, seq: Seq32) -> bool:
        """
        Return True iff 'seq' falls in any tracked block, i.e. the
        peer has SACK-acknowledged that byte.
        """

        assert is_uint32(seq), f"The 'seq' argument must be a 32-bit unsigned integer. Got: {seq!r}"

        for block_left, block_right in self._blocks:
            if in_range32(seq, block_left, sub32(block_right, 1)):
                return True
        return False

    def prune_below(self, snd_una: Seq32) -> None:
        """
        Drop blocks entirely below 'snd_una' (the cumulative ACK has
        absorbed them) and trim the left edge of any block that
        straddles 'snd_una'. Blocks entirely above 'snd_una' are
        kept as-is.
        """

        assert is_uint32(snd_una), f"The 'snd_una' argument must be a 32-bit unsigned integer. Got: {snd_una!r}"

        survivors: list[tuple[Seq32, Seq32]] = []
        for left, right in self._blocks:
            if le32(right, snd_una):
                continue
            if lt32(left, snd_una):
                left = snd_una
            survivors.append((left, right))
        self._blocks = survivors

    def blocks(self) -> list[tuple[Seq32, Seq32]]:
        """
        Return a snapshot of the tracked '[left, right)' blocks in
        insertion order. The caller may reorder for SACK option
        emission per RFC 2018 §4 (most-recent first).
        """

        return list(self._blocks)

    def total_sacked_bytes(self) -> int:
        """
        Return the total number of bytes covered by the
        scoreboard, summing modular block widths. Used by the
        RFC 6937 PRR delta-tracking hook in '_ingest_sack_info'
        to compute 'DeliveredData' from before/after totals
        across a SACK-block ingestion.

        The merge invariant guarantees no two tracked blocks
        overlap, so a plain modular sum of '(right - left)'
        widths is the exact byte coverage.
        """

        return sum((right - left) & UINT_32__MAX for left, right in self._blocks)

    def first_gap(self, snd_una: Seq32) -> Seq32 | None:
        """
        Return the lowest seq >= 'snd_una' that is NOT covered by
        any tracked block, walking through contiguous coverage that
        starts exactly at 'snd_una'. Returns None when the scoreboard
        cannot identify a finite gap (currently unreachable for any
        finite block set; the API reserves None for the saturation
        case the phase-5 NextSeg wrapper may use).
        """

        assert is_uint32(snd_una), f"The 'snd_una' argument must be a 32-bit unsigned integer. Got: {snd_una!r}"

        if not self._blocks:
            return snd_una

        # Sort blocks by forward distance from 'snd_una' so the walk
        # below visits them in the natural seq order. Blocks that
        # land below 'snd_una' (negative forward distance) sort to
        # the far end of the modular ring; the caller is expected to
        # have just pruned, so this only matters as a defensive sort.
        ordered = sorted(self._blocks, key=lambda b: (b[0] - snd_una) & UINT_32__MAX)

        cursor = snd_una
        for left, right in ordered:
            if left == cursor:
                cursor = right
                continue
            if lt32(left, cursor):
                # Block sits below 'cursor' (e.g. caller did not
                # prune); skip it - it cannot create a gap above.
                continue
            # 'left > cursor': there is a gap '[cursor, left)'.
            return cursor
        return cursor


def _overlaps_or_touches(a_left: Seq32, a_right: Seq32, b_left: Seq32, b_right: Seq32) -> bool:
    """
    Return True iff '[a_left, a_right)' and '[b_left, b_right)'
    overlap or are exactly adjacent (one's right edge equals the
    other's left edge), in 32-bit modular sequence space.
    """

    # Adjacent: one block ends exactly where the other starts.
    if a_right == b_left or b_right == a_left:
        return True
    # Overlap iff either left edge sits strictly inside the other
    # block. Both directions must be checked because either block
    # can contain the other in modular space.
    if in_range32(b_left, a_left, sub32(a_right, 1)):
        return True
    if in_range32(a_left, b_left, sub32(b_right, 1)):
        return True
    return False


def _merge(a_left: Seq32, a_right: Seq32, b_left: Seq32, b_right: Seq32) -> tuple[Seq32, Seq32]:
    """
    Return the modular union of '[a_left, a_right)' and
    '[b_left, b_right)' as a single '[left, right)' block. The
    caller must have established the two blocks overlap or touch.
    """

    new_left = a_left if le32(a_left, b_left) else b_left
    new_right = a_right if ge32(a_right, b_right) else b_right
    return new_left, new_right
