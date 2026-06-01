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
This module contains the RFC 6675 Conservative Loss Recovery
predicates (IsLost, NextSeg, Pipe) used by 'TcpSession' to drive
SACK-aware fast retransmit decisions on top of the
'SackScoreboard' helper.

pytcp/protocols/tcp/tcp__loss_recovery.py

ver 3.0.8
"""

from net_proto.lib.int_checks import is_uint32
from pytcp.protocols.tcp.tcp__sack import SackScoreboard
from pytcp.protocols.tcp.tcp__seq import Seq32, le32, lt32, sub32

# RFC 6675 §3 default DupThresh (matches RFC 5681's count-based
# fast-retransmit threshold).
TCP__DUP_THRESH: int = 3


def is_lost(
    seq: Seq32,
    /,
    *,
    scoreboard: SackScoreboard,
    snd_una: Seq32,
    mss: int,
    dup_thresh: int = TCP__DUP_THRESH,
) -> bool:
    """
    RFC 6675 §3 IsLost(SeqNum) predicate. Return True iff the
    receiver-known SACK information about ranges above 'seq'
    suggests 'seq' was lost in transit. Two independent triggers,
    either of which is sufficient:

      1. At least 'dup_thresh' (default 3) discontiguous SACK
         blocks lie at or above 'seq'.
      2. More than '(dup_thresh - 1) * mss' bytes have been
         SACKed at or above 'seq'.

    The first rule fires when the receiver reports many small
    out-of-order arrivals; the second when it reports few but
    large ones. Both presume 'seq' itself remains unsacked.
    """

    assert is_uint32(seq), f"The 'seq' argument must be a 32-bit unsigned integer. Got: {seq!r}"
    assert is_uint32(snd_una), f"The 'snd_una' argument must be a 32-bit unsigned integer. Got: {snd_una!r}"
    assert mss > 0, f"The 'mss' argument must be a positive integer. Got: {mss!r}"
    assert dup_thresh > 0, f"The 'dup_thresh' argument must be a positive integer. Got: {dup_thresh!r}"

    blocks_above = 0
    bytes_above = 0
    for left, right in scoreboard.blocks():
        # A block "above seq" is one whose left edge lies at or
        # above seq in modular order. Blocks straddling seq (left
        # below, right above) are degenerate in the IsLost model;
        # since the scoreboard's invariants keep blocks above
        # SND.UNA and the caller passes 'seq >= SND.UNA',
        # straddles don't arise in practice. Filter defensively
        # by 'le32(seq, left)' anyway.
        if le32(seq, left):
            blocks_above += 1
            bytes_above += sub32(right, left)

    if blocks_above >= dup_thresh:
        return True
    if bytes_above > (dup_thresh - 1) * mss:
        return True
    return False


def next_seg(
    *,
    scoreboard: SackScoreboard,
    snd_una: Seq32,
    snd_max: Seq32,
    mss: int,
    dup_thresh: int = TCP__DUP_THRESH,
) -> Seq32 | None:
    """
    RFC 6675 §3 NextSeg() procedure (rule 1). Return the smallest
    seq in '[SND.UNA, SND.MAX)' that is not yet SACKed AND is
    'lost' per 'is_lost()', or None when no such seq exists. The
    return value drives the next retransmission: when not None,
    the caller MUST retransmit one MSS-sized segment starting at
    that seq.
    """

    assert is_uint32(snd_una), f"The 'snd_una' argument must be a 32-bit unsigned integer. Got: {snd_una!r}"
    assert is_uint32(snd_max), f"The 'snd_max' argument must be a 32-bit unsigned integer. Got: {snd_max!r}"

    gap = scoreboard.first_gap(snd_una)
    if gap is None or not lt32(gap, snd_max):
        return None
    if is_lost(gap, scoreboard=scoreboard, snd_una=snd_una, mss=mss, dup_thresh=dup_thresh):
        return gap
    return None


def pipe(
    *,
    scoreboard: SackScoreboard,
    snd_una: Seq32,
    snd_max: Seq32,
) -> int:
    """
    RFC 6675 §4 Pipe() estimate: bytes the sender believes are
    currently in flight, defined as everything between SND.UNA
    and SND.MAX that has NOT been SACK-acknowledged. The return
    value bounds the sender's effective window during recovery
    so dup-ACK-driven cwnd inflation does not over-commit.

    Note: the simplified Pipe used here treats every unsacked
    byte in the in-flight range as still in flight (no
    'has-been-retransmitted' bookkeeping). RFC 6675 §4 splits
    out retransmitted bytes; PyTCP defers that subtlety because
    we do not yet track per-seq retransmit state here.
    """

    assert is_uint32(snd_una), f"The 'snd_una' argument must be a 32-bit unsigned integer. Got: {snd_una!r}"
    assert is_uint32(snd_max), f"The 'snd_max' argument must be a 32-bit unsigned integer. Got: {snd_max!r}"

    in_flight = sub32(snd_max, snd_una)
    sacked = 0
    for left, right in scoreboard.blocks():
        # Skip blocks whose edges fall outside the in-flight
        # window; the ingestion gate in 'TcpSession' already
        # filters these but defensive callers may not.
        if not (le32(snd_una, left) and le32(right, snd_max)):
            continue
        sacked += sub32(right, left)

    return in_flight - sacked
