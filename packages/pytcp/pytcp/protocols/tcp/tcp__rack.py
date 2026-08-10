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
This module contains the RFC 8985 RACK-TLP per-segment state
primitives.

RFC 8985 §5.2 specifies a per-segment 'Segment' tuple that the
sender maintains for every outbound segment that consumes
sequence space. RACK consumes the tuple to drive time-based loss
detection (§6.2 step 5) and the reordering window adaptation
(§6.2 steps 3-4); TLP consumes it to identify the highest-seq
in-flight segment for retransmit-style probes (§7.3).

Reference RFCs (see also 'docs/rfc/tcp/rfc8985__rack_tlp/adherence.md'
for the per-clause spec audit):
    RFC 8985 §5.2  Per-Segment Variables
    RFC 8985 §6.1  Transmitting a data segment
    RFC 8985 §6.2  Upon receiving an ACK
    RFC 8985 §7.3  Sending a loss probe upon PTO expiration

pytcp/protocols/tcp/tcp__rack.py

ver 3.0.9
"""

from dataclasses import dataclass

# RFC 8985 §5.2 invalid-timestamp marker. A segment's 'xmit_ts'
# field is set to 'INFINITE_TS' when the segment is no longer
# considered in flight (e.g. after RACK has marked it lost via
# 'Segment.lost = True'). Subsequent ACK-processing iterations
# use the marker to skip lost segments during the §6.2 step 2
# RACK_sent_after lexicographic comparison: a segment whose
# xmit_ts is INFINITE_TS cannot be 'sent after' any real-valued
# xmit_ts because INFINITE_TS lies outside the live transmission
# window. The canonical value (0xFFFFFFFF, the maximum 32-bit
# unsigned) doubles as a sentinel that fits the 32-bit timestamp
# field width used throughout the RFC pseudocode.
INFINITE_TS: int = 0xFFFF_FFFF


@dataclass(frozen=True, slots=True)
class RackSegment:
    """
    The RFC 8985 §5.2 per-segment 'Segment' tuple.

    Stored in 'TcpSession._rack_segments' keyed by the segment's
    starting sequence number. Constructed once at transmission
    time (or replaced wholesale on retransmit, since the
    dataclass is frozen) and removed on cumulative-ACK pruning.

    Fields:
        end_seq        seq + payload_length (RFC 8985 §5.2:
                       'Segment.end_seq')
        xmit_ts        most recent transmission timestamp in
                       milliseconds; 'INFINITE_TS' iff
                       'lost == True' (RFC 8985 §5.2:
                       'Segment.xmit_ts')
        retransmitted  True iff the segment has ever been
                       retransmitted (RFC 8985 §5.2:
                       'Segment.retransmitted'). Used by RACK
                       §6.2 step 2 to skip spurious retransmit
                       samples when the TSecr cannot
                       disambiguate.
        lost           True iff RACK has declared the segment
                       lost (RFC 8985 §5.2: 'Segment.lost').
                       Used by §6.2 step 5 to drive the
                       retransmit walk and by §7.3 to skip
                       lost-but-not-yet-retransmitted bytes.
    """

    end_seq: int
    xmit_ts: int
    retransmitted: bool
    lost: bool


def rack_sent_after(t1_xmit_ts: int, t1_end_seq: int, t2_xmit_ts: int, t2_end_seq: int) -> bool:
    """
    Return True if segment 1 was 'sent after' segment 2 in the
    RFC 8985 §6.2 step 2 lexicographic sense:

        (t1.xmit_ts, t1.end_seq) > (t2.xmit_ts, t2.end_seq)

    Ties on 'xmit_ts' are broken by the segment's 'end_seq' so
    two segments transmitted in the same millisecond keep a
    stable relative order.

    The 'end_seq' tie-breaker uses modular comparison via the
    ordinary signed delta: when both segments belong to the
    same flight (i.e. their end_seqs are within UINT_31 of each
    other in modular space) the comparison is unambiguous. The
    pseudocode in RFC 8985 uses '>' on the seq field, which
    PyTCP implements via the modular helpers in
    'pytcp.protocols.tcp.tcp__seq'.
    """

    if t1_xmit_ts != t2_xmit_ts:
        return t1_xmit_ts > t2_xmit_ts
    # Modular '>' on end_seq via the standard PyTCP helper.
    from pytcp.protocols.tcp.tcp__seq import gt32

    return gt32(t1_end_seq, t2_end_seq)


def rack_update(
    *,
    newly_acked_segments: list[RackSegment],
    now_ms: int,
    ts_recent_echo_ms: int | None,
    prior_min_rtt_ms: int,
    prior_rack_rtt_ms: int,
    prior_rack_xmit_ts: int,
    prior_rack_end_seq: int,
) -> tuple[int, int, int, int]:
    """
    Apply the RFC 8985 §6.2 step 1-2 update on the per-connection
    RACK scalars given a list of segments freshly acknowledged
    by an inbound ACK.

    Pseudocode (RFC 8985 §6.2 step 2):

        For each newly-acked segment in ascending xmit_ts order:
            rtt = now_ms - segment.xmit_ts
            If segment.retransmitted:
                If TSecr < segment.xmit_ts: continue
                If rtt < min_RTT: continue
            min_RTT = min(min_RTT, rtt)   # §B.1 algorithm
            RACK.rtt = rtt
            If RACK_sent_after(segment.xmit_ts, segment.end_seq,
                               RACK.xmit_ts, RACK.end_seq):
                RACK.xmit_ts = segment.xmit_ts
                RACK.end_seq = segment.end_seq

    The two retransmit-skip conditions guard against using a
    spurious retransmit's RTT to update RACK.rtt: 'TSecr <
    segment.xmit_ts' indicates the ACK is for an earlier
    transmission of this segment (RFC 7323 §4 disambiguation),
    while 'rtt < min_RTT' is a heuristic for the same condition
    when timestamps are unavailable.

    Parameters:
        newly_acked_segments: segments whose 'end_seq' is
                              newly covered by SND.UNA on this
                              ACK; the caller computes this
                              set before the cum-ACK pruning
                              fires.
        now_ms:               virtual clock at the moment the
                              ACK was received.
        ts_recent_echo_ms:    peer's TSecr value if RFC 7323
                              timestamps are negotiated; None
                              otherwise.
        prior_min_rtt_ms:     RACK.min_RTT before this ACK
                              (0 means uninitialized).
        prior_rack_rtt_ms:    RACK.rtt before this ACK.
        prior_rack_xmit_ts:   RACK.xmit_ts before this ACK.
        prior_rack_end_seq:   RACK.end_seq before this ACK.

    Returns: (new_min_rtt_ms, new_rack_rtt_ms,
              new_rack_xmit_ts, new_rack_end_seq).
    """

    min_rtt_ms = prior_min_rtt_ms
    rack_rtt_ms = prior_rack_rtt_ms
    rack_xmit_ts = prior_rack_xmit_ts
    rack_end_seq = prior_rack_end_seq

    # Iterate in ascending xmit_ts order per the RFC pseudocode.
    # Sort by (xmit_ts, end_seq) so segments transmitted in the
    # same millisecond remain in seq order.
    for seg in sorted(newly_acked_segments, key=lambda s: (s.xmit_ts, s.end_seq)):
        # RFC 8985 §5.2 lost segments carry xmit_ts = INFINITE_TS;
        # their RTT computation would be nonsensical (and
        # negative) so skip them entirely. The cum-ACK pruning
        # in the caller will drop the dict entry afterwards.
        if seg.xmit_ts == INFINITE_TS:
            continue
        rtt_ms = now_ms - seg.xmit_ts

        if seg.retransmitted:
            # Skip if peer's TSecr identifies an earlier
            # transmission of this segment (RFC 7323 §4
            # disambiguation, RFC 8985 §6.2 step 2 condition 1).
            if ts_recent_echo_ms is not None and ts_recent_echo_ms < seg.xmit_ts:
                continue
            # Skip if rtt is implausibly small compared to the
            # minimum observed RTT - heuristic guard against
            # spurious-retransmit samples in non-TSopt
            # connections (RFC 8985 §6.2 step 2 condition 2).
            if min_rtt_ms > 0 and rtt_ms < min_rtt_ms:
                continue

        # RFC 8985 §B.1 min_RTT update: track the minimum across
        # all accepted samples. 'min_rtt_ms == 0' is the
        # uninitialized sentinel; on the first sample seed it
        # rather than taking the minimum with zero.
        if min_rtt_ms == 0 or rtt_ms < min_rtt_ms:
            min_rtt_ms = rtt_ms
        rack_rtt_ms = rtt_ms

        if rack_sent_after(seg.xmit_ts, seg.end_seq, rack_xmit_ts, rack_end_seq):
            rack_xmit_ts = seg.xmit_ts
            rack_end_seq = seg.end_seq

    return min_rtt_ms, rack_rtt_ms, rack_xmit_ts, rack_end_seq


def rack_detect_loss(
    *,
    segments: dict[int, RackSegment],
    rack_xmit_ts: int,
    rack_end_seq: int,
    reo_wnd_ms: int,
    now_ms: int,
) -> tuple[dict[int, RackSegment], int]:
    """
    Apply the RFC 8985 §6.2 step 5 time-based loss detection.
    Iterates 'segments' and marks a segment lost iff:

      1. It is not already lost ('seg.lost is False'), AND
      2. RACK was 'sent after' it lexicographically
         (rack_xmit_ts, rack_end_seq) > (seg.xmit_ts, seg.end_seq), AND
      3. 'now_ms - seg.xmit_ts > reo_wnd_ms' (the reordering
         tolerance has elapsed since the segment was sent).

    A segment in flight that satisfies (1) + (2) but not (3) is
    a 'reorder-window pending' candidate; the helper computes
    the earliest 'seg.xmit_ts + reo_wnd_ms - now_ms' across
    those candidates so the caller can arm a reordering timer.

    Marking a segment lost replaces it in the returned dict
    with a fresh 'RackSegment' having 'lost=True' and
    'xmit_ts=INFINITE_TS' per RFC 8985 §5.2: the lost segment
    is no longer in flight, and subsequent invocations of this
    function will skip it via condition (1).

    Parameters:
        segments:        the per-segment dict (typically
                         'TcpSession._rack_segments').
        rack_xmit_ts:    'RACK.xmit_ts' from the most recent
                         rack_update.
        rack_end_seq:    'RACK.end_seq' from the most recent
                         rack_update.
        reo_wnd_ms:      reordering window in milliseconds.
                         Phase 3 uses 0 (no reordering
                         tolerance); Phase 4 computes it via
                         rack_compute_reo_wnd.
        now_ms:          virtual clock at the moment of the
                         loss-detection check.

    Returns:
        (new_segments_dict, timeout_ms)
        'timeout_ms == 0' means no reordering-window timer is
        needed (no candidate satisfied (1)+(2) but not (3)).
        'timeout_ms > 0' is the earliest 'seg.xmit_ts +
        reo_wnd_ms - now_ms' across the pending candidates;
        the caller arms a single timer with that timeout.
    """

    new_segments: dict[int, RackSegment] = {}
    timeout_ms = 0

    for seq, seg in segments.items():
        if seg.lost:
            new_segments[seq] = seg
            continue
        if not rack_sent_after(rack_xmit_ts, rack_end_seq, seg.xmit_ts, seg.end_seq):
            new_segments[seq] = seg
            continue
        # RACK is 'sent after' this segment - it is a loss
        # candidate. Apply the reordering-window check.
        if now_ms - seg.xmit_ts > reo_wnd_ms:
            new_segments[seq] = RackSegment(
                end_seq=seg.end_seq,
                xmit_ts=INFINITE_TS,
                retransmitted=seg.retransmitted,
                lost=True,
            )
        else:
            seg_timeout = seg.xmit_ts + reo_wnd_ms - now_ms
            if timeout_ms == 0 or seg_timeout < timeout_ms:
                timeout_ms = seg_timeout
            new_segments[seq] = seg

    return new_segments, timeout_ms


def rack_compute_reo_wnd(
    *,
    reordering_seen: bool,
    reo_wnd_mult: int,
    min_rtt_ms: int,
) -> int:
    """
    Compute the current reordering window per RFC 8985 §6.2
    step 4.

    Algorithm (simplified):
        If RACK.reordering_seen is FALSE:
            return 0     # no reordering observed; use the
                         # dup-ACK trigger via reo_wnd=0
        Else:
            return min_RTT * reo_wnd_mult / 4

    The 'reo_wnd_mult' factor is increased by the caller when
    DSACK indicates a spurious retransmit (the peer received
    something we thought we lost), and decayed back to 1 after
    16 consecutive recovery-exits without DSACK (the
    'reo_wnd_persist' counter on TcpSession). Both adjustments
    are session-level state mutations, not the helper's job.

    The 'min_RTT / 4' base reflects RFC 8985's guidance that
    one quarter-RTT of network reordering is a reasonable
    tolerance before declaring a loss; a 'reo_wnd_mult' of 2
    doubles the tolerance to half-RTT, etc.

    Parameters:
        reordering_seen: True iff at least one inbound ACK has
                         delivered a segment whose end_seq is
                         strictly below 'RACK.fack'
                         (out-of-order delivery observed).
        reo_wnd_mult:    multiplier on the 'min_RTT / 4' base.
                         Starts at 1; increments on DSACK
                         rounds; resets to 1 after 16
                         recoveries without DSACK.
        min_rtt_ms:      RACK.min_RTT, the minimum observed
                         RTT (ms). 0 means no observation
                         yet, so the function returns 0
                         regardless of 'reordering_seen'.

    Returns: reordering window in milliseconds.
    """

    assert reo_wnd_mult >= 1, f"'reo_wnd_mult' must be >= 1; got {reo_wnd_mult!r}"
    assert min_rtt_ms >= 0, f"'min_rtt_ms' must be >= 0; got {min_rtt_ms!r}"

    if not reordering_seen:
        return 0
    if min_rtt_ms == 0:
        return 0
    return min_rtt_ms * reo_wnd_mult // 4


def tlp_calc_pto(
    *,
    srtt_ms: int | None,
    flight_size: int,
    smss: int,
    max_ack_delay_ms: int,
    rto_expiration_ms: int | None,
    now_ms: int,
) -> int:
    """
    Compute the Tail Loss Probe Timeout per RFC 8985 §7.2.

    Pseudocode:
        If SRTT is available:
            PTO = 2 * SRTT
            If FlightSize == 1 segment:
                PTO += max_ack_delay
        Else:
            PTO = 1000 ms     # initial RTO
        If now + PTO > RTO_expiration:
            PTO = RTO_expiration - now    # do not outlast RTO

    The 'max_ack_delay' inflation for the 1-segment FlightSize
    case absorbs the receiver's RFC 1122 §4.2.3.2 delayed-ACK
    timer: if a single segment is in flight and the receiver
    holds the ACK for up to 'max_ack_delay' ms, the sender
    must give peer a chance to ACK before assuming a tail
    loss. For 2+ segment FlightSize the receiver per RFC 5681
    §4.2 sends an immediate ACK-every-other so the
    'max_ack_delay' inflation is not needed.

    The 'don't outlast RTO' clause ensures the TLP probe
    fires BEFORE the RTO timer; otherwise an RTO would
    preempt TLP and the probe would never go out.

    Parameters:
        srtt_ms:           smoothed RTT estimate. None means
                           no RTT sample yet (use the 1000 ms
                           initial RTO as PTO).
        flight_size:       bytes currently in flight. Used
                           only to gate the +max_ack_delay
                           inflation (1 segment vs more).
        smss:              sender's MSS. Used to test the
                           '== 1 segment' condition.
        max_ack_delay_ms:  receiver's delayed-ACK upper
                           bound. Linux default 25 ms; PyTCP
                           uses the same default.
        rto_expiration_ms: time of the next RTO timer expiry
                           in absolute virtual-clock ms.
                           None means RTO is not currently
                           armed (e.g. all data acked, no
                           RTO running).
        now_ms:            virtual clock at the moment of the
                           PTO computation.

    Returns: PTO in milliseconds.
    """

    assert flight_size >= 0, f"'flight_size' must be >= 0; got {flight_size!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"
    assert max_ack_delay_ms >= 0, f"'max_ack_delay_ms' must be >= 0; got {max_ack_delay_ms!r}"

    if srtt_ms is not None and srtt_ms > 0:
        pto = 2 * srtt_ms
        if flight_size <= smss:
            pto += max_ack_delay_ms
    else:
        pto = 1000

    if rto_expiration_ms is not None:
        rto_remaining = rto_expiration_ms - now_ms
        # 'pto < rto_remaining' (strict) so TLP fires at least
        # one millisecond BEFORE RTO when both would otherwise
        # land on the same tick. The RFC's 'do not outlast'
        # clause permits equality, but PyTCP's FSM-tick order
        # runs '_retransmit_packet_timeout' before
        # '_tlp_pto_tick'; an equal PTO would let RTO preempt.
        if rto_remaining > 0 and pto >= rto_remaining:
            pto = rto_remaining - 1

    return pto


def tlp_process_ack(
    *,
    tlp_end_seq: int | None,
    tlp_is_retrans: bool,
    ack_seq: int,
    has_dsack_for_probe: bool,
    has_sack_blocks: bool,
) -> tuple[int | None, bool]:
    """
    Apply RFC 8985 §7.4 Tail Loss Probe loss-detection logic
    on an inbound ACK. Returns:

        (new_tlp_end_seq, should_invoke_cc_response)

    The helper clears 'tlp_end_seq' when the probe outcome is
    determined; only Case 3 (probe-repaired-single-loss)
    additionally signals the caller to invoke the §7.4.2
    congestion control response (cwnd halving).

    Algorithm (§7.4.2 pseudocode):

        If tlp_end_seq is None:
            return (None, False)         # no probe outstanding
        If NOT tlp_is_retrans AND ack >= tlp_end_seq:
            return (None, False)         # new-data probe delivered
        Elif has_dsack_for_probe:
            return (None, False)         # spurious retransmit (Case 1)
        Elif ack > tlp_end_seq (modular):
            return (None, True)          # single-loss repaired (Case 3)
        Elif ack == tlp_end_seq AND NOT has_sack_blocks:
            return (None, False)         # bare dup-ACK (Case 2)
        Otherwise: leave tlp_end_seq alone (probe outcome
        not yet determined; subsequent ACKs clarify).

    Parameters:
        tlp_end_seq:         current probe's end_seq marker;
                             None if no probe is outstanding.
        tlp_is_retrans:      True iff the probe was a
                             retransmit (vs new data).
        ack_seq:             peer's TCP ACK field on this
                             segment.
        has_dsack_for_probe: True iff peer's SACK option
                             carried a DSACK block matching
                             the probe.
        has_sack_blocks:     True iff peer's SACK option
                             carried any non-DSACK blocks.

    Returns: (new_tlp_end_seq, should_invoke_cc_response).
    """

    from pytcp.protocols.tcp.tcp__seq import le32, lt32

    if tlp_end_seq is None:
        return None, False

    # New-data probe delivered: ack covers the probe's end_seq.
    if not tlp_is_retrans and le32(tlp_end_seq, ack_seq):
        return None, False
    # Case 1: DSACK indicates the probe's bytes were a
    # spurious retransmit. The original was received earlier;
    # the connection is fine.
    if has_dsack_for_probe:
        return None, False
    # Case 3: ACK advances strictly past the probe's end_seq.
    # The probe repaired a single tail loss; invoke CC.
    if lt32(tlp_end_seq, ack_seq):
        return None, True
    # Case 2: bare duplicate ACK at probe's end_seq with no
    # SACK blocks. Probe of retransmit was useless; the
    # original had already been received.
    if ack_seq == tlp_end_seq and not has_sack_blocks:
        return None, False
    # Outcome not yet determined; preserve state.
    return tlp_end_seq, False
