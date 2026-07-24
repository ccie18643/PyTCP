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
This module contains the RFC 5681 / RFC 6928 congestion-control
formulas as pure functions.

Three operations the caller invokes from
'_process_ack_packet', '_retransmit_packet_request',
'_retransmit_packet_timeout', and the FSM init points:

    cwnd_grow_per_ack(cwnd, ssthresh, bytes_acked, smss) -> int
        RFC 5681 §3.1: slow-start vs CA growth on cum-ACK.
        if cwnd < ssthresh:
            new_cwnd = cwnd + min(bytes_acked, smss)
        else:
            new_cwnd = cwnd + max(1, smss * smss // cwnd)

    compute_loss_event_ssthresh(flight_size, smss) -> int
        RFC 5681 §3.1 / §3.2 step 2: ssthresh halving on RTO
        and fast-retransmit entry.
        ssthresh = max(flight_size // 2, 2 * smss)

    compute_ecn_event_ssthresh(flight_size, smss) -> int
        RFC 8511 §3 ABE: less aggressive ssthresh reduction on
        ECN-class congestion events (RFC 3168 ECE / RFC 9768
        r.CE delta).
        ssthresh = max(flight_size * 17 // 20, 2 * smss)

    initial_window(smss) -> int
        RFC 6928 §2: post-handshake cwnd.
        IW = min(10 * smss, max(2 * smss, 14600))

The TcpSession integration consumes the helpers at the canonical
hook points; see 'docs/rfc/tcp/rfc5681__reno_cwnd/adherence.md'
for the per-clause spec audit.

pytcp/protocols/tcp/tcp__cwnd.py

ver 3.0.8
"""

# RFC 6928 §2 Initial Window: post-handshake congestion window. The
# multi-clause formula 'min(10*MSS, max(2*MSS, 14600))' caps IW at
# both ends:
#   - lower: at least 2*MSS (or 14600 bytes if MSS is small enough
#     that 2*MSS < 14600), so very-small-MSS connections are not
#     under-provisioned at start.
#   - upper: at most 10*MSS, so large-MSS jumbo-frame paths cannot
#     exceed 10 segments at start.
# 14600 was chosen by RFC 6928 as 10 * 1460 (the canonical
# Ethernet-MTU-derived MSS).
INITIAL_WINDOW_FACTOR = 10
INITIAL_WINDOW_BYTES = 14600


def cwnd_grow_per_ack(cwnd: int, ssthresh: int, bytes_acked: int, smss: int) -> int:
    """
    Compute the post-growth cwnd value for a cumulative ACK that
    advances SND.UNA per RFC 5681 §3.1.

    Algorithm:
        if cwnd < ssthresh:                      # slow-start
            new_cwnd = cwnd + min(bytes_acked, smss)
        else:                                    # congestion-avoidance
            new_cwnd = cwnd + max(1, smss * smss // cwnd)

    The slow-start branch caps the per-ACK growth at SMSS so a
    large 'bytes_acked' (e.g. on a delayed-ACK boundary) cannot
    inflate cwnd by more than one SMSS per ACK. The CA branch
    approximates the canonical 'cwnd += SMSS / cwnd_in_segments'
    formula in integer arithmetic, with 'max(1, ...)' protecting
    against the floor-div underflow when cwnd >> smss.

    Parameters:
        cwnd:        current cwnd value (bytes; pre-growth)
        ssthresh:    current slow-start threshold (bytes)
        bytes_acked: amount of new data acknowledged by the
                     cumulative ACK (bytes)
        smss:        sender's MSS (SMSS) - the slow-start
                     per-ACK growth cap and the CA numerator

    Returns: post-growth cwnd value (bytes).
    """

    assert cwnd > 0, f"'cwnd' must be positive; got {cwnd!r}"
    assert ssthresh > 0, f"'ssthresh' must be positive; got {ssthresh!r}"
    assert bytes_acked >= 0, f"'bytes_acked' must be non-negative; got {bytes_acked!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"

    if cwnd < ssthresh:
        return cwnd + min(bytes_acked, smss)
    return cwnd + max(1, smss * smss // cwnd)


def compute_loss_event_ssthresh(flight_size: int, smss: int) -> int:
    """
    Compute the new ssthresh value for a loss event (RTO or fast
    retransmit) per RFC 5681 §3.1 / §3.2 step 2.

    Algorithm:
        ssthresh = max(flight_size // 2, 2 * smss)

    The 'max(..., 2*SMSS)' floor prevents a small in-flight burst
    at loss-detection time from setting ssthresh below the
    canonical minimum and causing the post-recovery slow-start to
    exit immediately into congestion-avoidance.

    Parameters:
        flight_size: bytes in flight at the moment of loss
                     detection (bytes)
        smss:        sender's MSS (SMSS) - both the floor multiplier
                     and the canonical RFC 5681 minimum

    Returns: new ssthresh value (bytes).
    """

    assert flight_size >= 0, f"'flight_size' must be non-negative; got {flight_size!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"

    return max(flight_size // 2, 2 * smss)


def compute_ecn_event_ssthresh(flight_size: int, smss: int) -> int:
    """
    Compute the new ssthresh value for an ECN-class congestion
    event per RFC 8511 §3 (Alternative Backoff with ECN).

    Algorithm:
        ssthresh = max(flight_size * 17 // 20, 2 * smss)

    The 17/20 integer ratio is the canonical RFC 8511 0.85
    multiplier - less aggressive than the 0.5 used for loss
    events. ECN provides early-warning congestion notification
    before drops occur, so ABE preserves more in-flight data
    while still backing off when the network signals.

    The 'max(..., 2*SMSS)' floor matches the loss-event helper's
    behaviour and prevents a small in-flight burst at event time
    from setting ssthresh below the canonical RFC 5681 minimum.

    Parameters:
        flight_size: bytes in flight at the moment of the ECN
                     event
        smss:        sender's MSS

    Returns: new ssthresh value (bytes).
    """

    assert flight_size >= 0, f"'flight_size' must be non-negative; got {flight_size!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"

    return max(flight_size * 17 // 20, 2 * smss)


def initial_window(smss: int) -> int:
    """
    Compute the post-handshake Initial Window per RFC 6928 §2.

    Algorithm:
        IW = min(INITIAL_WINDOW_FACTOR * smss,
                 max(2 * smss, INITIAL_WINDOW_BYTES))

    The constants are 10 (segment-count cap) and 14600 (10 * 1460,
    the canonical 1500-MTU-derived MSS). For canonical 1460-byte
    MSS the formula yields IW = 14600 = 10*MSS.

    Parameters:
        smss: sender's MSS (SMSS) at handshake completion (bytes)

    Returns: post-handshake cwnd value (bytes).
    """

    assert smss > 0, f"'smss' must be positive; got {smss!r}"

    return min(INITIAL_WINDOW_FACTOR * smss, max(2 * smss, INITIAL_WINDOW_BYTES))
