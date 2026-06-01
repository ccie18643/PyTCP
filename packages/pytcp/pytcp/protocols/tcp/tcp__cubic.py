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
This module contains the RFC 9438 CUBIC congestion-control
formulas as pure functions.

Five operations the caller invokes from
'_process_ack_packet' (CA growth + Reno-friendly W_est) and
'_retransmit_packet_request' / '_retransmit_packet_timeout'
(loss-event ssthresh + W_max with optional fast convergence):

    cubic_compute_K(w_max, cwnd_epoch, smss) -> int
        RFC 9438 §4.2 figure 2: K = cubicroot(
            (W_max - cwnd_epoch) / C
        ) returned in milliseconds.

    cubic_w(t_ms, w_max, K_ms, smss) -> int
        RFC 9438 §4.2 figure 1: W_cubic(t) =
            C * (t - K)^3 + W_max
        with t and K in ms; W_max in bytes; result in bytes.

    cubic_grow_per_ack(*, cwnd, ssthresh, w_max, K_ms,
                        epoch_start_ms, now_ms, bytes_acked,
                        smss) -> int
        RFC 9438 §4.2 / §4.4 / §4.5 cwnd growth on cum-ACK in
        congestion avoidance. Slow-start branch yields the
        unchanged RFC 5681 §3.1 path. Combines cubic and Reno-
        friendly responses are NOT mixed here; the Reno-
        friendly comparison is the caller's responsibility
        via 'cubic_w_est'.

    cubic_loss_event_ssthresh(*, cwnd, smss, fast_conv_active,
                               prior_w_max) -> tuple[int, int]
        RFC 9438 §4.6 + §4.7 fast convergence: returns the
        new (ssthresh, W_max) pair for a loss event.

    cubic_w_est(*, w_est_prev, cwnd, smss, bytes_acked) -> int
        RFC 9438 §4.3 figure 4 Reno-friendly tracker:
            W_est = W_est + alpha_cubic * segments_acked / cwnd

The TcpSession integration consumes the helpers at the canonical
hook points; see 'docs/rfc/tcp/rfc9438__cubic/adherence.md' for
the per-clause spec audit.

pytcp/protocols/tcp/tcp__cubic.py

ver 3.0.8
"""

# RFC 9438 §4.1.1 constants. Encoded as integer numerator /
# denominator pairs so the cubic math stays float-free in hot
# paths (Python's 'int' is arbitrary precision; cubic_root is
# the one place we accept a float-cast rounding error).

# C = 0.4 segments / second^3 (the cubic scaling factor that
# determines how aggressively CUBIC probes new bandwidth).
# Encoded as 2/5.
C_NUM = 2
C_DEN = 5

# beta_cubic = 0.7 (the RFC 9438 §4.6 SHOULD-be-set
# multiplicative decrease factor on a loss event). Encoded as
# 7/10.
BETA_CUBIC_NUM = 7
BETA_CUBIC_DEN = 10

# alpha_cubic = 3 * (1 - beta_cubic) / (1 + beta_cubic) =
# 3 * 0.3 / 1.7 ≈ 0.529 (the RFC 9438 §4.3 Reno-friendly
# additive-increase factor). Exact rational form: 9/17.
ALPHA_CUBIC_NUM = 9
ALPHA_CUBIC_DEN = 17

# Fast-convergence reduction factor: (1 + beta_cubic) / 2 =
# 17/20 = 0.85. Applied to cwnd to compute the further-reduced
# W_max when cwnd < prior W_max at loss-event time
# (RFC 9438 §4.7).
FAST_CONV_NUM = 17
FAST_CONV_DEN = 20


def cubic_compute_K(w_max: int, cwnd_epoch: int, smss: int) -> int:
    """
    Compute K (the inflection-point time of the cubic curve)
    per RFC 9438 §4.2 figure 2:

        K = cubicroot((W_max - cwnd_epoch) / C)

    in seconds where W_max and cwnd_epoch are in segments.

    This implementation works in bytes and returns K in ms.
    From figure 2:

        K_seconds = cubicroot((W_max_seg - cwnd_epoch_seg) / C)
        K_ms = K_seconds * 1000

    Substituting W_max_seg = W_max_b / smss and using
    C = C_NUM / C_DEN:

        K_ms = (((W_max_b - cwnd_epoch_b) * C_DEN
                 * 1_000_000_000)
                / (smss * C_NUM)) ** (1/3)

    where the 1_000_000_000 factor is 10^9 = (10^3)^3, lifting
    the ms-cube into the cubic-root argument.

    When cwnd_epoch >= W_max (no decrease event preceded this
    epoch, or cwnd has already grown past W_max) K = 0.

    Parameters:
        w_max:       prior W_max value (bytes)
        cwnd_epoch:  cwnd at epoch start (bytes)
        smss:        sender's MSS (bytes)

    Returns: K in milliseconds.
    """

    assert w_max >= 0, f"'w_max' must be non-negative; got {w_max!r}"
    assert cwnd_epoch >= 0, f"'cwnd_epoch' must be non-negative; got {cwnd_epoch!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"

    if w_max <= cwnd_epoch:
        return 0

    diff_bytes = w_max - cwnd_epoch
    arg = diff_bytes * 1_000_000_000 * C_DEN // (smss * C_NUM)
    return int(round(arg ** (1.0 / 3.0)))


def cubic_w(t_ms: int, w_max: int, K_ms: int, smss: int) -> int:
    """
    Evaluate W_cubic(t) per RFC 9438 §4.2 figure 1:

        W(t) = C * (t - K)^3 + W_max

    where t and K are in ms (the project's wall-clock unit)
    and W_max is in bytes.

    In integer arithmetic with C = C_NUM / C_DEN and the time
    cubed in ms scaled back to seconds via 10^9:

        delta_seg = C * (t - K)^3 / 10^9
        delta_b   = delta_seg * smss
                  = C_NUM * (t_ms - K_ms)^3 * smss
                            / (C_DEN * 10^9)

    The diff (t_ms - K_ms) may be negative; Python's signed-
    int cube handles it correctly. Result is clamped at 0
    bytes (W_cubic should never return a negative window).

    Parameters:
        t_ms:  elapsed ms since epoch start
        w_max: W_max anchor (bytes)
        K_ms:  curve inflection time (ms)
        smss:  sender's MSS (bytes)

    Returns: W_cubic(t) in bytes.
    """

    assert w_max >= 0, f"'w_max' must be non-negative; got {w_max!r}"
    assert K_ms >= 0, f"'K_ms' must be non-negative; got {K_ms!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"

    diff = t_ms - K_ms
    cube = diff * diff * diff
    delta_bytes = C_NUM * cube * smss // (C_DEN * 1_000_000_000)
    return max(0, w_max + delta_bytes)


def cubic_target(cwnd: int, w_max: int, K_ms: int, t_ms: int, smss: int) -> int:
    """
    Compute the cubic target cwnd per RFC 9438 §4.2:

        target = clamp(W_cubic(t), [cwnd, 1.5 * cwnd])

    The lower bound (target >= cwnd) ensures the cwnd never
    decreases via cubic growth; the upper bound (target <=
    1.5 * cwnd) prevents the cubic increase from outpacing
    slow-start ([SXEZ19]).
    """

    assert cwnd > 0, f"'cwnd' must be positive; got {cwnd!r}"

    raw_target = cubic_w(t_ms, w_max, K_ms, smss)
    if raw_target < cwnd:
        return cwnd
    upper = cwnd + cwnd // 2
    if raw_target > upper:
        return upper
    return raw_target


def cubic_grow_per_ack(
    *,
    cwnd: int,
    ssthresh: int,
    w_max: int,
    K_ms: int,
    epoch_start_ms: int,
    now_ms: int,
    bytes_acked: int,
    smss: int,
    srtt_ms: int = 0,
) -> int:
    """
    Compute the post-growth cwnd value for a cumulative ACK
    that advances SND.UNA per RFC 9438 §4.2 / §4.4 / §4.5.

    Slow-start branch (cwnd < ssthresh) follows RFC 5681 §3.1
    unchanged: cwnd += min(bytes_acked, smss).

    Congestion-avoidance branch (cwnd >= ssthresh) computes
    target = cubic_target(...) and increments cwnd by
        (target - cwnd) * bytes_acked / cwnd
    with a 1-byte floor when target > cwnd. When target <=
    cwnd (the curve hasn't yet caught up to the operating
    point) cwnd is unchanged.

    Parameters:
        cwnd:           current cwnd (bytes; pre-growth)
        ssthresh:       slow-start threshold (bytes)
        w_max:          prior W_max anchor (bytes)
        K_ms:           cubic curve inflection time (ms)
        epoch_start_ms: virtual-clock anchor for the curve (ms)
        now_ms:         current virtual clock (ms)
        bytes_acked:    bytes newly acknowledged by this ACK
        smss:           sender's MSS

    Returns: post-growth cwnd value (bytes).
    """

    assert cwnd > 0, f"'cwnd' must be positive; got {cwnd!r}"
    assert ssthresh > 0, f"'ssthresh' must be positive; got {ssthresh!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"
    assert bytes_acked >= 0, f"'bytes_acked' must be non-negative; got {bytes_acked!r}"

    if cwnd < ssthresh:
        return cwnd + min(bytes_acked, smss)

    # RFC 9438 §4.2: target = clamp(W_cubic(t + RTT), [cwnd, 1.5*cwnd]).
    # The +RTT projection lets the curve aim at the cwnd value
    # the network is expected to support one RTT in the future,
    # smoothing growth across the ACK arrival window. The 'srtt_ms'
    # default of 0 preserves the legacy 'W_cubic(t)' behaviour for
    # callers that don't pass a smoothed RTT (chiefly the unit
    # tests).
    t_ms = max(0, now_ms - epoch_start_ms) + srtt_ms
    target = cubic_target(cwnd, w_max, K_ms, t_ms, smss)

    if target <= cwnd:
        return cwnd

    increment = (target - cwnd) * bytes_acked // cwnd
    return cwnd + max(1, increment)


def cubic_loss_event_ssthresh(
    *,
    cwnd: int,
    smss: int,
    fast_conv_active: bool,
    prior_w_max: int,
) -> tuple[int, int]:
    """
    Compute the new (ssthresh, W_max) pair for a loss event
    per RFC 9438 §4.6 + §4.7.

    §4.6 multiplicative decrease (using cwnd in place of
    flight_size; the implementation MUST prevent cwnd from
    growing past flight_size, which PyTCP does via
    'min(cwnd, snd_wnd)' on the wire-level transmit gate):

        ssthresh = max(cwnd * beta_cubic, 2 * smss)
                 = max(cwnd * 7 // 10, 2 * smss)

    §4.7 fast convergence: if fast_conv_active AND
    cwnd < prior_w_max:

        W_max = cwnd * (1 + beta_cubic) / 2
              = cwnd * 17 // 20

    otherwise:

        W_max = cwnd

    The fast-convergence reduction releases bandwidth to new
    flows entering a saturated network.

    Parameters:
        cwnd:             cwnd at loss-event time (bytes)
        smss:             sender's MSS (bytes)
        fast_conv_active: whether fast convergence is enabled
        prior_w_max:      W_max from the prior loss event (bytes;
                          pass 0 if none)

    Returns: (new_ssthresh, new_W_max) tuple.
    """

    assert cwnd > 0, f"'cwnd' must be positive; got {cwnd!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"
    assert prior_w_max >= 0, f"'prior_w_max' must be non-negative; got {prior_w_max!r}"

    new_ssthresh = max(cwnd * BETA_CUBIC_NUM // BETA_CUBIC_DEN, 2 * smss)

    if fast_conv_active and cwnd < prior_w_max:
        new_w_max = cwnd * FAST_CONV_NUM // FAST_CONV_DEN
    else:
        new_w_max = cwnd

    return new_ssthresh, new_w_max


def cubic_w_est(
    *,
    w_est_prev: int,
    cwnd: int,
    smss: int,
    bytes_acked: int,
) -> int:
    """
    Update the Reno-friendly W_est tracker per RFC 9438 §4.3
    figure 4:

        W_est = W_est + alpha_cubic * segments_acked / cwnd

    where segments_acked is in segments, cwnd in segments,
    and W_est in segments. In bytes (multiplying both sides
    by smss):

        W_est_b += alpha_cubic * bytes_acked * smss / cwnd_b

    using alpha_cubic = ALPHA_CUBIC_NUM / ALPHA_CUBIC_DEN =
    9/17.

    Parameters:
        w_est_prev:  prior W_est value (bytes)
        cwnd:        current cwnd (bytes)
        smss:        sender's MSS (bytes)
        bytes_acked: bytes acknowledged by this cum-ACK

    Returns: new W_est value (bytes).
    """

    assert w_est_prev >= 0, f"'w_est_prev' must be non-negative; got {w_est_prev!r}"
    assert cwnd > 0, f"'cwnd' must be positive; got {cwnd!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"
    assert bytes_acked >= 0, f"'bytes_acked' must be non-negative; got {bytes_acked!r}"

    delta = ALPHA_CUBIC_NUM * bytes_acked * smss // (ALPHA_CUBIC_DEN * cwnd)
    return w_est_prev + delta
