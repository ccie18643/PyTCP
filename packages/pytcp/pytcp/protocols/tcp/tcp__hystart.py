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
This module contains the RFC 9406 HyStart++ delay-based slow-start-
exit algorithm as pure functions, separated from session state.

HyStart++ replaces classic slow-start's "blast cwnd until first
loss" termination with a delay-based exit that detects bandwidth
saturation BEFORE loss occurs:

  - Track per-round minimum RTT during slow-start.
  - When current round's minRTT exceeds the previous round's by
    a small threshold, exit slow-start to a "Conservative Slow
    Start" (CSS) phase that grows cwnd at 1/CSS_GROWTH_DIVISOR
    the normal slow-start rate.
  - In CSS, watch for RTT recovery: if currentRoundMinRTT drops
    below the CSS-entry baseline, the early exit was spurious
    and slow-start resumes.
  - If CSS_ROUNDS rounds pass without RTT recovery, treat the
    delay increase as genuine bandwidth saturation and enter
    congestion avoidance (set ssthresh = cwnd).

The §4.3 tuning constants are encoded here. The session-level
hook points (RTT-sample feed, round-boundary detection, cwnd
growth) live in 'pytcp/protocols/tcp/tcp__session.py'.

pytcp/protocols/tcp/tcp__hystart.py

ver 3.0.9
"""

from dataclasses import dataclass

# RFC 9406 §4.3 tuning constants. These RECOMMENDED values were
# determined from lab measurements; production stacks (Linux,
# FreeBSD) ship them unchanged.
HYSTART__MIN_RTT_THRESH_MS: int = 4
HYSTART__MAX_RTT_THRESH_MS: int = 16
HYSTART__MIN_RTT_DIVISOR: int = 8
HYSTART__N_RTT_SAMPLE: int = 8
HYSTART__CSS_GROWTH_DIVISOR: int = 4
HYSTART__CSS_ROUNDS: int = 5

# RFC 9406 §4.2 sentinel for "infinity" — encoded as -1 since we
# carry RTTs as non-negative integers (milliseconds). Comparisons
# against the sentinel use explicit equality checks rather than
# arithmetic so the sentinel never enters min() / arithmetic
# expressions.
HYSTART__RTT_INFINITY: int = -1


@dataclass(slots=True)
class HyStartState:
    """
    HyStart++ per-connection state. Mutable because the algorithm
    naturally evolves across rounds and ACKs; the session owns the
    instance and the helper functions in this module update it
    in place. The 'in_css' flag distinguishes the slow-start vs
    Conservative Slow Start phases.
    """

    # RFC 9406 §4.2: lastRoundMinRTT, currentRoundMinRTT, currRTT
    # all initialised to infinity. PyTCP encodes infinity as -1.
    last_round_min_rtt_ms: int = HYSTART__RTT_INFINITY
    current_round_min_rtt_ms: int = HYSTART__RTT_INFINITY

    # RFC 9406 §4.2: rttSampleCount per round; reset at each
    # round boundary.
    rtt_sample_count: int = 0

    # RFC 9406 §4.2: windowEnd as a sequence number marking the
    # end of the current round. Initialised to 0 here; the session
    # sets it to SND.NXT on first transmit and rotates at each
    # round boundary.
    window_end_seq: int = 0

    # RFC 9406 §4.2 CSS state. 'in_css' is True during the
    # Conservative Slow Start phase. 'css_baseline_min_rtt_ms' is
    # the minRTT recorded at CSS entry; CSS resumes slow-start if
    # currentRoundMinRTT drops below this baseline.
    # 'css_rounds_remaining' counts down from CSS_ROUNDS at CSS
    # entry; zero means CSS exhausted (enter CA).
    in_css: bool = False
    css_baseline_min_rtt_ms: int = HYSTART__RTT_INFINITY
    css_rounds_remaining: int = 0


def rtt_thresh_ms(last_round_min_rtt_ms: int) -> int:
    """
    Compute the per-round delay-increase threshold per RFC 9406
    §4.2:

        RttThresh = max(MIN_RTT_THRESH,
                        min(lastRoundMinRTT / MIN_RTT_DIVISOR,
                            MAX_RTT_THRESH))

    The clamp ensures the threshold is at least MIN_RTT_THRESH
    (4 ms) and at most MAX_RTT_THRESH (16 ms), regardless of how
    fast or slow the path is. For typical 50-200 ms RTT paths,
    the formula yields lastRoundMinRTT / 8 = 6-25 ms which the
    upper clamp pins at 16 ms.

    Caller MUST pass a valid lastRoundMinRTT (not the infinity
    sentinel); the helper does not handle infinity.
    """

    assert last_round_min_rtt_ms >= 0, (
        f"'last_round_min_rtt_ms' must be a non-negative RTT in "
        f"milliseconds; got {last_round_min_rtt_ms!r} (the infinity "
        "sentinel is not a valid input to rtt_thresh_ms)."
    )

    return max(
        HYSTART__MIN_RTT_THRESH_MS,
        min(
            last_round_min_rtt_ms // HYSTART__MIN_RTT_DIVISOR,
            HYSTART__MAX_RTT_THRESH_MS,
        ),
    )


def should_exit_slow_start_to_css(state: HyStartState) -> bool:
    """
    Apply the RFC 9406 §4.2 delay-increase trigger that exits
    slow-start to CSS:

        if (rttSampleCount >= N_RTT_SAMPLE
            AND currentRoundMinRTT != infinity
            AND lastRoundMinRTT != infinity):
          RttThresh = max(MIN_RTT_THRESH,
            min(lastRoundMinRTT / MIN_RTT_DIVISOR, MAX_RTT_THRESH))
          if (currentRoundMinRTT >= (lastRoundMinRTT + RttThresh)):
            exit slow start and enter CSS

    Returns True iff the caller should transition to CSS.
    """

    if state.in_css:
        return False
    if state.rtt_sample_count < HYSTART__N_RTT_SAMPLE:
        return False
    if state.current_round_min_rtt_ms == HYSTART__RTT_INFINITY:
        return False
    if state.last_round_min_rtt_ms == HYSTART__RTT_INFINITY:
        return False

    threshold = rtt_thresh_ms(state.last_round_min_rtt_ms)
    return state.current_round_min_rtt_ms >= state.last_round_min_rtt_ms + threshold


def should_resume_slow_start_from_css(state: HyStartState) -> bool:
    """
    Apply the RFC 9406 §4.2 spurious-CSS-exit check:

        if (currentRoundMinRTT < cssBaselineMinRtt):
            cssBaselineMinRtt = infinity
            resume slow start including HyStart++

    The check requires N_RTT_SAMPLE samples in the current CSS
    round before being considered, mirroring the SS->CSS gate's
    sample-floor for symmetry (the RFC text doesn't strictly
    require this for the resume path, but applying the same
    sample floor avoids triggering on a single anomalous RTT
    drop).

    Returns True iff the caller should resume slow-start from
    CSS.
    """

    if not state.in_css:
        return False
    if state.rtt_sample_count < HYSTART__N_RTT_SAMPLE:
        return False
    if state.current_round_min_rtt_ms == HYSTART__RTT_INFINITY:
        return False
    if state.css_baseline_min_rtt_ms == HYSTART__RTT_INFINITY:
        return False

    return state.current_round_min_rtt_ms < state.css_baseline_min_rtt_ms


def css_growth_increment(bytes_acked: int, smss: int) -> int:
    """
    Compute the per-ACK cwnd increment during CSS per RFC 9406
    §4.2:

        cwnd += min(N, L * SMSS) / CSS_GROWTH_DIVISOR

    where N = bytes_acked and L = 1 (PyTCP uses the conservative
    L=1 cap consistent with RFC 5681's standard slow-start;
    RFC 9406's L=8 ABC-style boost is orthogonal to the delay-
    detection mechanism and is not enabled here).

    Returns the byte count to add to cwnd.
    """

    assert bytes_acked >= 0, f"'bytes_acked' must be non-negative; got {bytes_acked!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"

    return min(bytes_acked, smss) // HYSTART__CSS_GROWTH_DIVISOR


def fold_rtt_sample(state: HyStartState, rtt_ms: int) -> None:
    """
    Fold a fresh RTT sample into the HyStart++ state per RFC 9406
    §4.2:

        currentRoundMinRTT = min(currentRoundMinRTT, currRTT)
        rttSampleCount += 1

    The infinity sentinel collapses correctly: min(infinity, rtt)
    = rtt, encoded as the explicit "if currentRoundMinRTT ==
    infinity, take the new value" branch.
    """

    assert rtt_ms >= 0, f"'rtt_ms' must be non-negative; got {rtt_ms!r}"

    if state.current_round_min_rtt_ms == HYSTART__RTT_INFINITY:
        state.current_round_min_rtt_ms = rtt_ms
    else:
        state.current_round_min_rtt_ms = min(state.current_round_min_rtt_ms, rtt_ms)
    state.rtt_sample_count += 1


def rotate_round(state: HyStartState, new_window_end_seq: int) -> None:
    """
    Rotate the HyStart++ per-round state at a round boundary per
    RFC 9406 §4.2:

        lastRoundMinRTT = currentRoundMinRTT
        currentRoundMinRTT = infinity
        rttSampleCount = 0

    The new windowEnd is set to the caller's SND.NXT at the
    moment of rotation. CSS round counting decrements
    'css_rounds_remaining'; reaching zero is the caller's signal
    to enter congestion avoidance.
    """

    state.last_round_min_rtt_ms = state.current_round_min_rtt_ms
    state.current_round_min_rtt_ms = HYSTART__RTT_INFINITY
    state.rtt_sample_count = 0
    state.window_end_seq = new_window_end_seq

    if state.in_css and state.css_rounds_remaining > 0:
        state.css_rounds_remaining -= 1


def enter_css(state: HyStartState) -> None:
    """
    Transition the HyStart++ state machine into CSS per RFC 9406
    §4.2:

        cssBaselineMinRtt = currentRoundMinRTT
        exit slow start and enter CSS

    Initialises the CSS round counter to CSS_ROUNDS per the §4.2
    "CSS lasts at most CSS_ROUNDS rounds" rule.
    """

    state.in_css = True
    state.css_baseline_min_rtt_ms = state.current_round_min_rtt_ms
    state.css_rounds_remaining = HYSTART__CSS_ROUNDS


def resume_slow_start(state: HyStartState) -> None:
    """
    Reset the CSS state per RFC 9406 §4.2's "resume slow start
    including HyStart++":

        cssBaselineMinRtt = infinity
        resume slow start
    """

    state.in_css = False
    state.css_baseline_min_rtt_ms = HYSTART__RTT_INFINITY
    state.css_rounds_remaining = 0
