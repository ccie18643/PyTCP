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
This module contains unit tests for the RFC 9406 HyStart++ helper
functions and constants in 'pytcp/protocols/tcp/tcp__hystart.py'.

pytcp/tests/unit/protocols/tcp/test__tcp__hystart.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__hystart import (
    HYSTART__CSS_GROWTH_DIVISOR,
    HYSTART__CSS_ROUNDS,
    HYSTART__MAX_RTT_THRESH_MS,
    HYSTART__MIN_RTT_DIVISOR,
    HYSTART__MIN_RTT_THRESH_MS,
    HYSTART__N_RTT_SAMPLE,
    HYSTART__RTT_INFINITY,
    HyStartState,
    css_growth_increment,
    enter_css,
    fold_rtt_sample,
    resume_slow_start,
    rotate_round,
    rtt_thresh_ms,
    should_exit_slow_start_to_css,
    should_resume_slow_start_from_css,
)


class TestHyStartConstants(TestCase):
    """
    Pin the RFC 9406 §4.3 RECOMMENDED tuning constants.
    """

    def test__hystart__rfc9406_section_4_3_constants(self) -> None:
        """
        Ensure the §4.3 tuning constants match the RFC's
        RECOMMENDED values exactly. Production stacks (Linux,
        FreeBSD) ship these unchanged; a regression that
        nudged any of them would silently change slow-start
        exit behaviour.

        Reference: RFC 9406 §4.3 (tuning constants).
        """

        self.assertEqual(
            HYSTART__MIN_RTT_THRESH_MS,
            4,
            msg="RFC 9406 §4.3: MIN_RTT_THRESH = 4 ms.",
        )
        self.assertEqual(
            HYSTART__MAX_RTT_THRESH_MS,
            16,
            msg="RFC 9406 §4.3: MAX_RTT_THRESH = 16 ms.",
        )
        self.assertEqual(
            HYSTART__MIN_RTT_DIVISOR,
            8,
            msg="RFC 9406 §4.3: MIN_RTT_DIVISOR = 8.",
        )
        self.assertEqual(
            HYSTART__N_RTT_SAMPLE,
            8,
            msg="RFC 9406 §4.3: N_RTT_SAMPLE = 8.",
        )
        self.assertEqual(
            HYSTART__CSS_GROWTH_DIVISOR,
            4,
            msg="RFC 9406 §4.3: CSS_GROWTH_DIVISOR = 4.",
        )
        self.assertEqual(
            HYSTART__CSS_ROUNDS,
            5,
            msg="RFC 9406 §4.3: CSS_ROUNDS = 5.",
        )


class TestRttThreshMs(TestCase):
    """
    Pin the RFC 9406 §4.2 RttThresh formula.
    """

    def test__rtt_thresh_ms__small_rtt_clamps_to_min(self) -> None:
        """
        Ensure that for very small lastRoundMinRTT (8 ms), the
        formula 'lastRoundMinRTT / MIN_RTT_DIVISOR' = 1 ms,
        which is below MIN_RTT_THRESH = 4 ms. The outer max()
        MUST clamp the result up to MIN_RTT_THRESH.

        Reference: RFC 9406 §4.2 (RttThresh = max(MIN_RTT_THRESH, ...)).
        """

        self.assertEqual(
            rtt_thresh_ms(8),
            4,
            msg=("Small lastRoundMinRTT (8 ms) MUST clamp the " "RttThresh up to MIN_RTT_THRESH = 4 ms."),
        )

    def test__rtt_thresh_ms__large_rtt_clamps_to_max(self) -> None:
        """
        Ensure that for very large lastRoundMinRTT (e.g.
        1000 ms), the formula 'lastRoundMinRTT / 8' = 125 ms,
        which exceeds MAX_RTT_THRESH = 16 ms. The inner min()
        MUST clamp the result down to MAX_RTT_THRESH.

        Reference: RFC 9406 §4.2 (RttThresh = ... min(.../DIV, MAX_RTT_THRESH)).
        """

        self.assertEqual(
            rtt_thresh_ms(1000),
            16,
            msg=("Large lastRoundMinRTT (1000 ms) MUST clamp " "the RttThresh down to MAX_RTT_THRESH = 16 ms."),
        )

    def test__rtt_thresh_ms__mid_rtt_uses_division_directly(self) -> None:
        """
        Ensure that for a mid-range lastRoundMinRTT (80 ms),
        the formula yields 80 / 8 = 10 ms, which is within
        the [4, 16] window — so the result is the unclamped
        division.

        Reference: RFC 9406 §4.2.
        """

        self.assertEqual(
            rtt_thresh_ms(80),
            10,
            msg=(
                "Mid-range lastRoundMinRTT (80 ms) MUST yield "
                "RttThresh = 80 / 8 = 10 ms (within the [4, 16] "
                "clamp window)."
            ),
        )


class TestFoldRttSample(TestCase):
    """
    Pin the RFC 9406 §4.2 per-ACK RTT-sample fold.
    """

    def test__fold_rtt_sample__first_sample_replaces_infinity(self) -> None:
        """
        Ensure the first RTT sample replaces the infinity
        sentinel (-1) with the observed RTT, rather than
        evaluating min(-1, rtt) which would corrupt the
        running minimum.

        Reference: RFC 9406 §4.2 (currentRoundMinRTT initialised to infinity).
        """

        state = HyStartState()
        fold_rtt_sample(state, rtt_ms=42)
        self.assertEqual(
            state.current_round_min_rtt_ms,
            42,
            msg=(
                "First RTT sample MUST replace the infinity "
                "sentinel; got "
                f"current_round_min_rtt_ms={state.current_round_min_rtt_ms}."
            ),
        )

    def test__fold_rtt_sample__subsequent_samples_track_minimum(self) -> None:
        """
        Ensure subsequent RTT samples track the running
        per-round minimum.

        Reference: RFC 9406 §4.2 (currentRoundMinRTT = min(currentRoundMinRTT, currRTT)).
        """

        state = HyStartState()
        fold_rtt_sample(state, rtt_ms=50)
        fold_rtt_sample(state, rtt_ms=30)
        fold_rtt_sample(state, rtt_ms=70)

        self.assertEqual(
            state.current_round_min_rtt_ms,
            30,
            msg=(
                "current_round_min_rtt_ms MUST equal the minimum "
                "of all folded samples in the current round; got "
                f"{state.current_round_min_rtt_ms}, expected 30."
            ),
        )

    def test__fold_rtt_sample__increments_sample_count(self) -> None:
        """
        Ensure each fold increments rtt_sample_count by 1.

        Reference: RFC 9406 §4.2 (rttSampleCount += 1).
        """

        state = HyStartState()
        for rtt in (50, 30, 70, 60):
            fold_rtt_sample(state, rtt_ms=rtt)

        self.assertEqual(
            state.rtt_sample_count,
            4,
            msg=(
                "rtt_sample_count MUST equal the number of "
                f"folded samples; got {state.rtt_sample_count}, "
                "expected 4."
            ),
        )


class TestRotateRound(TestCase):
    """
    Pin the RFC 9406 §4.2 round-boundary rotation.
    """

    def test__rotate_round__copies_current_to_last_and_resets(self) -> None:
        """
        Ensure round rotation copies currentRoundMinRTT into
        lastRoundMinRTT, resets currentRoundMinRTT to
        infinity, resets rttSampleCount, and stores the new
        windowEnd seq.

        Reference: RFC 9406 §4.2 (per-round init).
        """

        state = HyStartState(
            current_round_min_rtt_ms=42,
            rtt_sample_count=12,
            window_end_seq=0x1000,
        )
        rotate_round(state, new_window_end_seq=0x2000)

        self.assertEqual(
            state.last_round_min_rtt_ms,
            42,
            msg="last_round_min_rtt_ms MUST be set to the prior current_round_min_rtt_ms.",
        )
        self.assertEqual(
            state.current_round_min_rtt_ms,
            HYSTART__RTT_INFINITY,
            msg="current_round_min_rtt_ms MUST reset to the infinity sentinel.",
        )
        self.assertEqual(
            state.rtt_sample_count,
            0,
            msg="rtt_sample_count MUST reset to 0.",
        )
        self.assertEqual(
            state.window_end_seq,
            0x2000,
            msg="window_end_seq MUST be set to the new SND.NXT.",
        )

    def test__rotate_round__decrements_css_rounds_when_in_css(self) -> None:
        """
        Ensure round rotation in CSS decrements
        'css_rounds_remaining' so the §4.2 "CSS lasts at most
        CSS_ROUNDS rounds" rule can be enforced by the caller.

        Reference: RFC 9406 §4.2 (CSS_ROUNDS counter).
        """

        state = HyStartState(in_css=True, css_rounds_remaining=5)
        rotate_round(state, new_window_end_seq=0x1000)

        self.assertEqual(
            state.css_rounds_remaining,
            4,
            msg=(
                "css_rounds_remaining MUST decrement on each "
                f"CSS round boundary; got {state.css_rounds_remaining}, "
                "expected 4."
            ),
        )

    def test__rotate_round__does_not_decrement_when_not_in_css(self) -> None:
        """
        Ensure round rotation in slow-start (not CSS) does NOT
        touch css_rounds_remaining (it stays at 0).

        Reference: RFC 9406 §4.2 (CSS_ROUNDS counter scoped to CSS).
        """

        state = HyStartState(in_css=False, css_rounds_remaining=0)
        rotate_round(state, new_window_end_seq=0x1000)

        self.assertEqual(
            state.css_rounds_remaining,
            0,
            msg="css_rounds_remaining MUST stay 0 in slow-start.",
        )


class TestShouldExitSlowStartToCss(TestCase):
    """
    Pin the RFC 9406 §4.2 SS→CSS delay-increase trigger.
    """

    def test__exit_to_css__false_when_already_in_css(self) -> None:
        """
        Ensure the trigger does not fire when state is already
        in CSS — the gate only applies during slow-start.

        Reference: RFC 9406 §4.2.
        """

        state = HyStartState(in_css=True)
        self.assertFalse(should_exit_slow_start_to_css(state))

    def test__exit_to_css__false_below_n_rtt_sample(self) -> None:
        """
        Ensure the trigger does not fire when fewer than
        N_RTT_SAMPLE samples have been observed in the current
        round.

        Reference: RFC 9406 §4.2 (rttSampleCount >= N_RTT_SAMPLE gate).
        """

        state = HyStartState(
            last_round_min_rtt_ms=50,
            current_round_min_rtt_ms=70,
            rtt_sample_count=HYSTART__N_RTT_SAMPLE - 1,
        )
        self.assertFalse(should_exit_slow_start_to_css(state))

    def test__exit_to_css__false_when_rtt_unchanged(self) -> None:
        """
        Ensure the trigger does not fire when the current
        round's minRTT is at-or-below the previous round's —
        a stable or decreasing RTT is the negative signal.

        Reference: RFC 9406 §4.2 (currentRoundMinRTT >= lastRoundMinRTT + RttThresh).
        """

        state = HyStartState(
            last_round_min_rtt_ms=50,
            current_round_min_rtt_ms=50,
            rtt_sample_count=HYSTART__N_RTT_SAMPLE,
        )
        self.assertFalse(should_exit_slow_start_to_css(state))

    def test__exit_to_css__true_when_rtt_increase_exceeds_threshold(self) -> None:
        """
        Ensure the trigger fires when the current round's
        minRTT exceeds the previous round's by more than the
        RttThresh window. With lastRoundMinRTT = 80 ms,
        RttThresh = 10 ms; an increase to 95 ms (delta 15 ms)
        crosses the threshold.

        Reference: RFC 9406 §4.2 (delay-increase trigger).
        """

        state = HyStartState(
            last_round_min_rtt_ms=80,
            current_round_min_rtt_ms=95,
            rtt_sample_count=HYSTART__N_RTT_SAMPLE,
        )
        self.assertTrue(should_exit_slow_start_to_css(state))

    def test__exit_to_css__false_when_last_round_min_rtt_infinity(self) -> None:
        """
        Ensure the trigger does not fire when lastRoundMinRTT
        is still at the infinity sentinel (the very first
        round of slow-start has no prior round to compare
        against).

        Reference: RFC 9406 §4.2 (lastRoundMinRTT != infinity gate).
        """

        state = HyStartState(
            last_round_min_rtt_ms=HYSTART__RTT_INFINITY,
            current_round_min_rtt_ms=50,
            rtt_sample_count=HYSTART__N_RTT_SAMPLE,
        )
        self.assertFalse(should_exit_slow_start_to_css(state))


class TestShouldResumeSlowStartFromCss(TestCase):
    """
    Pin the RFC 9406 §4.2 CSS→SS spurious-exit recovery.
    """

    def test__resume_ss__false_when_not_in_css(self) -> None:
        """
        Ensure the resume trigger does not fire when state is
        not in CSS.

        Reference: RFC 9406 §4.2 (CSS-to-SS resume).
        """

        state = HyStartState(in_css=False)
        self.assertFalse(should_resume_slow_start_from_css(state))

    def test__resume_ss__false_below_n_rtt_sample(self) -> None:
        """
        Ensure the resume trigger does not fire below
        N_RTT_SAMPLE in the current CSS round.

        Reference: RFC 9406 §4.2 (sample-floor gate, applied symmetrically).
        """

        state = HyStartState(
            in_css=True,
            css_baseline_min_rtt_ms=80,
            current_round_min_rtt_ms=60,
            rtt_sample_count=HYSTART__N_RTT_SAMPLE - 1,
        )
        self.assertFalse(should_resume_slow_start_from_css(state))

    def test__resume_ss__true_when_current_below_baseline(self) -> None:
        """
        Ensure the resume trigger fires when the CSS round's
        minRTT drops below the CSS-entry baseline — the §4.2
        "spurious slow-start exit" signal.

        Reference: RFC 9406 §4.2 (currentRoundMinRTT < cssBaselineMinRtt).
        """

        state = HyStartState(
            in_css=True,
            css_baseline_min_rtt_ms=80,
            current_round_min_rtt_ms=70,
            rtt_sample_count=HYSTART__N_RTT_SAMPLE,
        )
        self.assertTrue(should_resume_slow_start_from_css(state))


class TestEnterCss(TestCase):
    """
    Pin the RFC 9406 §4.2 SS→CSS state-machine transition.
    """

    def test__enter_css__sets_in_css_and_baseline(self) -> None:
        """
        Ensure entering CSS records the current round's
        minRTT as the baseline and sets the CSS-rounds
        countdown to CSS_ROUNDS.

        Reference: RFC 9406 §4.2 (cssBaselineMinRtt = currentRoundMinRTT).
        """

        state = HyStartState(current_round_min_rtt_ms=95)
        enter_css(state)

        self.assertTrue(state.in_css, msg="enter_css MUST set in_css=True.")
        self.assertEqual(
            state.css_baseline_min_rtt_ms,
            95,
            msg="CSS baseline MUST be set to currentRoundMinRTT.",
        )
        self.assertEqual(
            state.css_rounds_remaining,
            HYSTART__CSS_ROUNDS,
            msg="css_rounds_remaining MUST initialise to CSS_ROUNDS.",
        )


class TestResumeSlowStart(TestCase):
    """
    Pin the RFC 9406 §4.2 CSS→SS state-machine reset.
    """

    def test__resume_slow_start__clears_css_state(self) -> None:
        """
        Ensure resuming slow-start clears the in-CSS flag,
        resets the baseline to infinity, and zeros the CSS-
        rounds countdown.

        Reference: RFC 9406 §4.2 (cssBaselineMinRtt = infinity; resume slow start).
        """

        state = HyStartState(
            in_css=True,
            css_baseline_min_rtt_ms=95,
            css_rounds_remaining=3,
        )
        resume_slow_start(state)

        self.assertFalse(state.in_css)
        self.assertEqual(state.css_baseline_min_rtt_ms, HYSTART__RTT_INFINITY)
        self.assertEqual(state.css_rounds_remaining, 0)


class TestCssGrowthIncrement(TestCase):
    """
    Pin the RFC 9406 §4.2 CSS per-ACK cwnd growth formula.
    """

    def test__css_growth__quarter_of_smss_at_full_smss_ack(self) -> None:
        """
        Ensure that a full-SMSS ACK in CSS grows cwnd by
        SMSS / CSS_GROWTH_DIVISOR = SMSS / 4.

        Reference: RFC 9406 §4.2 (cwnd += min(N, L*SMSS) / CSS_GROWTH_DIVISOR).
        """

        smss = 1460
        self.assertEqual(
            css_growth_increment(bytes_acked=smss, smss=smss),
            smss // 4,
            msg=(
                "CSS per-ACK growth at SMSS-bytes-acked MUST equal "
                f"SMSS / 4 = {smss // 4}; got "
                f"{css_growth_increment(bytes_acked=smss, smss=smss)}."
            ),
        )

    def test__css_growth__caps_at_smss_then_divides(self) -> None:
        """
        Ensure that a multi-SMSS ACK in CSS is capped at SMSS
        (the L=1 standard slow-start cap) BEFORE the divide
        by CSS_GROWTH_DIVISOR — so a 5-SMSS ACK still yields
        only SMSS / 4 increment.

        Reference: RFC 9406 §4.2 (min(N, L*SMSS) inside the divide).
        """

        smss = 1460
        self.assertEqual(
            css_growth_increment(bytes_acked=5 * smss, smss=smss),
            smss // 4,
            msg=(
                "Multi-SMSS ACK in CSS MUST cap at SMSS before "
                "the CSS_GROWTH_DIVISOR division; got "
                f"{css_growth_increment(bytes_acked=5 * smss, smss=smss)}, "
                f"expected {smss // 4}."
            ),
        )


def _hystart_state(**overrides: object) -> HyStartState:
    """Build a HyStartState with the given field overrides."""

    state = HyStartState()
    for name, value in overrides.items():
        setattr(state, name, value)
    return state


class TestHyStartMutationGoldens(TestCase):
    """
    Branch-boundary, floor-division, and default-value goldens closing
    the remaining HyStart++ mutation survivors. The infinity-sentinel
    '== -1' equality mutations to 'is -1' are documented equivalents
    (-1 is interned) and left in place; the '!=' / branch / arithmetic
    mutations are killed here.
    """

    def test__hystart__infinity_sentinel_is_minus_one(self) -> None:
        """
        Ensure the RTT infinity sentinel is exactly -1.

        Reference: RFC 9406 §4.2 (lastRoundMinRTT initialised to infinity).
        """

        self.assertEqual(
            HYSTART__RTT_INFINITY,
            -1,
            msg="HYSTART__RTT_INFINITY must be -1.",
        )

    def test__hystart__state_defaults_and_slots(self) -> None:
        """
        Ensure a fresh HyStartState defaults windowEnd and
        cssRoundsRemaining to 0 and is slotted (no __dict__).

        Reference: RFC 9406 §4.2 (initial HyStart++ state).
        """

        state = HyStartState()
        self.assertEqual(state.window_end_seq, 0, msg="window_end_seq must default to 0.")
        self.assertEqual(state.css_rounds_remaining, 0, msg="css_rounds_remaining must default to 0.")
        self.assertFalse(
            hasattr(state, "__dict__"),
            msg="HyStartState must be slotted (no __dict__).",
        )

    def test__hystart__rtt_thresh_floor_div_and_clamps(self) -> None:
        """
        Ensure RttThresh is lastRoundMinRTT // 8 (integer floor)
        clamped to [4, 16] ms.

        Reference: RFC 9406 §4.2 (RttThresh formula and clamps).
        """

        self.assertEqual(rtt_thresh_ms(100), 12, msg="100 // 8 = 12 (in band).")
        self.assertEqual(rtt_thresh_ms(10), 4, msg="lower clamp to MIN_RTT_THRESH 4.")
        self.assertEqual(rtt_thresh_ms(200), 16, msg="upper clamp to MAX_RTT_THRESH 16.")

    def test__hystart__rtt_thresh_guard(self) -> None:
        """
        Ensure rtt_thresh_ms accepts its exact lower boundary of 0 and
        rejects a negative input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(rtt_thresh_ms(0), 4, msg="rtt_thresh_ms(0) accepted -> 4.")
        with self.assertRaises(AssertionError):
            rtt_thresh_ms(-1)

    def test__hystart__exit_to_css_trigger(self) -> None:
        """
        Ensure the SS→CSS delay trigger fires only when the sample
        floor is met and currentRoundMinRTT >= lastRoundMinRTT +
        RttThresh, pinning the additive threshold (not bit-OR) and the
        '>=' boundary.

        Reference: RFC 9406 §4.2 (delay-increase trigger to CSS).
        """

        # last=100 -> RttThresh=12 -> trigger at current >= 112.
        self.assertTrue(
            should_exit_slow_start_to_css(
                _hystart_state(
                    rtt_sample_count=8,
                    current_round_min_rtt_ms=112,
                    last_round_min_rtt_ms=100,
                )
            ),
            msg="current=112 == last+thresh must trigger CSS exit.",
        )
        self.assertFalse(
            should_exit_slow_start_to_css(
                _hystart_state(
                    rtt_sample_count=8,
                    current_round_min_rtt_ms=111,
                    last_round_min_rtt_ms=100,
                )
            ),
            msg="current=111 < last+thresh must NOT trigger (kills '>='→'>').",
        )
        self.assertFalse(
            should_exit_slow_start_to_css(
                _hystart_state(
                    rtt_sample_count=8,
                    current_round_min_rtt_ms=110,
                    last_round_min_rtt_ms=100,
                )
            ),
            msg="current=110 between (last|thresh) and (last+thresh) must NOT trigger (kills '+'→'|').",
        )

    def test__hystart__exit_to_css_sample_floor_uses_lt(self) -> None:
        """
        Ensure the sample-count floor uses '<' (not 'is not'): a count
        above N_RTT_SAMPLE still triggers, where an 'is not' edit would
        early-return False.

        Reference: RFC 9406 §4.2 (rttSampleCount >= N_RTT_SAMPLE gate).
        """

        self.assertTrue(
            should_exit_slow_start_to_css(
                _hystart_state(
                    rtt_sample_count=9,
                    current_round_min_rtt_ms=112,
                    last_round_min_rtt_ms=100,
                )
            ),
            msg="count=9 (> 8) must still trigger (kills '<'→'is not').",
        )
        self.assertFalse(
            should_exit_slow_start_to_css(
                _hystart_state(
                    rtt_sample_count=7,
                    current_round_min_rtt_ms=112,
                    last_round_min_rtt_ms=100,
                )
            ),
            msg="count=7 (< 8) must not trigger (pins the sample floor; kills 'return False'→'True').",
        )

    def test__hystart__exit_to_css_infinity_guards_return_false(self) -> None:
        """
        Ensure the SS→CSS trigger returns False (not True) when
        currentRoundMinRTT or lastRoundMinRTT is still the infinity
        sentinel, or when already in CSS.

        Reference: RFC 9406 §4.2 (both RTTs must be valid).
        """

        self.assertFalse(
            should_exit_slow_start_to_css(
                _hystart_state(
                    rtt_sample_count=8,
                    current_round_min_rtt_ms=-1,
                    last_round_min_rtt_ms=100,
                )
            ),
            msg="current == infinity must return False.",
        )
        self.assertFalse(
            should_exit_slow_start_to_css(
                _hystart_state(
                    rtt_sample_count=8,
                    current_round_min_rtt_ms=112,
                    last_round_min_rtt_ms=-1,
                )
            ),
            msg="last == infinity must return False.",
        )
        self.assertFalse(
            should_exit_slow_start_to_css(
                _hystart_state(
                    in_css=True,
                    rtt_sample_count=8,
                    current_round_min_rtt_ms=112,
                    last_round_min_rtt_ms=100,
                )
            ),
            msg="already in CSS must return False.",
        )

    def test__hystart__resume_from_css_trigger(self) -> None:
        """
        Ensure the CSS→SS resume fires only when currentRoundMinRTT is
        strictly below cssBaselineMinRtt, pinning the strict '<' and
        the False-returning guards.

        Reference: RFC 9406 §4.2 (spurious-CSS-exit resume).
        """

        self.assertTrue(
            should_resume_slow_start_from_css(
                _hystart_state(
                    in_css=True,
                    rtt_sample_count=8,
                    current_round_min_rtt_ms=50,
                    css_baseline_min_rtt_ms=100,
                )
            ),
            msg="current=50 < baseline=100 must resume slow start.",
        )
        self.assertFalse(
            should_resume_slow_start_from_css(
                _hystart_state(
                    in_css=True,
                    rtt_sample_count=8,
                    current_round_min_rtt_ms=100,
                    css_baseline_min_rtt_ms=100,
                )
            ),
            msg="current=100 == baseline must NOT resume (kills '<'→'<=').",
        )
        self.assertFalse(
            should_resume_slow_start_from_css(
                _hystart_state(
                    in_css=False,
                    rtt_sample_count=8,
                    current_round_min_rtt_ms=50,
                    css_baseline_min_rtt_ms=100,
                )
            ),
            msg="not in CSS must return False.",
        )

    def test__hystart__css_growth_floor_div_and_guards(self) -> None:
        """
        Ensure the CSS growth increment is min(bytes_acked, smss) // 4
        (integer floor) and the argument guards hold at their
        boundaries.

        Reference: RFC 9406 §4.2 (CSS cwnd += min(N, L*SMSS) / CSS_GROWTH_DIVISOR).
        """

        self.assertEqual(
            css_growth_increment(101, 1460),
            25,
            msg="101 // 4 = 25 (odd input pins the floor division).",
        )
        css_growth_increment(0, 1)
        with self.assertRaises(AssertionError):
            css_growth_increment(-1, 1460)
        with self.assertRaises(AssertionError):
            css_growth_increment(100, 0)

    def test__hystart__rotate_round_css_decrement_logic(self) -> None:
        """
        Ensure round rotation decrements cssRoundsRemaining only while
        in CSS and the counter is strictly positive, pinning the 'and'
        (not 'or') and the '> 0' guard.

        Reference: RFC 9406 §4.2 (CSS round counting at round boundary).
        """

        in_css = _hystart_state(in_css=True, css_rounds_remaining=3, current_round_min_rtt_ms=80)
        rotate_round(in_css, 5000)
        self.assertEqual(in_css.css_rounds_remaining, 2, msg="in CSS with rounds>0 must decrement to 2.")
        self.assertEqual(in_css.last_round_min_rtt_ms, 80, msg="lastRoundMinRTT must take currentRoundMinRTT.")
        self.assertEqual(in_css.current_round_min_rtt_ms, -1, msg="currentRoundMinRTT must reset to infinity.")

        not_css = _hystart_state(in_css=False, css_rounds_remaining=3)
        rotate_round(not_css, 9000)
        self.assertEqual(
            not_css.css_rounds_remaining,
            3,
            msg="not in CSS must NOT decrement (kills 'and'→'or').",
        )

        css_zero = _hystart_state(in_css=True, css_rounds_remaining=0)
        rotate_round(css_zero, 1)
        self.assertEqual(
            css_zero.css_rounds_remaining,
            0,
            msg="rounds==0 must NOT decrement below 0 (kills '> 0'→'>= 0').",
        )
