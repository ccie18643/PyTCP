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
This module contains unit tests for the RFC 6298 RTO estimator in
'pytcp/protocols/tcp/tcp__rto.py'.

Tests assert:

  * RFC 6298 §2.1 / RFC 8961 initial RTO = 1000 ms.
  * RFC 6298 §2.2 first-sample formula
        SRTT = R, RTTVAR = R / 2, RTO = SRTT + max(G, K * RTTVAR).
  * RFC 6298 §2.3 subsequent-sample EWMA with α = 1/8, β = 1/4.
  * RFC 6298 §2.4 lower bound (RTO >= 1 second).
  * RFC 6298 §2.5 upper bound (RTO <= 60 seconds).
  * RFC 6298 §5.5 binary backoff (RTO doubles, capped at MAX).
  * Karn's algorithm spirit: 'back_off' preserves SRTT / RTTVAR.

Reference RFCs:
    RFC 6298   Computing TCP's Retransmission Timer
    RFC 8961   Requirements for Time-Based Loss Detection (initial RTO)

pytcp/tests/unit/protocols/tcp/test__tcp__rto.py

ver 3.0.10
"""

from dataclasses import FrozenInstanceError
from unittest import TestCase

from pytcp.protocols.tcp.tcp__rto import (
    ALPHA_DEN,
    ALPHA_NUM,
    BETA_DEN,
    BETA_NUM,
    INITIAL_RTO_MS,
    MAX_RTO_MS,
    MIN_RTO_MS,
    K,
    RtoState,
    back_off,
    clamp_rto,
    initial_state,
    update,
)


class TestRtoConstants(TestCase):
    """
    Spot-checks on the module-level constants so a refactor that
    silently changes them is caught early.
    """

    def test__rto__initial_rto_is_1_second(self) -> None:
        """
        Ensure the initial RTO before any RTT sample is 1 second.

        Reference: RFC 6298 §2.1 (initial RTO = 1 second).
        """

        self.assertEqual(
            INITIAL_RTO_MS,
            1000,
            msg="RFC 6298 §2.1 mandates initial RTO = 1 second.",
        )

    def test__rto__min_rto_is_at_least_1_second(self) -> None:
        """
        Ensure the RTO lower bound is at least 1 second.

        Reference: RFC 6298 §2.4 (RTO lower bound).
        """

        self.assertGreaterEqual(
            MIN_RTO_MS,
            1000,
            msg="RFC 6298 §2.4 mandates a minimum of at least 1 second.",
        )

    def test__rto__max_rto_is_at_least_60_seconds(self) -> None:
        """
        Ensure the RTO upper bound is at least 60 seconds.

        Reference: RFC 6298 §2.5 (RTO upper bound).
        """

        self.assertGreaterEqual(
            MAX_RTO_MS,
            60_000,
            msg="RFC 6298 §2.5 requires the upper bound, if any, to be >= 60 s.",
        )

    def test__rto__k_multiplier_is_4(self) -> None:
        """
        Ensure the K multiplier on RTTVAR is 4.

        Reference: RFC 6298 §2.2 (K = 4).
        """

        self.assertEqual(K, 4, msg="RFC 6298 mandates K = 4.")

    def test__rto__alpha_is_one_eighth(self) -> None:
        """
        Ensure the SRTT EWMA weight α is 1/8.

        Reference: RFC 6298 §2.3 (alpha = 1/8).
        """

        self.assertEqual(
            (ALPHA_NUM, ALPHA_DEN),
            (1, 8),
            msg="RFC 6298 §2.3 mandates α = 1/8.",
        )

    def test__rto__beta_is_one_quarter(self) -> None:
        """
        Ensure the RTTVAR EWMA weight β is 1/4.

        Reference: RFC 6298 §2.3 (beta = 1/4).
        """

        self.assertEqual(
            (BETA_NUM, BETA_DEN),
            (1, 4),
            msg="RFC 6298 §2.3 mandates β = 1/4.",
        )


class TestRtoInitialState(TestCase):
    """
    The 'initial_state' factory tests.
    """

    def test__rto__initial_state__rto_is_initial_rto_ms(self) -> None:
        """
        Ensure 'initial_state()' returns RTO = INITIAL_RTO_MS
        (1000 ms).

        Reference: RFC 6298 §2.1 (initial RTO before any sample).
        """

        state = initial_state()

        self.assertEqual(
            state.rto_ms,
            INITIAL_RTO_MS,
            msg="initial_state() must yield RTO = INITIAL_RTO_MS (1 s) before any sample.",
        )

    def test__rto__initial_state__srtt_and_rttvar_uninitialized(self) -> None:
        """
        Ensure 'initial_state()' returns 'srtt_ms = None' and
        'rttvar_ms = None' to mark "no RTT measurement yet".

        Reference: RFC 6298 §2 (uninitialized SRTT/RTTVAR).
        """

        state = initial_state()

        self.assertIsNone(
            state.srtt_ms,
            msg="initial_state() must mark SRTT as uninitialized (None).",
        )
        self.assertIsNone(
            state.rttvar_ms,
            msg="initial_state() must mark RTTVAR as uninitialized (None).",
        )


class TestRtoUpdateFirstSample(TestCase):
    """
    The RFC 6298 §2.2 first-sample tests:
        SRTT   = R
        RTTVAR = R / 2
        RTO    = SRTT + max(G, K * RTTVAR), clamped to [MIN, MAX]
    """

    def test__rto__update__first_sample_500ms_canonical_values(self) -> None:
        """
        Ensure that a first sample of 500 ms produces SRTT = 500,
        RTTVAR = 250, and RTO = 500 + max(1, 4 * 250) = 1500 ms
        (within the [MIN, MAX] bounds, no clamping applied).

        Reference: RFC 6298 §2.2 (first-sample formula).
        """

        state = update(initial_state(), 500)

        self.assertEqual(
            state.srtt_ms,
            500,
            msg="RFC 6298 §2.2 first-sample formula: SRTT = R.",
        )
        self.assertEqual(
            state.rttvar_ms,
            250,
            msg="RFC 6298 §2.2 first-sample formula: RTTVAR = R / 2.",
        )
        self.assertEqual(
            state.rto_ms,
            1500,
            msg="RFC 6298 §2.2 first-sample RTO = SRTT + max(G, K * RTTVAR) = 500 + 1000 = 1500 ms.",
        )

    def test__rto__update__first_sample_small_R_clamped_to_min_rto(self) -> None:
        """
        Ensure that a small first sample (e.g., 10 ms - typical of
        a same-host loopback) produces a pre-clamp RTO well below
        1 second, which gets clamped UP to MIN_RTO_MS = 1000 ms.

        Pre-clamp: RTO = 10 + max(1, 4 * 5) = 10 + 20 = 30 ms.
        Post-clamp: RTO = MIN_RTO_MS = 1000 ms.

        Reference: RFC 6298 §2.4 (RTO lower-bound clamp).
        """

        state = update(initial_state(), 10)

        self.assertEqual(
            state.srtt_ms,
            10,
            msg="First-sample SRTT must equal R (no clamping applied to SRTT).",
        )
        self.assertEqual(
            state.rttvar_ms,
            5,
            msg="First-sample RTTVAR must equal R / 2.",
        )
        self.assertEqual(
            state.rto_ms,
            MIN_RTO_MS,
            msg="RFC 6298 §2.4: RTO < 1 s SHOULD be rounded up to MIN_RTO_MS.",
        )


class TestRtoUpdateSubsequentSample(TestCase):
    """
    The RFC 6298 §2.3 subsequent-sample EWMA tests. With α = 1/8
    and β = 1/4 and integer arithmetic via floor division,
    starting from SRTT = 500, RTTVAR = 250 (after the first 500ms
    sample), a follow-up sample of 600 ms yields:

        RTTVAR' = (3 * 250 + |500 - 600|) // 4
                = (750 + 100) // 4 = 850 // 4 = 212

        SRTT'   = (7 * 500 + 600) // 8
                = (3500 + 600) // 8 = 4100 // 8 = 512

        RTO     = 512 + max(1, 4 * 212) = 512 + 848 = 1360 ms
        (within bounds, no clamping)
    """

    def test__rto__update__subsequent_sample_canonical_formula(self) -> None:
        """
        Ensure the EWMA update yields the canonical integer-
        arithmetic values for a known input pair.

        Reference: RFC 6298 §2.3 (EWMA update).
        """

        state = update(initial_state(), 500)
        state = update(state, 600)

        self.assertEqual(
            state.rttvar_ms,
            212,
            msg=("RFC 6298 §2.3 RTTVAR EWMA: " "(3 * 250 + |500 - 600|) // 4 = 850 // 4 = 212."),
        )
        self.assertEqual(
            state.srtt_ms,
            512,
            msg=("RFC 6298 §2.3 SRTT EWMA: " "(7 * 500 + 600) // 8 = 4100 // 8 = 512."),
        )
        self.assertEqual(
            state.rto_ms,
            1360,
            msg=("RFC 6298 §2.3 RTO = SRTT + max(G, K * RTTVAR) = " "512 + 4 * 212 = 1360 ms."),
        )

    def test__rto__update__subsequent_sample_clamped_to_min(self) -> None:
        """
        Ensure that a subsequent sample yielding a sub-second RTO
        is clamped UP to MIN_RTO_MS. Two short samples back-to-
        back (10 ms then 12 ms) yield SRTT and RTTVAR small
        enough that the unclamped RTO is far below 1 second.

        Reference: RFC 6298 §2.4 (RTO lower-bound clamp).
        """

        state = update(initial_state(), 10)
        state = update(state, 12)

        self.assertEqual(
            state.rto_ms,
            MIN_RTO_MS,
            msg="Sub-second RTO from short samples must clamp to MIN_RTO_MS.",
        )

    def test__rto__update__sample_yielding_huge_rto_clamped_to_max(self) -> None:
        """
        Ensure that a pathological RTT sample (e.g., 30 s - a
        link with multi-second latency) yields an unclamped RTO
        far above 60 s on the first sample (RTO = 30000 +
        max(1, 4 * 15000) = 90000 ms), which clamps DOWN to
        MAX_RTO_MS.

        Reference: RFC 6298 §2.5 (RTO upper-bound clamp).
        """

        state = update(initial_state(), 30_000)

        self.assertEqual(
            state.rto_ms,
            MAX_RTO_MS,
            msg="RTO > 60 s must clamp to MAX_RTO_MS per RFC 6298 §2.5.",
        )


class TestRtoBackOff(TestCase):
    """
    The RFC 6298 §5.5 binary-backoff tests.
    """

    def test__rto__back_off__doubles_rto(self) -> None:
        """
        Ensure 'back_off' doubles the current RTO
        ("RTO <- RTO * 2 ('back off the timer')").

        Reference: RFC 6298 §5.5 (binary backoff).
        """

        # Reach a stable RTO well below the upper bound.
        state = update(initial_state(), 500)  # RTO = 1500
        self.assertEqual(state.rto_ms, 1500, msg="Setup precondition: RTO = 1500.")

        state = back_off(state)

        self.assertEqual(
            state.rto_ms,
            3000,
            msg="RFC 6298 §5.5: 'back_off' must double the RTO (1500 -> 3000).",
        )

    def test__rto__back_off__caps_at_max_rto(self) -> None:
        """
        Ensure 'back_off' caps at MAX_RTO_MS so a long-silent
        peer cannot drive the doubled RTO past the upper bound.

        Reference: RFC 6298 §5.5 (backoff capped at MAX_RTO).
        """

        # Construct a state with RTO already near the cap.
        state = RtoState(srtt_ms=10_000, rttvar_ms=5_000, rto_ms=50_000)

        state = back_off(state)

        self.assertEqual(
            state.rto_ms,
            MAX_RTO_MS,
            msg=(
                "RFC 6298 §2.5 / §5.5: 'back_off' must cap RTO at MAX_RTO_MS "
                "(50000 doubled would be 100000, but the upper bound is 60000)."
            ),
        )

    def test__rto__back_off__preserves_srtt_and_rttvar(self) -> None:
        """
        Ensure 'back_off' leaves SRTT and RTTVAR unchanged.
        Karn's algorithm prohibits updating the estimator from
        a retransmitted-segment sample, so the smoothed values
        must remain stale across the entire retransmit-and-
        back-off cycle until a fresh non-retransmitted sample
        arrives.

        Reference: RFC 6298 §3 (Karn's algorithm).
        """

        state = update(initial_state(), 500)  # SRTT=500, RTTVAR=250

        backed_off = back_off(state)

        self.assertEqual(
            backed_off.srtt_ms,
            state.srtt_ms,
            msg="Karn's algorithm: 'back_off' must NOT alter SRTT.",
        )
        self.assertEqual(
            backed_off.rttvar_ms,
            state.rttvar_ms,
            msg="Karn's algorithm: 'back_off' must NOT alter RTTVAR.",
        )


class TestRtoClamp(TestCase):
    """
    The 'clamp_rto' helper-function tests (RFC 6298 §2.4 / §2.5).
    """

    def test__rto__clamp_rto__within_bounds_unchanged(self) -> None:
        """
        Ensure values within '[MIN_RTO_MS, MAX_RTO_MS]' pass
        through unchanged.

        Reference: RFC 6298 §2.4 (RTO bounds).
        """

        for rto_ms in (MIN_RTO_MS, 1500, 30_000, MAX_RTO_MS):
            with self.subTest(rto_ms=rto_ms):
                self.assertEqual(
                    clamp_rto(rto_ms),
                    rto_ms,
                    msg=f"clamp_rto({rto_ms}) must be a no-op when within bounds.",
                )

    def test__rto__clamp_rto__below_min_clamped_up(self) -> None:
        """
        Ensure 'clamp_rto' on values below 'MIN_RTO_MS' returns
        'MIN_RTO_MS'.

        Reference: RFC 6298 §2.4 (RTO lower-bound clamp).
        """

        for rto_ms in (0, 1, 100, 999):
            with self.subTest(rto_ms=rto_ms):
                self.assertEqual(
                    clamp_rto(rto_ms),
                    MIN_RTO_MS,
                    msg=f"clamp_rto({rto_ms}) must round up to MIN_RTO_MS.",
                )

    def test__rto__clamp_rto__above_max_clamped_down(self) -> None:
        """
        Ensure 'clamp_rto' on values above 'MAX_RTO_MS' returns
        'MAX_RTO_MS'.

        Reference: RFC 6298 §2.5 (RTO upper-bound clamp).
        """

        for rto_ms in (MAX_RTO_MS + 1, 100_000, 1_000_000):
            with self.subTest(rto_ms=rto_ms):
                self.assertEqual(
                    clamp_rto(rto_ms),
                    MAX_RTO_MS,
                    msg=f"clamp_rto({rto_ms}) must clamp down to MAX_RTO_MS.",
                )


class TestRtoConvergence(TestCase):
    """
    Stability / convergence sanity checks. Pedagogical: a stream
    of identical RTT samples must drive SRTT toward the sample
    value and RTTVAR toward zero, demonstrating the EWMA filter
    behaves as expected.
    """

    def test__rto__update__many_identical_samples_converge_to_sample(self) -> None:
        """
        Ensure that after a long run of identical samples, SRTT
        converges to the sample value and RTTVAR converges
        toward zero. After 50 samples of 500 ms, SRTT should be
        within a few ms of 500 and RTTVAR should be small enough
        that 'K * RTTVAR < CLOCK_GRANULARITY_MS' is plausible
        (or at least that RTTVAR is much smaller than SRTT).

        Reference: RFC 6298 §2.3 (EWMA convergence).
        """

        state = update(initial_state(), 500)
        for _ in range(50):
            state = update(state, 500)

        self.assertIsNotNone(state.srtt_ms)
        self.assertIsNotNone(state.rttvar_ms)
        # Mypy narrowing.
        srtt_ms = state.srtt_ms
        rttvar_ms = state.rttvar_ms
        assert srtt_ms is not None
        assert rttvar_ms is not None

        self.assertAlmostEqual(
            srtt_ms,
            500,
            delta=10,
            msg="SRTT must converge toward the sample value after a long run of identical samples.",
        )
        self.assertLess(
            rttvar_ms,
            srtt_ms // 10,
            msg="RTTVAR must converge toward zero (much smaller than SRTT) after a long run of identical samples.",
        )


class TestRtoMutationGoldens(TestCase):
    """
    Exact-literal and structural goldens closing the rto mutation
    survivors: the clamp boundaries against literal MIN/MAX (so a
    constant edit is caught even though the clamp helper reads the
    same constant), the first-sample RTTVAR floor division on an
    odd sample, the EWMA second-multiplier on numerators chosen to
    cross the floor boundary, the clock-granularity term exposed at
    RTTVAR=0, and the frozen / slotted RtoState dataclass.
    """

    def test__rto__clamp_boundaries_are_exact_literals(self) -> None:
        """
        Ensure clamp_rto pins to the literal 1000 ms / 60000 ms
        bounds, so a NumberReplacer edit of MIN_RTO_MS / MAX_RTO_MS
        is caught.

        Reference: RFC 6298 §2.4 (RTO lower bound of 1 second).
        Reference: RFC 6298 §2.5 (RTO upper bound, at least 60 seconds).
        """

        self.assertEqual(
            clamp_rto(50),
            1000,
            msg="clamp_rto below the floor must return exactly 1000 ms.",
        )
        self.assertEqual(
            clamp_rto(99999),
            60000,
            msg="clamp_rto above the ceiling must return exactly 60000 ms.",
        )

    def test__rto__first_sample_rttvar_floor_divides_on_odd_R(self) -> None:
        """
        Ensure the first-sample RTTVAR is R // 2 (integer floor): an
        odd R=301 yields 150, never the true-division 150.5.

        Reference: RFC 6298 §2.2 (first sample: RTTVAR = R / 2).
        """

        state = update(initial_state(), 301)
        self.assertEqual(
            state.rttvar_ms,
            150,
            msg="first-sample RTTVAR for odd R=301 must floor to 150.",
        )
        self.assertEqual(
            state.srtt_ms,
            301,
            msg="first-sample SRTT must equal R=301.",
        )

    def test__rto__ewma_second_multiplier_rttvar(self) -> None:
        """
        Ensure the RTTVAR EWMA scales the new deviation by BETA_NUM
        (multiply, not add): with prior RTTVAR=150 and a second
        sample of 321 the result is 117, where the multiply→add
        mutant would yield 118.

        Reference: RFC 6298 §2.3 (RTTVAR EWMA, beta = 1/4).
        """

        state = update(update(initial_state(), 300), 321)
        self.assertEqual(
            state.rttvar_ms,
            117,
            msg="RTTVAR EWMA at sample 321 must be 117 (kills the multiply→add mutant).",
        )

    def test__rto__ewma_second_multiplier_srtt(self) -> None:
        """
        Ensure the SRTT EWMA scales the new sample by ALPHA_NUM
        (multiply, not add): with prior SRTT=300 and a second sample
        of 323 the result is 302, where the multiply→add mutant would
        yield 303.

        Reference: RFC 6298 §2.3 (SRTT EWMA, alpha = 1/8).
        """

        state = update(update(initial_state(), 300), 323)
        self.assertEqual(
            state.srtt_ms,
            302,
            msg="SRTT EWMA at sample 323 must be 302 (kills the multiply→add mutant).",
        )

    def test__rto__clock_granularity_floor_exposed_at_zero_rttvar(self) -> None:
        """
        Ensure the RTO adds max(CLOCK_GRANULARITY_MS, K*RTTVAR): after
        a long run of identical large samples RTTVAR decays to 0 and
        SRTT settles at 2000, so the unclamped RTO is exactly
        2000 + 1 = 2001 — a CLOCK_GRANULARITY_MS edit moves it.

        Reference: RFC 6298 §2.4 (RTO = SRTT + max(G, K*RTTVAR)).
        """

        state = initial_state()
        for _ in range(120):
            state = update(state, 2000)

        self.assertEqual(
            state.rttvar_ms,
            0,
            msg="RTTVAR must decay to exactly 0 after a long identical-sample run.",
        )
        self.assertEqual(
            state.rto_ms,
            2001,
            msg="RTO must be SRTT(2000) + CLOCK_GRANULARITY(1) = 2001 when RTTVAR=0.",
        )

    def test__rto__state_is_frozen_and_slotted(self) -> None:
        """
        Ensure RtoState is a frozen, slotted dataclass (no __dict__,
        immutable), so the frozen=/slots= flags cannot be flipped
        unnoticed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        state = initial_state()
        self.assertFalse(
            hasattr(state, "__dict__"),
            msg="RtoState must be slotted (no __dict__).",
        )
        with self.assertRaises(FrozenInstanceError):
            state.rto_ms = 5  # type: ignore[misc]
