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
This module contains unit tests for the RFC 9438 CUBIC
congestion-control helpers in
'pytcp/protocols/tcp/tcp__cubic.py'.

The tests cover:

  - cubic_compute_K boundary values and monotonicity in W_max.
  - cubic_w canonical (t, W_max, K) triples with hand-verified
    expected outputs and the post-K growth direction.
  - cubic_grow_per_ack slow-start branch unchanged from Reno;
    CA branch picks the cubic target; target-floor and
    target-ceiling clamps fire.
  - cubic_loss_event_ssthresh main path, 2*SMSS floor, fast-
    convergence active vs inactive.
  - cubic_w_est linear growth at alpha_cubic ≈ 0.529.

pytcp/tests/unit/protocols/tcp/test__tcp__cubic.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__cubic import (
    ALPHA_CUBIC_DEN,
    ALPHA_CUBIC_NUM,
    BETA_CUBIC_DEN,
    BETA_CUBIC_NUM,
    C_DEN,
    C_NUM,
    FAST_CONV_DEN,
    FAST_CONV_NUM,
    cubic_compute_K,
    cubic_grow_per_ack,
    cubic_loss_event_ssthresh,
    cubic_target,
    cubic_w,
    cubic_w_est,
)


class TestCubicConstants(TestCase):
    """
    RFC 9438 §4.1.1 constants (encoded as integer ratios).
    """

    def test__cubic__c_constant_value(self) -> None:
        """
        Ensure C = 0.4 encoded exactly as 2/5.

        Reference: RFC 9438 §4.1.1 (constant C).
        """

        self.assertEqual(
            (C_NUM, C_DEN),
            (2, 5),
            msg="RFC 9438 §4.1.1 C must be encoded as 2/5.",
        )

    def test__cubic__beta_constant_value(self) -> None:
        """
        Ensure beta_cubic = 0.7 encoded exactly as 7/10.

        Reference: RFC 9438 §4.6 (beta_cubic SHOULD be 0.7).
        """

        self.assertEqual(
            (BETA_CUBIC_NUM, BETA_CUBIC_DEN),
            (7, 10),
            msg="RFC 9438 §4.6 beta_cubic must be encoded as 7/10.",
        )

    def test__cubic__alpha_constant_value(self) -> None:
        """
        Ensure alpha_cubic = 9/17 ≈ 0.529.

        Reference: RFC 9438 §4.3 (alpha_cubic = 3 * (1 - beta) / (1 + beta)).
        """

        self.assertEqual(
            (ALPHA_CUBIC_NUM, ALPHA_CUBIC_DEN),
            (9, 17),
            msg="RFC 9438 §4.3 alpha_cubic must be encoded as 9/17.",
        )

    def test__cubic__fast_conv_constant_value(self) -> None:
        """
        Ensure (1 + beta_cubic) / 2 = 17/20 (the fast-
        convergence W_max reduction factor).

        Reference: RFC 9438 §4.7 (fast convergence factor).
        """

        self.assertEqual(
            (FAST_CONV_NUM, FAST_CONV_DEN),
            (17, 20),
            msg="RFC 9438 §4.7 fast-convergence factor must be encoded as 17/20.",
        )


class TestCubicComputeK(TestCase):
    """
    RFC 9438 §4.2 figure 2: K = cubicroot(
        (W_max - cwnd_epoch) / C
    ) in seconds, returned in milliseconds.
    """

    def test__cubic__K_zero_when_w_max_equals_cwnd_epoch(self) -> None:
        """
        Ensure K = 0 when W_max == cwnd_epoch (no curve).

        Reference: RFC 9438 §4.2 figure 2.
        """

        self.assertEqual(
            cubic_compute_K(w_max=14600, cwnd_epoch=14600, smss=1460),
            0,
            msg="K must be 0 when W_max == cwnd_epoch.",
        )

    def test__cubic__K_zero_when_w_max_below_cwnd_epoch(self) -> None:
        """
        Ensure K = 0 when W_max < cwnd_epoch (defensive
        bound; the cubic root would be undefined).

        Reference: RFC 9438 §4.2 figure 2 (defensive).
        """

        self.assertEqual(
            cubic_compute_K(w_max=10000, cwnd_epoch=14600, smss=1460),
            0,
            msg="K must be 0 when W_max < cwnd_epoch (defensive).",
        )

    def test__cubic__K_canonical_value(self) -> None:
        """
        Ensure K matches the spec for a canonical operating
        point. With W_max = 100 SMSS = 146000 bytes,
        cwnd_epoch = 70 SMSS = 102200 bytes (post-loss
        70% reduction), smss = 1460:

        diff_seg = 30
        K_seconds = cubicroot(30 / 0.4) = cubicroot(75)
                  ≈ 4.217 seconds
        K_ms ≈ 4217

        Reference: RFC 9438 §4.2 figure 2.
        """

        K_ms = cubic_compute_K(w_max=146000, cwnd_epoch=102200, smss=1460)
        self.assertGreaterEqual(K_ms, 4150, msg="K must be ≈ 4217 ms (lower bound).")
        self.assertLessEqual(K_ms, 4280, msg="K must be ≈ 4217 ms (upper bound).")

    def test__cubic__K_monotone_in_w_max(self) -> None:
        """
        Ensure K grows monotonically with W_max (larger
        W_max → curve takes longer to climb back to it).

        Reference: RFC 9438 §4.2 figure 2.
        """

        K_small = cubic_compute_K(w_max=14600, cwnd_epoch=10220, smss=1460)
        K_large = cubic_compute_K(w_max=146000, cwnd_epoch=102200, smss=1460)
        self.assertLess(
            K_small,
            K_large,
            msg="K must grow monotonically with W_max.",
        )


class TestCubicW(TestCase):
    """
    RFC 9438 §4.2 figure 1: W(t) = C * (t - K)^3 + W_max.
    """

    def test__cubic__w_equals_w_max_at_t_equals_K(self) -> None:
        """
        Ensure W(K) == W_max (the curve passes through W_max
        at the inflection time).

        Reference: RFC 9438 §4.2 figure 1.
        """

        self.assertEqual(
            cubic_w(t_ms=4217, w_max=146000, K_ms=4217, smss=1460),
            146000,
            msg="W(K) must equal W_max.",
        )

    def test__cubic__w_below_w_max_before_K(self) -> None:
        """
        Ensure W(t) < W_max for t < K (concave region; the
        curve approaches W_max from below).

        Reference: RFC 9438 §4.2 figure 1.
        """

        result = cubic_w(t_ms=2000, w_max=146000, K_ms=4217, smss=1460)
        self.assertLess(result, 146000, msg="W(t) must be < W_max for t < K.")

    def test__cubic__w_above_w_max_after_K(self) -> None:
        """
        Ensure W(t) > W_max for t > K (convex region; the
        curve probes new bandwidth past W_max).

        Reference: RFC 9438 §4.2 figure 1.
        """

        result = cubic_w(t_ms=6000, w_max=146000, K_ms=4217, smss=1460)
        self.assertGreater(result, 146000, msg="W(t) must be > W_max for t > K.")

    def test__cubic__w_clamps_at_zero_for_extreme_negative(self) -> None:
        """
        Ensure W(t) is clamped at 0 when the cubic delta
        would underflow past W_max (extreme negative t-K).

        Reference: RFC 9438 §4.2 (defensive non-negative).
        """

        # W_max = 1460, K = 100000, t = 0 → cube = -1e15 → very large
        # negative delta; clamp at 0.
        result = cubic_w(t_ms=0, w_max=1460, K_ms=100000, smss=1460)
        self.assertEqual(result, 0, msg="W(t) must clamp at 0.")


class TestCubicTarget(TestCase):
    """
    RFC 9438 §4.2: target = clamp(W_cubic(t), [cwnd, 1.5*cwnd]).
    """

    def test__cubic__target_floor_at_cwnd_when_curve_below(self) -> None:
        """
        Ensure target == cwnd when W_cubic(t) < cwnd.

        Reference: RFC 9438 §4.2 (target floor).
        """

        # t = 0, K = 4217, W_max = 146000 → W(0) = cwnd_epoch
        # ≈ 102200. Set cwnd = 110000 above the curve so the
        # target floor fires.
        result = cubic_target(cwnd=110000, w_max=146000, K_ms=4217, t_ms=0, smss=1460)
        self.assertEqual(result, 110000, msg="target must clamp to cwnd when curve is below.")

    def test__cubic__target_ceiling_at_1_5_cwnd_when_curve_above(self) -> None:
        """
        Ensure target == 1.5 * cwnd when W_cubic(t) >
        1.5 * cwnd.

        Reference: RFC 9438 §4.2 (target ceiling).
        """

        # Far past K with very large W_max → W_cubic huge.
        result = cubic_target(cwnd=10000, w_max=146000, K_ms=0, t_ms=100000, smss=1460)
        self.assertEqual(result, 15000, msg="target must clamp to 1.5*cwnd when curve far above.")

    def test__cubic__target_uses_curve_value_in_band(self) -> None:
        """
        Ensure target equals W_cubic(t) when in the
        [cwnd, 1.5*cwnd] band.

        Reference: RFC 9438 §4.2.
        """

        # At t=K, W = W_max. Set cwnd = W_max - small offset,
        # W_max in band.
        target = cubic_target(cwnd=140000, w_max=146000, K_ms=4217, t_ms=4217, smss=1460)
        self.assertEqual(target, 146000, msg="target must equal W(t) when in band.")


class TestCubicGrowPerAck(TestCase):
    """
    RFC 9438 §4.2 / §4.4 / §4.5: per-ACK CA growth using
    the cubic curve.
    """

    def test__cubic__slow_start_branch_unchanged_from_reno(self) -> None:
        """
        Ensure that with cwnd < ssthresh, growth is the
        unchanged Reno slow-start formula.

        Reference: RFC 5681 §3.1 (slow-start).
        Reference: RFC 9438 §4.6 (CA-only formula).
        """

        result = cubic_grow_per_ack(
            cwnd=1460,
            ssthresh=14600,
            w_max=0,
            K_ms=0,
            epoch_start_ms=0,
            now_ms=10,
            bytes_acked=1460,
            smss=1460,
        )
        self.assertEqual(
            result,
            2920,
            msg="Slow-start branch must add SMSS regardless of CUBIC state.",
        )

    def test__cubic__ca_branch_grows_when_curve_above_cwnd(self) -> None:
        """
        Ensure CA growth fires when the cubic curve is
        above cwnd (concave or convex region).

        Reference: RFC 9438 §4.4 / §4.5.
        """

        # cwnd = 100*SMSS = 146000; ssthresh below cwnd → CA.
        # W_max = 146000 (current cwnd), K_ms = 0 (post-loss
        # epoch reset), t_ms = 1000 → W(t) > W_max → growth.
        result = cubic_grow_per_ack(
            cwnd=146000,
            ssthresh=100000,
            w_max=146000,
            K_ms=0,
            epoch_start_ms=0,
            now_ms=1000,
            bytes_acked=1460,
            smss=1460,
        )
        self.assertGreater(
            result,
            146000,
            msg="CA branch must grow cwnd when target is above current.",
        )

    def test__cubic__ca_no_growth_when_curve_below_cwnd(self) -> None:
        """
        Ensure cwnd is unchanged when target <= cwnd (the
        cubic curve hasn't caught up yet).

        Reference: RFC 9438 §4.2 (target floor at cwnd).
        """

        # t = 0, K = 4217, W_max = 146000 → W(0) ≈ 102200.
        # cwnd = 110000 > W(0); target is floored at cwnd.
        result = cubic_grow_per_ack(
            cwnd=110000,
            ssthresh=10000,
            w_max=146000,
            K_ms=4217,
            epoch_start_ms=0,
            now_ms=0,
            bytes_acked=1460,
            smss=1460,
        )
        self.assertEqual(
            result,
            110000,
            msg="CA branch must leave cwnd unchanged when target <= cwnd.",
        )


class TestCubicLossEventSsthresh(TestCase):
    """
    RFC 9438 §4.6 + §4.7: ssthresh and W_max update on
    a loss event.
    """

    def test__cubic__ssthresh_halves_at_beta_cubic(self) -> None:
        """
        Ensure ssthresh = cwnd * 7/10 in the main path.

        Reference: RFC 9438 §4.6 (multiplicative decrease).
        """

        ssthresh, w_max = cubic_loss_event_ssthresh(
            cwnd=146000,
            smss=1460,
            fast_conv_active=False,
            prior_w_max=0,
        )
        self.assertEqual(
            ssthresh,
            146000 * 7 // 10,
            msg="ssthresh must equal cwnd * beta_cubic in the main path.",
        )
        self.assertEqual(
            w_max,
            146000,
            msg="W_max must equal cwnd when fast convergence is disabled.",
        )

    def test__cubic__ssthresh_floor_at_2_smss(self) -> None:
        """
        Ensure ssthresh floor at 2*SMSS for very small cwnd.

        Reference: RFC 9438 §4.6 (floor protection).
        """

        ssthresh, _ = cubic_loss_event_ssthresh(
            cwnd=1460,  # 1 SMSS
            smss=1460,
            fast_conv_active=False,
            prior_w_max=0,
        )
        self.assertEqual(
            ssthresh,
            2 * 1460,
            msg="ssthresh must floor at 2*SMSS.",
        )

    def test__cubic__fast_convergence_reduces_w_max_when_cwnd_below_prior(self) -> None:
        """
        Ensure fast convergence reduces W_max to
        cwnd * 17/20 when cwnd < prior W_max.

        Reference: RFC 9438 §4.7 (fast convergence).
        """

        _, w_max = cubic_loss_event_ssthresh(
            cwnd=100000,
            smss=1460,
            fast_conv_active=True,
            prior_w_max=146000,
        )
        self.assertEqual(
            w_max,
            100000 * 17 // 20,
            msg="W_max must be reduced to cwnd * 17/20 when cwnd < prior W_max.",
        )

    def test__cubic__fast_convergence_inactive_when_cwnd_at_or_above_prior(self) -> None:
        """
        Ensure fast convergence does NOT reduce W_max when
        cwnd >= prior W_max (the flow's saturation point
        has not declined).

        Reference: RFC 9438 §4.7 (gating).
        """

        _, w_max = cubic_loss_event_ssthresh(
            cwnd=146000,
            smss=1460,
            fast_conv_active=True,
            prior_w_max=100000,
        )
        self.assertEqual(
            w_max,
            146000,
            msg="W_max must equal cwnd when cwnd >= prior W_max.",
        )

    def test__cubic__fast_convergence_disabled_keeps_w_max_at_cwnd(self) -> None:
        """
        Ensure fast_conv_active=False keeps W_max = cwnd
        even when cwnd < prior W_max.

        Reference: RFC 9438 §4.7 (disabled mode).
        """

        _, w_max = cubic_loss_event_ssthresh(
            cwnd=100000,
            smss=1460,
            fast_conv_active=False,
            prior_w_max=146000,
        )
        self.assertEqual(
            w_max,
            100000,
            msg="W_max must equal cwnd when fast convergence disabled.",
        )


class TestCubicWEst(TestCase):
    """
    RFC 9438 §4.3 figure 4: W_est = W_est + alpha_cubic *
    segments_acked / cwnd.
    """

    def test__cubic__w_est_grows_at_alpha_cubic_per_full_window_acked(self) -> None:
        """
        Ensure W_est grows by alpha_cubic * SMSS bytes when
        a full cwnd worth of bytes is acked (the canonical
        per-RTT reference).

        Reference: RFC 9438 §4.3 figure 4.
        """

        # cwnd = 14600 (10 SMSS); bytes_acked = 14600 (full
        # window). delta = alpha_cubic * 14600 * 1460 /
        # 14600 = alpha_cubic * 1460 = 9 * 1460 / 17 ≈ 773.
        result = cubic_w_est(
            w_est_prev=14600,
            cwnd=14600,
            smss=1460,
            bytes_acked=14600,
        )
        delta = result - 14600
        self.assertEqual(
            delta,
            9 * 1460 // 17,
            msg="W_est must grow by alpha_cubic * SMSS per full-window ack.",
        )

    def test__cubic__w_est_zero_growth_on_zero_bytes_acked(self) -> None:
        """
        Ensure W_est is unchanged when bytes_acked = 0
        (degenerate dup-ACK that shouldn't enter this path).

        Reference: RFC 9438 §4.3 figure 4 (zero numerator).
        """

        result = cubic_w_est(
            w_est_prev=14600,
            cwnd=14600,
            smss=1460,
            bytes_acked=0,
        )
        self.assertEqual(
            result,
            14600,
            msg="W_est must be unchanged on zero bytes acked.",
        )

    def test__cubic__w_est_grows_proportional_to_bytes_acked(self) -> None:
        """
        Ensure W_est advance is approximately linear in
        bytes_acked (within integer-floor rounding error).

        Reference: RFC 9438 §4.3 figure 4 (linear proportionality).
        """

        small = cubic_w_est(w_est_prev=14600, cwnd=14600, smss=1460, bytes_acked=1460)
        large = cubic_w_est(w_est_prev=14600, cwnd=14600, smss=1460, bytes_acked=14600)
        # Integer floor-div introduces small rounding, so allow
        # up to 10 bytes of slack across the 10x scaling.
        self.assertAlmostEqual(
            large - 14600,
            (small - 14600) * 10,
            delta=10,
            msg="W_est advance must scale approximately linearly with bytes_acked.",
        )


class TestCubicHelperAsserts(TestCase):
    """
    Defensive asserts on each helper.
    """

    def test__cubic__compute_K_rejects_negative_w_max(self) -> None:
        """
        Ensure cubic_compute_K rejects negative w_max.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            cubic_compute_K(w_max=-1, cwnd_epoch=0, smss=1460)

    def test__cubic__compute_K_rejects_zero_smss(self) -> None:
        """
        Ensure cubic_compute_K rejects smss <= 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            cubic_compute_K(w_max=14600, cwnd_epoch=0, smss=0)

    def test__cubic__grow_per_ack_rejects_zero_cwnd(self) -> None:
        """
        Ensure cubic_grow_per_ack rejects cwnd <= 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            cubic_grow_per_ack(
                cwnd=0,
                ssthresh=14600,
                w_max=0,
                K_ms=0,
                epoch_start_ms=0,
                now_ms=0,
                bytes_acked=1460,
                smss=1460,
            )

    def test__cubic__loss_event_rejects_zero_cwnd(self) -> None:
        """
        Ensure cubic_loss_event_ssthresh rejects cwnd <= 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            cubic_loss_event_ssthresh(
                cwnd=0,
                smss=1460,
                fast_conv_active=False,
                prior_w_max=0,
            )

    def test__cubic__w_est_rejects_zero_cwnd(self) -> None:
        """
        Ensure cubic_w_est rejects cwnd <= 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            cubic_w_est(
                w_est_prev=0,
                cwnd=0,
                smss=1460,
                bytes_acked=1460,
            )


class TestCubicExactGoldens(TestCase):
    """
    Exact integer-output goldens for every CUBIC formula, so any
    arithmetic mutation (operator swap / constant change) on the
    growth math moves the output and is caught.
    """

    def test__cubic__compute_K_exact_value(self) -> None:
        """
        Ensure cubic_compute_K returns the exact integer K(ms) for
        a canonical decrease, and 0 when cwnd_epoch >= W_max.

        Reference: RFC 9438 §4.2 (K = cubicroot((W_max - cwnd_epoch) / C)).
        """

        self.assertEqual(
            cubic_compute_K(200000, 100000, 1460),
            5553,
            msg="cubic_compute_K(200000,100000,1460) must equal 5553 ms exactly.",
        )
        self.assertEqual(
            cubic_compute_K(100000, 100000, 1460),
            0,
            msg="cubic_compute_K must return 0 when cwnd_epoch == W_max.",
        )

    def test__cubic__w_exact_value_positive_and_negative_diff(self) -> None:
        """
        Ensure cubic_w returns the exact W_cubic(t) for a post-K
        (positive cube) and a pre-K (negative cube) sample.

        Reference: RFC 9438 §4.2 (W(t) = C * (t - K)^3 + W_max).
        """

        self.assertEqual(
            cubic_w(500, 200000, 100, 1460),
            200037,
            msg="cubic_w(500,200000,100,1460) must equal 200037 bytes exactly.",
        )
        self.assertEqual(
            cubic_w(0, 200000, 300, 1460),
            199984,
            msg="cubic_w(0,200000,300,1460) (negative diff) must equal 199984 bytes.",
        )

    def test__cubic__target_clamp_band_exact(self) -> None:
        """
        Ensure cubic_target returns the exact floor, ceiling, and
        in-band values across the three clamp branches.

        Reference: RFC 9438 §4.2 (target = clamp(W_cubic(t), [cwnd, 1.5*cwnd])).
        """

        self.assertEqual(
            cubic_target(100000, 200000, 100, 500, 1460),
            150000,
            msg="cubic_target above 1.5*cwnd must clamp to 150000 (cwnd + cwnd//2).",
        )
        self.assertEqual(
            cubic_target(10000, 200000, 100, 5000, 1460),
            15000,
            msg="cubic_target ceiling for cwnd=10000 must be 15000.",
        )
        self.assertEqual(
            cubic_target(200000, 200000, 100, 2000, 1460),
            204005,
            msg="cubic_target in-band (cwnd=w_max=200000, t=2000) must equal 204005.",
        )

    def test__cubic__grow_per_ack_slow_start_exact(self) -> None:
        """
        Ensure the slow-start branch adds exactly min(bytes_acked, smss).

        Reference: RFC 5681 §3.1 (slow start: cwnd += min(bytes_acked, smss)).
        """

        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=10000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=500,
                bytes_acked=1460,
                smss=1460,
            ),
            11460,
            msg="slow-start full-MSS ack must grow cwnd 10000 -> 11460.",
        )
        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=10000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=500,
                bytes_acked=500,
                smss=1460,
            ),
            10500,
            msg="slow-start sub-MSS ack must grow cwnd by exactly bytes_acked (10500).",
        )

    def test__cubic__grow_per_ack_ca_increment_exact(self) -> None:
        """
        Ensure the congestion-avoidance increment equals
        (target - cwnd) * bytes_acked // cwnd with the clamped target.

        Reference: RFC 9438 §4.2 (cwnd += (target - cwnd) * bytes_acked / cwnd).
        """

        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=100000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=500,
                bytes_acked=1460,
                smss=1460,
            ),
            100730,
            msg="CA increment with clamped target must grow cwnd 100000 -> 100730.",
        )

    def test__cubic__grow_per_ack_ca_unclamped_time_and_rtt_sensitive(self) -> None:
        """
        Ensure the CA elapsed-time term max(0, now - epoch) + srtt feeds
        the unclamped target: changing srtt or the epoch anchor moves the
        post-growth cwnd by the exact expected amount.

        Reference: RFC 9438 §4.2 (target projected to t + RTT).
        """

        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=200000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=3500,
                bytes_acked=1460,
                smss=1460,
                srtt_ms=0,
            ),
            200167,
            msg="unclamped CA growth at now=3500, srtt=0 must equal 200167.",
        )
        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=200000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=3500,
                bytes_acked=1460,
                smss=1460,
                srtt_ms=300,
            ),
            200215,
            msg="srtt=300 must lift the unclamped CA target to 200215 (kills +srtt drop).",
        )
        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=200000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=1000,
                now_ms=3500,
                bytes_acked=1460,
                smss=1460,
                srtt_ms=0,
            ),
            200058,
            msg="epoch=1000 (t=now-epoch=2500) must give 200058 (kills now-epoch swap).",
        )

    def test__cubic__loss_event_ssthresh_exact_pairs(self) -> None:
        """
        Ensure cubic_loss_event_ssthresh returns the exact (ssthresh,
        W_max) pair across the beta-cubic decrease, the 2*SMSS floor,
        and fast-convergence active vs inactive.

        Reference: RFC 9438 §4.6 (ssthresh = max(cwnd*7//10, 2*smss)).
        Reference: RFC 9438 §4.7 (fast convergence: W_max = cwnd*17//20).
        """

        self.assertEqual(
            cubic_loss_event_ssthresh(cwnd=100000, smss=1460, fast_conv_active=True, prior_w_max=200000),
            (70000, 85000),
            msg="beta-cubic decrease + fast-conv must give (70000, 85000).",
        )
        self.assertEqual(
            cubic_loss_event_ssthresh(cwnd=3000, smss=1460, fast_conv_active=True, prior_w_max=200000),
            (2920, 2550),
            msg="ssthresh must floor at 2*smss=2920; W_max = 3000*17//20 = 2550.",
        )
        self.assertEqual(
            cubic_loss_event_ssthresh(cwnd=100000, smss=1460, fast_conv_active=False, prior_w_max=200000),
            (70000, 100000),
            msg="fast-conv inactive must keep W_max = cwnd (100000).",
        )
        self.assertEqual(
            cubic_loss_event_ssthresh(cwnd=100000, smss=1460, fast_conv_active=True, prior_w_max=50000),
            (70000, 100000),
            msg="fast-conv with cwnd >= prior_w_max must keep W_max = cwnd (100000).",
        )

    def test__cubic__w_est_exact_value(self) -> None:
        """
        Ensure cubic_w_est grows the estimate by the exact
        alpha_cubic * bytes_acked / cwnd * smss increment.

        Reference: RFC 9438 §4.3 (W_est += alpha_cubic * (bytes_acked / cwnd)).
        """

        self.assertEqual(
            cubic_w_est(w_est_prev=100000, cwnd=100000, smss=1460, bytes_acked=1460),
            100011,
            msg="cubic_w_est full-MSS ack must grow estimate 100000 -> 100011.",
        )
        self.assertEqual(
            cubic_w_est(w_est_prev=100000, cwnd=100000, smss=1460, bytes_acked=730),
            100005,
            msg="cubic_w_est half-MSS ack must grow estimate 100000 -> 100005.",
        )


class TestCubicMutationTail(TestCase):
    """
    Odd-value floor-division goldens, exact branch-boundary cases,
    and per-argument guard boundaries closing the remaining killable
    CUBIC mutation survivors.
    """

    def test__cubic__target_upper_clamp_floor_divides_on_odd_cwnd(self) -> None:
        """
        Ensure the 1.5*cwnd ceiling uses integer floor division: an
        odd cwnd yields cwnd + cwnd//2 (150001), never the float
        150001.5.

        Reference: RFC 9438 §4.2 (target ceiling at 1.5 * cwnd).
        """

        self.assertEqual(
            cubic_target(100001, 200000, 100, 500, 1460),
            150001,
            msg="target ceiling for odd cwnd=100001 must floor to 150001.",
        )

    def test__cubic__loss_event_floor_divides_on_odd_cwnd(self) -> None:
        """
        Ensure the loss-event ssthresh and fast-convergence W_max use
        integer floor division: an odd cwnd yields the floored
        (70000, 85000), never floats.

        Reference: RFC 9438 §4.6 / §4.7 (ssthresh = cwnd*7//10, W_max = cwnd*17//20).
        """

        ssthresh, w_max = cubic_loss_event_ssthresh(cwnd=100001, smss=1460, prior_w_max=200000, fast_conv_active=True)
        self.assertEqual(
            (ssthresh, w_max),
            (70000, 85000),
            msg="odd cwnd=100001 must floor to ssthresh=70000, W_max=85000.",
        )
        self.assertIsInstance(ssthresh, int, msg="ssthresh must be int (floor div).")
        self.assertIsInstance(w_max, int, msg="W_max must be int (floor div).")

    def test__cubic__ca_increment_floor_is_at_least_one_byte(self) -> None:
        """
        Ensure the CA growth floors at +1 byte: a zero raw increment
        and a unit raw increment both yield exactly cwnd + 1, pinning
        the max(1, ...) floor against a 0 or 2 edit.

        Reference: RFC 9438 §4.2 (1-byte minimum CA growth).
        """

        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=200000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=2000,
                bytes_acked=1,
                smss=1460,
            ),
            200001,
            msg="zero raw increment must floor to cwnd + 1 = 200001.",
        )
        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=200000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=2000,
                bytes_acked=50,
                smss=1460,
            ),
            200001,
            msg="unit raw increment must yield cwnd + 1 = 200001 (kills the +2 floor edit).",
        )

    def test__cubic__ca_default_srtt_is_zero(self) -> None:
        """
        Ensure the srtt_ms parameter defaults to 0: omitting it in an
        unclamped CA case yields the same 200167 as passing srtt_ms=0.

        Reference: RFC 9438 §4.2 (legacy W_cubic(t) without RTT projection).
        """

        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=200000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=3500,
                bytes_acked=1460,
                smss=1460,
            ),
            200167,
            msg="default srtt_ms must be 0 (omitted == passing 0).",
        )

    def test__cubic__ca_branch_taken_at_cwnd_equals_ssthresh(self) -> None:
        """
        Ensure the slow-start / congestion-avoidance split uses a
        strict '<': at cwnd == ssthresh the CA branch is taken (growth
        200029), not the slow-start branch (which would give 201460).

        Reference: RFC 5681 §3.1 (cwnd >= ssthresh enters CA).
        """

        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=200000,
                ssthresh=200000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=2000,
                bytes_acked=1460,
                smss=1460,
            ),
            200029,
            msg="cwnd == ssthresh must take the CA branch (200029, not SS 201460).",
        )

    def test__cubic__no_growth_when_target_not_above_cwnd(self) -> None:
        """
        Ensure that when the curve has not caught up (target floored
        to cwnd) the cwnd is returned unchanged: a strict '<=' edit to
        '<' would wrongly add the 1-byte floor.

        Reference: RFC 9438 §4.2 (no growth while target <= cwnd).
        """

        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=300000,
                ssthresh=50000,
                w_max=200000,
                K_ms=100,
                epoch_start_ms=0,
                now_ms=200,
                bytes_acked=1460,
                smss=1460,
            ),
            300000,
            msg="target == cwnd must leave cwnd unchanged at 300000.",
        )

    def test__cubic__fast_convergence_not_applied_at_cwnd_equals_prior(self) -> None:
        """
        Ensure fast convergence uses a strict '<': at cwnd ==
        prior_w_max it is NOT applied, so W_max stays cwnd (200000),
        not the reduced cwnd*17//20.

        Reference: RFC 9438 §4.7 (fast convergence only when cwnd < prior W_max).
        """

        self.assertEqual(
            cubic_loss_event_ssthresh(cwnd=200000, smss=1460, prior_w_max=200000, fast_conv_active=True),
            (140000, 200000),
            msg="cwnd == prior_w_max must keep W_max = cwnd (200000).",
        )

    def test__cubic__positive_guards_accept_boundary_and_reject_below(self) -> None:
        """
        Ensure every CUBIC argument guard accepts its exact boundary
        (0 for '>= 0' guards, 1 for '> 0' guards) and rejects the
        value just below it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Boundary values accepted (no AssertionError).
        self.assertEqual(cubic_compute_K(0, 0, 1), 0)
        self.assertEqual(cubic_w(0, 0, 0, 1), 0)
        self.assertEqual(cubic_target(1, 0, 0, 0, 1), 1)
        self.assertEqual(
            cubic_grow_per_ack(
                cwnd=1,
                ssthresh=1,
                w_max=0,
                K_ms=0,
                epoch_start_ms=0,
                now_ms=0,
                bytes_acked=0,
                smss=1,
            ),
            1,
        )
        self.assertEqual(
            cubic_loss_event_ssthresh(
                cwnd=1,
                smss=1,
                prior_w_max=0,
                fast_conv_active=False,
            ),
            (2, 1),
        )
        self.assertEqual(
            cubic_w_est(
                w_est_prev=0,
                cwnd=1,
                smss=1,
                bytes_acked=0,
            ),
            0,
        )

        # Below-boundary values rejected.
        for call in (
            lambda: cubic_compute_K(-1, 0, 1),
            lambda: cubic_compute_K(0, -1, 1),
            lambda: cubic_compute_K(0, 0, 0),
            lambda: cubic_w(0, -1, 0, 1),
            lambda: cubic_w(0, 0, 0, 0),
            lambda: cubic_target(0, 0, 0, 0, 1),
            lambda: cubic_grow_per_ack(
                cwnd=0,
                ssthresh=1,
                w_max=0,
                K_ms=0,
                epoch_start_ms=0,
                now_ms=0,
                bytes_acked=0,
                smss=1,
            ),
            lambda: cubic_grow_per_ack(
                cwnd=1,
                ssthresh=0,
                w_max=0,
                K_ms=0,
                epoch_start_ms=0,
                now_ms=0,
                bytes_acked=0,
                smss=1,
            ),
            lambda: cubic_grow_per_ack(
                cwnd=1,
                ssthresh=1,
                w_max=0,
                K_ms=0,
                epoch_start_ms=0,
                now_ms=0,
                bytes_acked=-1,
                smss=1,
            ),
            lambda: cubic_grow_per_ack(
                cwnd=1,
                ssthresh=1,
                w_max=0,
                K_ms=0,
                epoch_start_ms=0,
                now_ms=0,
                bytes_acked=0,
                smss=0,
            ),
            lambda: cubic_loss_event_ssthresh(
                cwnd=0,
                smss=1,
                prior_w_max=0,
                fast_conv_active=False,
            ),
            lambda: cubic_loss_event_ssthresh(
                cwnd=1,
                smss=0,
                prior_w_max=0,
                fast_conv_active=False,
            ),
            lambda: cubic_loss_event_ssthresh(
                cwnd=1,
                smss=1,
                prior_w_max=-1,
                fast_conv_active=False,
            ),
            lambda: cubic_w_est(w_est_prev=-1, cwnd=1, smss=1, bytes_acked=0),
            lambda: cubic_w_est(w_est_prev=0, cwnd=0, smss=1, bytes_acked=0),
            lambda: cubic_w_est(w_est_prev=0, cwnd=1, smss=0, bytes_acked=0),
            lambda: cubic_w_est(w_est_prev=0, cwnd=1, smss=1, bytes_acked=-1),
        ):
            with self.assertRaises(AssertionError):
                call()
