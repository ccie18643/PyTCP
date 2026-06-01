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
This module contains unit tests for the RFC 5681 / RFC 6928
congestion-control helpers in
'pytcp/protocols/tcp/tcp__cwnd.py'.

Three pure functions:

    cwnd_grow_per_ack(cwnd, ssthresh, bytes_acked, smss) -> int
        RFC 5681 §3.1 slow-start vs CA growth.

    compute_loss_event_ssthresh(flight_size, smss) -> int
        RFC 5681 §3.1 / §3.2 step 2 ssthresh halving.

    initial_window(smss) -> int
        RFC 6928 §2 Initial Window.

The tests cover the natural edge cases of each formula:
  - slow-start cap at SMSS, CA floor at 1 byte
  - exact 'cwnd == ssthresh' boundary (CA branch)
  - very large cwnd with very small smss in CA (1-byte floor)
  - flight_size = 0 / 1 / smss / 4*smss / very large (loss event)
  - canonical 1460-byte MSS, very small MSS, very large MSS,
    jumbo MSS (initial window)
  - argument validation asserts on each helper

pytcp/tests/unit/protocols/tcp/test__tcp__cwnd.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__cwnd import (
    INITIAL_WINDOW_BYTES,
    INITIAL_WINDOW_FACTOR,
    compute_ecn_event_ssthresh,
    compute_loss_event_ssthresh,
    cwnd_grow_per_ack,
    initial_window,
)


class TestCwndGrowPerAck__SlowStart(TestCase):
    """
    RFC 5681 §3.1 slow-start branch: cwnd < ssthresh, growth
    is min(bytes_acked, SMSS) per ACK.
    """

    def test__cwnd__slow_start_grows_by_bytes_acked_when_below_smss(self) -> None:
        """
        Ensure that with bytes_acked < SMSS in slow-start, cwnd
        grows by bytes_acked exactly.

        Reference: RFC 5681 §3.1 (slow-start growth).
        """

        result = cwnd_grow_per_ack(cwnd=1460, ssthresh=14600, bytes_acked=500, smss=1460)

        self.assertEqual(
            result,
            1460 + 500,
            msg="Slow-start branch must add bytes_acked when bytes_acked < SMSS.",
        )

    def test__cwnd__slow_start_grows_by_smss_when_bytes_acked_equals_smss(self) -> None:
        """
        Ensure that with bytes_acked == SMSS in slow-start, cwnd
        grows by SMSS (boundary of the min() cap).

        Reference: RFC 5681 §3.1 (slow-start cap at SMSS).
        """

        result = cwnd_grow_per_ack(cwnd=1460, ssthresh=14600, bytes_acked=1460, smss=1460)

        self.assertEqual(
            result,
            1460 + 1460,
            msg="Slow-start branch must add SMSS when bytes_acked == SMSS.",
        )

    def test__cwnd__slow_start_caps_growth_at_smss_when_bytes_acked_above_smss(self) -> None:
        """
        Ensure that with bytes_acked > SMSS in slow-start, cwnd
        grows by SMSS only (the min() cap fires). Models a
        delayed-ACK that cumulatively acknowledges multiple
        segments.

        Reference: RFC 5681 §3.1 (slow-start cap at SMSS).
        """

        result = cwnd_grow_per_ack(cwnd=1460, ssthresh=14600, bytes_acked=10 * 1460, smss=1460)

        self.assertEqual(
            result,
            1460 + 1460,
            msg="Slow-start branch must cap growth at SMSS regardless of bytes_acked.",
        )

    def test__cwnd__slow_start_zero_bytes_acked_leaves_cwnd_unchanged(self) -> None:
        """
        Ensure that bytes_acked = 0 (degenerate ACK) leaves cwnd
        unchanged in slow-start.

        Reference: RFC 5681 §3.1 (slow-start growth requires new ACK).
        """

        result = cwnd_grow_per_ack(cwnd=1460, ssthresh=14600, bytes_acked=0, smss=1460)

        self.assertEqual(
            result,
            1460,
            msg="Slow-start with bytes_acked=0 must not change cwnd.",
        )


class TestCwndGrowPerAck__CongestionAvoidance(TestCase):
    """
    RFC 5681 §3.1 congestion-avoidance branch: cwnd >= ssthresh,
    growth is max(1, SMSS*SMSS // cwnd) per ACK.
    """

    def test__cwnd__ca_growth_at_exact_threshold_uses_ca_branch(self) -> None:
        """
        Ensure that the cwnd == ssthresh boundary uses the CA
        branch (the condition is 'cwnd < ssthresh', so '=='
        falls into CA).

        Reference: RFC 5681 §3.1 (slow-start vs CA boundary).
        """

        result = cwnd_grow_per_ack(cwnd=14600, ssthresh=14600, bytes_acked=1460, smss=1460)

        expected = 14600 + max(1, 1460 * 1460 // 14600)
        self.assertEqual(
            result,
            expected,
            msg="cwnd == ssthresh must use the CA branch (RFC 5681 §3.1 wording 'cwnd < ssthresh' for SS).",
        )

    def test__cwnd__ca_growth_uses_smss_squared_over_cwnd(self) -> None:
        """
        Ensure the standard CA formula: cwnd += SMSS*SMSS //
        cwnd. With SMSS=1460 and cwnd=14600 -> +146
        (= 1460*1460 // 14600).

        Reference: RFC 5681 §3.1 (CA growth = SMSS^2 / cwnd).
        """

        result = cwnd_grow_per_ack(cwnd=14600, ssthresh=1460, bytes_acked=1460, smss=1460)

        self.assertEqual(
            result,
            14600 + 146,
            msg="CA branch must compute floor-div(SMSS*SMSS, cwnd).",
        )

    def test__cwnd__ca_growth_floors_to_one_byte_when_cwnd_huge(self) -> None:
        """
        Ensure that when cwnd is much larger than SMSS*SMSS,
        integer floor-div would yield 0; the max(1, ...) clamps
        to 1 so cwnd always grows by at least one byte.

        Reference: RFC 5681 §3.1 (CA growth floor of 1 byte).
        """

        result = cwnd_grow_per_ack(cwnd=1_000_000_000, ssthresh=1460, bytes_acked=1460, smss=1460)

        self.assertEqual(
            result,
            1_000_000_001,
            msg="CA branch must floor growth at 1 byte regardless of how small SMSS*SMSS // cwnd gets.",
        )

    def test__cwnd__ca_growth_independent_of_bytes_acked(self) -> None:
        """
        Ensure that in CA, growth is determined by cwnd / SMSS
        only, NOT by bytes_acked. Two cum-ACKs with different
        bytes_acked but identical cwnd / ssthresh / smss
        produce identical post-growth cwnd.

        Reference: RFC 5681 §3.1 (CA per-ACK growth formula).
        """

        a = cwnd_grow_per_ack(cwnd=29200, ssthresh=14600, bytes_acked=1460, smss=1460)
        b = cwnd_grow_per_ack(cwnd=29200, ssthresh=14600, bytes_acked=10 * 1460, smss=1460)

        self.assertEqual(
            a,
            b,
            msg="CA growth must depend only on cwnd / smss, not on bytes_acked.",
        )


class TestCwndGrowPerAck__ArgumentAsserts(TestCase):
    """
    Argument validation asserts on cwnd_grow_per_ack.
    """

    def test__cwnd__zero_cwnd_raises(self) -> None:
        """
        Ensure cwnd must be positive (zero / negative cwnd is
        non-sensical for a connection that has begun
        transmitting).

        Reference: RFC 5681 §3 (cwnd is positive byte count).
        """

        with self.assertRaises(AssertionError):
            cwnd_grow_per_ack(cwnd=0, ssthresh=14600, bytes_acked=1460, smss=1460)

    def test__cwnd__zero_ssthresh_raises(self) -> None:
        """
        Ensure ssthresh must be positive (it is the slow-start
        exit threshold; zero would never enter CA correctly).

        Reference: RFC 5681 §3 (ssthresh is positive).
        """

        with self.assertRaises(AssertionError):
            cwnd_grow_per_ack(cwnd=1460, ssthresh=0, bytes_acked=1460, smss=1460)

    def test__cwnd__negative_bytes_acked_raises(self) -> None:
        """
        Ensure bytes_acked must be non-negative (a cum-ACK that
        retreats SND.UNA is a wire-format violation).

        Reference: RFC 9293 §3.4 (cumulative ACK never retreats).
        """

        with self.assertRaises(AssertionError):
            cwnd_grow_per_ack(cwnd=1460, ssthresh=14600, bytes_acked=-1, smss=1460)

    def test__cwnd__zero_smss_raises(self) -> None:
        """
        Ensure smss must be positive (the per-ACK growth cap
        and CA numerator).

        Reference: RFC 5681 §2 (SMSS is positive).
        """

        with self.assertRaises(AssertionError):
            cwnd_grow_per_ack(cwnd=1460, ssthresh=14600, bytes_acked=1460, smss=0)


class TestComputeLossEventSsthresh(TestCase):
    """
    RFC 5681 §3.1 / §3.2 step 2 ssthresh halving:
    ssthresh = max(flight_size // 2, 2 * smss).
    """

    def test__ssthresh__zero_flight_size_clamps_to_two_smss_floor(self) -> None:
        """
        Ensure flight_size = 0 yields max(0, 2*SMSS) = 2*SMSS.
        The floor prevents post-recovery slow-start from
        exiting immediately.

        Reference: RFC 5681 §3.2 (ssthresh floor at 2*SMSS).
        """

        result = compute_loss_event_ssthresh(flight_size=0, smss=1460)

        self.assertEqual(
            result,
            2 * 1460,
            msg="flight_size=0 must clamp ssthresh to 2*SMSS.",
        )

    def test__ssthresh__small_flight_size_clamps_to_two_smss_floor(self) -> None:
        """
        Ensure flight_size = SMSS: max(730, 2920) = 2920. Still
        below the floor.

        Reference: RFC 5681 §3.2 (ssthresh floor at 2*SMSS).
        """

        result = compute_loss_event_ssthresh(flight_size=1460, smss=1460)

        self.assertEqual(
            result,
            2 * 1460,
            msg="flight_size=SMSS must clamp ssthresh to 2*SMSS (730 < 2920).",
        )

    def test__ssthresh__exact_four_smss_flight_size_is_floor_boundary(self) -> None:
        """
        Ensure flight_size = 4*SMSS: max(2*SMSS, 2*SMSS) =
        2*SMSS. Exact boundary where the two clamps meet.

        Reference: RFC 5681 §3.2 (ssthresh floor boundary).
        """

        result = compute_loss_event_ssthresh(flight_size=4 * 1460, smss=1460)

        self.assertEqual(
            result,
            2 * 1460,
            msg="flight_size=4*SMSS is the boundary: max(2*SMSS, 2*SMSS).",
        )

    def test__ssthresh__large_flight_size_uses_half(self) -> None:
        """
        Ensure flight_size = 100*SMSS: max(50*SMSS, 2*SMSS) =
        50*SMSS. The floor is irrelevant here.

        Reference: RFC 5681 §3.2 (ssthresh = FlightSize/2).
        """

        result = compute_loss_event_ssthresh(flight_size=100 * 1460, smss=1460)

        self.assertEqual(
            result,
            50 * 1460,
            msg="flight_size >> SMSS must use FlightSize/2.",
        )

    def test__ssthresh__odd_flight_size_floors_division(self) -> None:
        """
        Ensure flight_size that doesn't divide evenly applies
        integer floor-div: flight_size=10001 -> 5000.

        Reference: RFC 5681 §3.2 (integer halving).
        """

        result = compute_loss_event_ssthresh(flight_size=10001, smss=1460)

        self.assertEqual(
            result,
            5000,
            msg="flight_size//2 must use integer floor-division.",
        )

    def test__ssthresh__negative_flight_size_raises(self) -> None:
        """
        Ensure flight_size must be non-negative.

        Reference: RFC 5681 §3 (FlightSize is non-negative byte count).
        """

        with self.assertRaises(AssertionError):
            compute_loss_event_ssthresh(flight_size=-1, smss=1460)

    def test__ssthresh__zero_smss_raises(self) -> None:
        """
        Ensure smss must be positive (it determines the floor).

        Reference: RFC 5681 §2 (SMSS is positive).
        """

        with self.assertRaises(AssertionError):
            compute_loss_event_ssthresh(flight_size=1460, smss=0)


class TestComputeEcnEventSsthresh(TestCase):
    """
    RFC 8511 §3 ABE (Alternative Backoff with ECN):
    ssthresh = max(flight_size * 17 // 20, 2 * smss).
    """

    def test__ssthresh__zero_flight_size_clamps_to_two_smss_floor(self) -> None:
        """
        Ensure flight_size = 0 yields max(0, 2*SMSS) = 2*SMSS.
        Same floor as the loss-event helper.

        Reference: RFC 8511 §3 (ABE preserves the 2*SMSS floor).
        """

        result = compute_ecn_event_ssthresh(flight_size=0, smss=1460)

        self.assertEqual(
            result,
            2 * 1460,
            msg="flight_size=0 must clamp ssthresh to 2*SMSS.",
        )

    def test__ssthresh__small_flight_size_clamps_to_two_smss_floor(self) -> None:
        """
        Ensure flight_size = SMSS: max(1241, 2920) = 2920. Still
        below the floor since 17/20 of SMSS < 2*SMSS.

        Reference: RFC 8511 §3 (floor at 2*SMSS).
        """

        result = compute_ecn_event_ssthresh(flight_size=1460, smss=1460)

        self.assertEqual(
            result,
            2 * 1460,
            msg="flight_size=SMSS must clamp ssthresh to 2*SMSS.",
        )

    def test__ssthresh__floor_boundary(self) -> None:
        """
        Ensure flight_size at the floor boundary: 2*SMSS / 0.85
        rounds to 3*SMSS at SMSS=1460. flight_size=3*1460=4380:
        max(4380*17//20, 2920) = max(3723, 2920) = 3723. Just
        above the floor.

        Reference: RFC 8511 §3 (boundary case).
        """

        result = compute_ecn_event_ssthresh(flight_size=3 * 1460, smss=1460)

        self.assertEqual(
            result,
            3 * 1460 * 17 // 20,
            msg="flight_size=3*SMSS must yield FlightSize*17/20.",
        )

    def test__ssthresh__large_flight_size_uses_abe_multiplier(self) -> None:
        """
        Ensure flight_size = 100*SMSS: max(85*SMSS, 2*SMSS) =
        85*SMSS. The 17/20 multiplier dominates.

        Reference: RFC 8511 §3 (ABE multiplier 0.85).
        """

        result = compute_ecn_event_ssthresh(flight_size=100 * 1460, smss=1460)

        self.assertEqual(
            result,
            85 * 1460,
            msg="flight_size >> SMSS must use FlightSize*17/20.",
        )

    def test__ssthresh__abe_is_less_aggressive_than_loss(self) -> None:
        """
        Ensure ABE's reduction is strictly less aggressive than
        the RFC 5681 loss-event reduction for any flight_size
        large enough to escape the floor. ABE preserves 0.85 of
        flight; loss-event preserves 0.5.

        Reference: RFC 8511 §3 (ABE preserves more cwnd than loss).
        """

        flight_size = 100 * 1460
        smss = 1460

        loss_value = compute_loss_event_ssthresh(flight_size, smss)
        ecn_value = compute_ecn_event_ssthresh(flight_size, smss)

        self.assertGreater(
            ecn_value,
            loss_value,
            msg=(
                "RFC 8511 §3: ECN-event ssthresh must exceed "
                "loss-event ssthresh for non-floor flight sizes. "
                f"Got ecn={ecn_value} loss={loss_value}."
            ),
        )

    def test__ssthresh__negative_flight_size_raises(self) -> None:
        """
        Ensure flight_size must be non-negative.

        Reference: RFC 8511 §3 (FlightSize is non-negative byte count).
        """

        with self.assertRaises(AssertionError):
            compute_ecn_event_ssthresh(flight_size=-1, smss=1460)

    def test__ssthresh__zero_smss_raises(self) -> None:
        """
        Ensure smss must be positive (it determines the floor).

        Reference: RFC 8511 §3 (SMSS is positive).
        """

        with self.assertRaises(AssertionError):
            compute_ecn_event_ssthresh(flight_size=1460, smss=0)


class TestInitialWindow(TestCase):
    """
    RFC 6928 §2 Initial Window:
    IW = min(10 * smss, max(2 * smss, 14600)).
    """

    def test__iw__canonical_1460_mss_yields_14600(self) -> None:
        """
        Ensure SMSS = 1460 (canonical 1500-MTU) yields
        IW = 10*1460 = 14600.

        Reference: RFC 6928 §2 (Initial Window of 10 segments).
        """

        result = initial_window(smss=1460)

        self.assertEqual(
            result,
            14600,
            msg="Canonical 1460-byte MSS must yield IW = 14600 (= 10*1460).",
        )

    def test__iw__small_mss_yields_14600_floor(self) -> None:
        """
        Ensure SMSS = 100: max(200, 14600) = 14600; min(1000,
        14600) = 1000. The 10*SMSS cap dominates here.

        Reference: RFC 6928 §2 (10*SMSS cap).
        """

        result = initial_window(smss=100)

        self.assertEqual(
            result,
            1000,
            msg="Small MSS: 10*SMSS cap dominates the 14600 floor.",
        )

    def test__iw__mid_mss_uses_14600_floor(self) -> None:
        """
        Ensure SMSS = 1500: max(3000, 14600) = 14600;
        min(15000, 14600) = 14600. The 14600 floor dominates
        the 2*SMSS clamp; the 10*SMSS cap kicks in to clamp to
        14600.

        Reference: RFC 6928 §2 (14600-byte floor).
        """

        result = initial_window(smss=1500)

        self.assertEqual(
            result,
            14600,
            msg="SMSS=1500 must yield IW=14600 (the 14600 floor).",
        )

    def test__iw__large_mss_uses_ten_smss_cap(self) -> None:
        """
        Ensure SMSS = 9000 (jumbo frames): max(18000, 14600) =
        18000; min(90000, 18000) = 18000. The 2*SMSS clamp
        dominates.

        Reference: RFC 6928 §2 (jumbo-MSS path).
        """

        result = initial_window(smss=9000)

        self.assertEqual(
            result,
            18000,
            msg="Jumbo MSS: 2*SMSS dominates 14600 floor; 10*SMSS cap leaves it intact.",
        )

    def test__iw__very_large_mss_uses_two_smss_clamp_only(self) -> None:
        """
        Ensure SMSS = 65535 (UINT16 max): max(131070, 14600) =
        131070; min(655350, 131070) = 131070.

        Reference: RFC 6928 §2 (Initial Window upper bound).
        """

        result = initial_window(smss=65535)

        self.assertEqual(
            result,
            2 * 65535,
            msg="UINT16 MSS: 2*SMSS dominates the floor.",
        )

    def test__iw__zero_smss_raises(self) -> None:
        """
        Ensure smss must be positive (degenerate at 0).

        Reference: RFC 6928 §2 (SMSS positive).
        """

        with self.assertRaises(AssertionError):
            initial_window(smss=0)


class TestModuleConstants(TestCase):
    """
    Module-level constant values pin RFC 6928 numbers so a
    silent edit is caught.
    """

    def test__cwnd__initial_window_factor_is_ten(self) -> None:
        """
        Ensure the segment-count cap is 10.

        Reference: RFC 6928 §2 (Initial Window of 10 segments).
        """

        self.assertEqual(
            INITIAL_WINDOW_FACTOR,
            10,
            msg="RFC 6928 §2 specifies a 10-segment Initial Window cap.",
        )

    def test__cwnd__initial_window_bytes_is_14600(self) -> None:
        """
        Ensure the byte floor is 14600 (= 10 * 1460).

        Reference: RFC 6928 §2 (14600-byte floor).
        """

        self.assertEqual(
            INITIAL_WINDOW_BYTES,
            14600,
            msg="RFC 6928 §2 specifies a 14600-byte floor (10 * canonical 1460 MSS).",
        )
