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
This module contains unit tests for the RFC 6582 NewReno
fast-recovery cwnd deflation helper in
'pytcp/protocols/tcp/tcp__newreno.py'.

The helper exposes a single pure function:
    'partial_cum_ack_deflate(cwnd, bytes_acked, smss) -> int'

which encodes the RFC 6582 §3 step 3b accounting:
    new_cwnd = max(smss, cwnd - bytes_acked)
    if bytes_acked >= smss:
        new_cwnd += smss

The tests cover the natural edge cases of this formula:
  - bytes_acked < smss (deflation only, no add-back)
  - bytes_acked == smss (deflation cancels add-back)
  - bytes_acked > smss (net deflation = bytes_acked - smss)
  - bytes_acked clamped by the smss floor
  - cwnd already at the smss floor (interaction with the
    deflation-then-add-back ordering)
  - argument validation asserts

pytcp/tests/unit/protocols/tcp/test__tcp__newreno.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__newreno import partial_cum_ack_deflate


class TestPartialCumAckDeflate__SubMssAcked(TestCase):
    """
    Sub-MSS partial cum-ACK: the deflation runs but the
    add-back does not fire (the §3 step 3b 'if bytes_acked
    >= SMSS' guard rejects it).
    """

    def test__newreno__sub_mss_acked_deflates_by_bytes_acked_only(self) -> None:
        """
        Ensure a partial cum-ACK acking less than 1 SMSS
        deflates cwnd by 'bytes_acked' and does NOT add back
        any SMSS (the add-back is gated on 'bytes_acked >=
        SMSS').

        Reference: RFC 6582 §3 step 3b (sub-MSS deflation only).
        """

        result = partial_cum_ack_deflate(cwnd=10000, bytes_acked=500, smss=1460)

        self.assertEqual(
            result,
            9500,
            msg=("RFC 6582 §3 step 3b: cwnd=10000 - " "bytes_acked=500 = 9500, no add-back since " "500 < SMSS=1460."),
        )

    def test__newreno__sub_mss_acked_just_below_floor_clamps(self) -> None:
        """
        Ensure that when the deflation would push cwnd below
        SMSS, the floor clamps it to SMSS and no add-back
        fires.

        Reference: RFC 6582 §3 step 3b (deflation floor at SMSS).
        """

        result = partial_cum_ack_deflate(cwnd=2000, bytes_acked=1000, smss=1460)

        self.assertEqual(
            result,
            1460,
            msg=(
                "Floor clamp: cwnd=2000 - 1000 = 1000 < "
                "SMSS=1460; result MUST be SMSS (the §3 step "
                "3b deflation floor)."
            ),
        )


class TestPartialCumAckDeflate__ExactMssAcked(TestCase):
    """
    Partial cum-ACK acking exactly 1 SMSS: the deflation
    cancels the add-back, leaving cwnd unchanged.
    """

    def test__newreno__exact_mss_acked_leaves_cwnd_unchanged(self) -> None:
        """
        Ensure that bytes_acked = SMSS triggers both the
        deflation (-SMSS) and the add-back (+SMSS); the two
        operations cancel and cwnd ends up unchanged.

        Reference: RFC 6582 §3 step 3b (deflation+add-back cancel).
        """

        result = partial_cum_ack_deflate(cwnd=10000, bytes_acked=1460, smss=1460)

        self.assertEqual(
            result,
            10000,
            msg=(
                "RFC 6582 §3 step 3b: cwnd=10000, "
                "bytes_acked=SMSS=1460. Deflation -1460 + "
                "add-back +1460 = 0 net change; cwnd stays "
                "at 10000."
            ),
        )


class TestPartialCumAckDeflate__MultiMssAcked(TestCase):
    """
    Partial cum-ACK acking more than 1 SMSS: net deflation
    = bytes_acked - SMSS.
    """

    def test__newreno__double_mss_acked_deflates_by_one_mss_net(self) -> None:
        """
        Ensure bytes_acked = 2*SMSS yields deflation -2*SMSS +
        add-back +SMSS = -1*SMSS net change.

        Reference: RFC 6582 §3 step 3b (multi-SMSS deflation accounting).
        """

        result = partial_cum_ack_deflate(cwnd=10000, bytes_acked=2 * 1460, smss=1460)

        self.assertEqual(
            result,
            10000 - 1460,
            msg=("bytes_acked = 2*SMSS: net change = -SMSS. " "cwnd=10000 -> 8540."),
        )

    def test__newreno__triple_mss_acked_deflates_by_two_mss_net(self) -> None:
        """
        Ensure bytes_acked = 3*SMSS yields deflation -3*SMSS +
        add-back +SMSS = -2*SMSS net.

        Reference: RFC 6582 §3 step 3b (multi-SMSS deflation accounting).
        """

        result = partial_cum_ack_deflate(cwnd=10000, bytes_acked=3 * 1460, smss=1460)

        self.assertEqual(
            result,
            10000 - 2 * 1460,
            msg=("bytes_acked = 3*SMSS: net change = -2*SMSS. " "cwnd=10000 -> 7080."),
        )

    def test__newreno__large_acked_clamps_cwnd_to_floor_then_adds_smss(self) -> None:
        """
        Ensure that when bytes_acked is large enough that the
        raw deflation would drive cwnd below SMSS, the floor
        clamps the deflation to SMSS, and then the add-back
        applies on top because bytes_acked >= SMSS. Result:
        cwnd = 2 * SMSS.

        Reference: RFC 6582 §3 step 3b (deflation floor + add-back).
        """

        result = partial_cum_ack_deflate(cwnd=2000, bytes_acked=10 * 1460, smss=1460)

        self.assertEqual(
            result,
            2 * 1460,
            msg=(
                "Large bytes_acked: deflation clamped to SMSS, "
                "then add-back applied. cwnd=2000, "
                "bytes_acked=10*SMSS, smss=1460 -> "
                "max(SMSS, 2000 - 10*SMSS) = SMSS = 1460; "
                "+SMSS add-back -> 2*SMSS = 2920."
            ),
        )


class TestPartialCumAckDeflate__BoundaryCwnd(TestCase):
    """
    cwnd already at or near the SMSS floor.
    """

    def test__newreno__cwnd_at_floor_with_sub_mss_acked_stays_at_floor(self) -> None:
        """
        Ensure that with cwnd already at SMSS and a partial
        cum-ACK acking less than SMSS, deflation clamps to
        SMSS, no add-back fires, and cwnd stays at the floor.

        Reference: RFC 6582 §3 step 3b (floor invariant).
        """

        result = partial_cum_ack_deflate(cwnd=1460, bytes_acked=100, smss=1460)

        self.assertEqual(
            result,
            1460,
            msg=("cwnd already at SMSS floor; sub-SMSS ack " "leaves cwnd at floor."),
        )

    def test__newreno__cwnd_at_floor_with_full_mss_acked_grows_to_double_mss(self) -> None:
        """
        Ensure that with cwnd at SMSS and a partial cum-ACK
        acking exactly SMSS, deflation clamps to SMSS and the
        add-back fires (since bytes_acked >= SMSS), yielding
        cwnd = 2 * SMSS.

        This is the only case where partial cum-ACK GROWS
        cwnd. It happens because the floor protects the
        deflation step but the add-back is unconditional on
        'bytes_acked >= SMSS'. In practice, cwnd at SMSS
        means we're right at the slow-start re-entry value
        and the recovery is barely making progress; the
        small permissive grant is RFC-correct.

        Reference: RFC 6582 §3 step 3b (floor + add-back permissive grant).
        """

        result = partial_cum_ack_deflate(cwnd=1460, bytes_acked=1460, smss=1460)

        self.assertEqual(
            result,
            2 * 1460,
            msg=("cwnd at SMSS, bytes_acked=SMSS: floor + " "add-back yields 2*SMSS."),
        )


class TestPartialCumAckDeflate__ArgumentAsserts(TestCase):
    """
    The helper asserts on argument sanity to fail loudly on
    accidental zero / negative inputs from broken callers.
    """

    def test__newreno__negative_cwnd_raises(self) -> None:
        """
        Ensure cwnd < 0 raises (non-sensical input).

        Reference: RFC 6582 §3 (cwnd is non-negative byte count).
        """

        with self.assertRaises(AssertionError):
            partial_cum_ack_deflate(cwnd=-1, bytes_acked=100, smss=1460)

    def test__newreno__negative_bytes_acked_raises(self) -> None:
        """
        Ensure bytes_acked < 0 raises (non-sensical input).

        Reference: RFC 6582 §3 (bytes_acked is non-negative).
        """

        with self.assertRaises(AssertionError):
            partial_cum_ack_deflate(cwnd=10000, bytes_acked=-1, smss=1460)

    def test__newreno__zero_smss_raises(self) -> None:
        """
        Ensure smss must be positive (it is the floor + add-
        back value, both of which would be degenerate at 0).

        Reference: RFC 6582 §3 (SMSS is positive byte count).
        """

        with self.assertRaises(AssertionError):
            partial_cum_ack_deflate(cwnd=10000, bytes_acked=100, smss=0)

    def test__newreno__zero_bytes_acked_passes_through(self) -> None:
        """
        Ensure bytes_acked = 0 passes through. This is
        degenerate (a partial cum-ACK should advance SND.UNA
        by at least one byte) but the helper does not assert
        on it - the caller's SND.UNA-advancement gate is the
        actual filter. With bytes_acked=0 the helper returns
        max(smss, cwnd) and skips the add-back, which is
        RFC-equivalent to "do nothing" for any reasonable cwnd.

        Reference: RFC 6582 §3 step 3b (no-op on no-progress).
        """

        result = partial_cum_ack_deflate(cwnd=10000, bytes_acked=0, smss=1460)

        self.assertEqual(
            result,
            10000,
            msg="bytes_acked=0 leaves cwnd unchanged.",
        )


class TestPartialCumAckDeflate__GuardBoundaries(TestCase):
    """
    Exact argument-guard boundaries closing the assert-line mutation
    survivors: cwnd accepts 0 and rejects negatives, smss accepts its
    exact lower bound of 1.
    """

    def test__newreno__cwnd_guard_accepts_zero(self) -> None:
        """
        Ensure the cwnd guard accepts its exact lower boundary of 0
        (a '>= 0' guard mutated to '>= 1' or '> 0' would reject it).

        Reference: RFC 6582 §3 (partial-ACK deflation).
        """

        self.assertEqual(
            partial_cum_ack_deflate(cwnd=0, bytes_acked=0, smss=1),
            1,
            msg="cwnd=0 must be accepted and floor to 1 SMSS.",
        )

    def test__newreno__cwnd_guard_rejects_negative(self) -> None:
        """
        Ensure the cwnd guard rejects a negative value (a '>= 0' guard
        mutated to '!= 0' would wrongly accept -1).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            partial_cum_ack_deflate(cwnd=-1, bytes_acked=0, smss=1)

    def test__newreno__smss_guard_accepts_exact_lower_bound(self) -> None:
        """
        Ensure the smss guard accepts its exact lower boundary of 1
        (a '> 0' guard mutated to '> 1' would reject it).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            partial_cum_ack_deflate(cwnd=10, bytes_acked=0, smss=1),
            10,
            msg="smss=1 must be accepted.",
        )
