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
Unit tests for RcvRttState — the receiver-side RTT estimator that DRS
(Tier-3 Track R) uses for its per-RTT measurement cadence. Samples are
folded via an alpha = 1/8 EWMA and deduplicated on the echoed TSecr so a
burst of segments within one round trip yields a single sample.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__rcv_rtt.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__rcv_rtt import RcvRttState


class TestRcvRttState(TestCase):
    """
    Defaults + observe() EWMA / dedup behaviour.
    """

    def test__rcv_rtt__defaults(self) -> None:
        """
        Ensure a fresh estimator has no smoothed RTT and no recorded
        TSecr — the canonical no-sample-yet state DRS checks before
        arming its cadence gate.

        Reference: RFC 7323 §4 (RTTM via TSecr).
        """

        state = RcvRttState()
        self.assertIsNone(state.rtt_ms, msg="rtt_ms must default to None (no sample yet).")
        self.assertIsNone(state.last_tsecr, msg="last_tsecr must default to None.")

    def test__rcv_rtt__first_sample_seeds_rtt(self) -> None:
        """
        Ensure the first sample seeds the smoothed RTT directly (no
        prior value to average against) and records its TSecr.

        Reference: RFC 7323 §4 (RTTM via TSecr).
        """

        state = RcvRttState()
        state.observe(sample_ms=40, tsecr=100)
        self.assertEqual(state.rtt_ms, 40, msg="First sample must seed rtt_ms directly.")
        self.assertEqual(state.last_tsecr, 100, msg="observe must record the sampled TSecr.")

    def test__rcv_rtt__subsequent_sample_ewma(self) -> None:
        """
        Ensure a subsequent sample with a fresh TSecr folds into the
        smoothed RTT via the alpha = 1/8 EWMA
        ('(7 * old + sample) // 8').

        Reference: RFC 7323 §4 (RTTM via TSecr).
        """

        state = RcvRttState()
        state.observe(sample_ms=40, tsecr=100)
        state.observe(sample_ms=80, tsecr=200)
        # (7 * 40 + 80) // 8 == 45.
        self.assertEqual(state.rtt_ms, 45, msg="Subsequent sample must fold via the 1/8 EWMA.")

    def test__rcv_rtt__duplicate_tsecr_is_ignored(self) -> None:
        """
        Ensure a sample echoing the same TSecr as the previous one is
        ignored, so a burst of segments within a single round trip
        contributes at most one RTT sample.

        Reference: RFC 7323 §4 (RTTM via TSecr).
        """

        state = RcvRttState()
        state.observe(sample_ms=40, tsecr=100)
        state.observe(sample_ms=999, tsecr=100)
        self.assertEqual(
            state.rtt_ms,
            40,
            msg="A repeated TSecr must not contribute a second sample.",
        )


class TestRcvRttStateWindowFallback(TestCase):
    """
    observe_window() min-smoothing behaviour (no-timestamps path).
    """

    def test__rcv_rtt__window_first_sample_seeds(self) -> None:
        """
        Ensure the first window-based sample seeds the smoothed RTT
        directly.

        Reference: RFC 9293 §3.8.6 (receive window management).
        """

        state = RcvRttState()
        state.observe_window(sample_ms=50)
        self.assertEqual(state.rtt_ms, 50, msg="First window sample must seed rtt_ms.")

    def test__rcv_rtt__window_larger_sample_ignored(self) -> None:
        """
        Ensure a larger window-based sample is ignored — the fallback
        takes the minimum (Linux win_dep=1) because the window-time
        measure biases high.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux tcp_rcv_rtt_update (win_dep min).
        """

        state = RcvRttState()
        state.observe_window(sample_ms=50)
        state.observe_window(sample_ms=80)
        self.assertEqual(state.rtt_ms, 50, msg="A larger window sample must not raise rtt_ms.")

    def test__rcv_rtt__window_smaller_sample_lowers(self) -> None:
        """
        Ensure a smaller window-based sample lowers the smoothed RTT
        toward the true minimum.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux tcp_rcv_rtt_update (win_dep min).
        """

        state = RcvRttState()
        state.observe_window(sample_ms=50)
        state.observe_window(sample_ms=30)
        self.assertEqual(state.rtt_ms, 30, msg="A smaller window sample must lower rtt_ms.")
