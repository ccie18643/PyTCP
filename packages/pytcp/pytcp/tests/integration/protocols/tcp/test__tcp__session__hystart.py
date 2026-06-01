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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains integration tests for the RFC 9406 HyStart++
delay-based slow-start-exit algorithm. Drives a TCP session into
slow-start with bilateral TSopt enabled, injects RTT-bearing ACKs
that simulate either stable or inflating per-round min-RTT, and
verifies the HyStart++ state machine transitions correctly between
slow-start and CSS phases.

pytcp/tests/integration/protocols/tcp/test__tcp__session__hystart.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__hystart import (
    HYSTART__CSS_ROUNDS,
    HYSTART__RTT_INFINITY,
)
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000
PEER__WIN: int = 64240
PEER__MSS: int = 1460
PEER__TSVAL_INITIAL: int = 0x1234_5678


class TestTcpSessionHyStartPP(TcpTestCase):
    """
    Integration tests for the RFC 9406 HyStart++ slow-start-exit
    state machine. Each test drives a session into slow-start
    with bilateral TSopt, then injects ACKs whose TSecr
    timestamps cause specific RTT samples to be folded into
    the HyStart++ state — verifying the SS->CSS / CSS->SS /
    CSS-rounds-exhaustion transitions happen at the right
    moments.
    """

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive an active-open handshake with bilateral TSopt."""

        session = self._make_active_session(iss=iss)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss,
            ack=iss + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            tsval=peer_tsval,
            tsecr=self._timer.now_ms,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._ts.send_ts
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__hystart__initial_state_is_slow_start(self) -> None:
        """
        Ensure that post-handshake the HyStart++ state is in
        slow-start: in_css is False, css_rounds_remaining is
        zero, and lastRoundMinRTT is still at the infinity
        sentinel (no round has rotated yet). The handshake's
        own SYN-ACK->ACK exchange may fold one RTT sample
        into currentRoundMinRTT — that's expected and benign.

        Reference: RFC 9406 §4.2 (HyStart++ state initialisation).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        self.assertFalse(
            session._cc.hystart_state.in_css,
            msg="in_css MUST be False post-handshake (start in slow-start).",
        )
        self.assertEqual(
            session._cc.hystart_state.css_rounds_remaining,
            0,
            msg="css_rounds_remaining MUST be 0 outside CSS.",
        )
        self.assertEqual(
            session._cc.hystart_state.last_round_min_rtt_ms,
            HYSTART__RTT_INFINITY,
            msg=("lastRoundMinRTT MUST still be infinity sentinel " "post-handshake — no round boundary has rotated."),
        )

    def test__hystart__rtt_sample_folded_during_slow_start(self) -> None:
        """
        Ensure that an ACK carrying a fresh TSecr during
        slow-start folds the resulting RTT sample into
        currentRoundMinRTT and increments rttSampleCount.

        Reference: RFC 9406 §4.2 (currentRoundMinRTT = min(...)).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )
        self.assertLess(
            session._cc.cwnd,
            session._cc.ssthresh,
            msg="Setup invariant: post-handshake cwnd < ssthresh (slow-start).",
        )

        # Send data and receive a TSecr-bearing ACK with 20 ms RTT.
        # The cum-ACK that drains the SYN-bytes triggers a
        # round-boundary rotation (resetting rtt_sample_count to 0
        # and current_round_min_rtt_ms to the infinity sentinel),
        # then the TSecr fold runs against the freshly-rotated
        # round. So after this single ACK we expect count==1 and
        # current==20 ms.
        session.send(data=b"X" * 100)
        self._advance(ms=1)  # tx fires
        self._advance(ms=20)  # spend 20 ms RTT
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=session._snd_seq.max,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL + 20,
            tsecr=self._timer.now_ms - 20,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._cc.hystart_state.current_round_min_rtt_ms,
            20,
            msg=(
                "RFC 9406 §4.2: TSecr-driven RTT sample MUST "
                "fold into currentRoundMinRTT during slow-start. "
                f"Got {session._cc.hystart_state.current_round_min_rtt_ms}, "
                "expected 20."
            ),
        )
        self.assertGreaterEqual(
            session._cc.hystart_state.rtt_sample_count,
            1,
            msg=(
                "rttSampleCount MUST be >= 1 after a fold (post-"
                "rotation it is 0; this fold increments it). Got "
                f"{session._cc.hystart_state.rtt_sample_count}."
            ),
        )

    def test__hystart__delay_increase_triggers_ss_to_css_transition(self) -> None:
        """
        Ensure that the session's
        '_hystart_check_phase_transition' helper transitions
        the state machine to CSS when the §4.2 trigger fires:
        currentRoundMinRTT exceeds lastRoundMinRTT + RttThresh
        with N_RTT_SAMPLE samples accumulated. Pre-populates
        the state directly to bypass the multi-segment-burst
        timing required to accumulate 8 in-round samples
        through normal cum-ACK flow; the helper-call wiring is
        what this test pins.

        Reference: RFC 9406 §4.2 (SS->CSS transition).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        # Pre-populate state with: round 1 baseline minRTT 50,
        # round 2 inflated minRTT 80 (delta 30 ms >> RttThresh
        # of 4 ms), N_RTT_SAMPLE samples accumulated.
        session._cc.hystart_state.last_round_min_rtt_ms = 50
        session._cc.hystart_state.current_round_min_rtt_ms = 80
        session._cc.hystart_state.rtt_sample_count = 8
        session._cc.hystart_state.in_css = False
        self.assertFalse(
            session._cc.hystart_state.in_css,
            msg="Setup precondition: not yet in CSS.",
        )

        # Trigger the phase-transition check.
        session._hystart_check_phase_transition()

        self.assertTrue(
            session._cc.hystart_state.in_css,
            msg=(
                "RFC 9406 §4.2 SS->CSS: with current_min=80, "
                "last_min=50, samples=8, the trigger MUST fire. "
                f"Got in_css={session._cc.hystart_state.in_css}."
            ),
        )
        self.assertEqual(
            session._cc.hystart_state.css_baseline_min_rtt_ms,
            80,
            msg=(
                "CSS entry MUST record currentRoundMinRTT (80) "
                "as the baseline. Got "
                f"{session._cc.hystart_state.css_baseline_min_rtt_ms}."
            ),
        )
        self.assertEqual(
            session._cc.hystart_state.css_rounds_remaining,
            HYSTART__CSS_ROUNDS,
            msg=(
                "CSS entry MUST initialise css_rounds_remaining "
                f"to CSS_ROUNDS={HYSTART__CSS_ROUNDS}; got "
                f"{session._cc.hystart_state.css_rounds_remaining}."
            ),
        )

    def test__hystart__css_resume_to_slow_start_on_rtt_recovery(self) -> None:
        """
        Ensure the CSS->SS spurious-exit recovery fires when
        the current round's minRTT drops below the CSS-entry
        baseline. Pre-populates the state in CSS with a high
        baseline; one fold below the baseline triggers the
        resume-slow-start path.

        Reference: RFC 9406 §4.2 (CSS->SS spurious-exit recovery).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        # Pre-populate: in CSS with baseline 80 ms; current
        # round saw a fold at 60 ms (below baseline) with
        # enough samples.
        session._cc.hystart_state.in_css = True
        session._cc.hystart_state.css_baseline_min_rtt_ms = 80
        session._cc.hystart_state.css_rounds_remaining = 3
        session._cc.hystart_state.current_round_min_rtt_ms = 60
        session._cc.hystart_state.rtt_sample_count = 8

        session._hystart_check_phase_transition()

        self.assertFalse(
            session._cc.hystart_state.in_css,
            msg=(
                "RFC 9406 §4.2 CSS->SS resume: current=60 < "
                "baseline=80 with samples=8 MUST clear in_css. "
                f"Got in_css={session._cc.hystart_state.in_css}."
            ),
        )
        self.assertEqual(
            session._cc.hystart_state.css_rounds_remaining,
            0,
            msg=(
                "CSS resume MUST zero css_rounds_remaining; got " f"{session._cc.hystart_state.css_rounds_remaining}."
            ),
        )

    def test__hystart__stable_rtt_does_not_trigger_css(self) -> None:
        """
        Ensure that when per-round min-RTT is stable across
        multiple rounds (no significant inflation), HyStart++
        does NOT trigger the SS->CSS transition. This is the
        negative-control invariant: the algorithm must not
        false-positive on stable links.

        Reference: RFC 9406 §4.2 (delay-increase trigger gate).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        peer_tsval = PEER__TSVAL_INITIAL

        # Drive 3 rounds with stable 50 ms RTT (24 ACKs).
        stable_rtt = 50
        for round_idx in range(3):
            for _ in range(8):
                session.send(data=b"X" * PEER__MSS)
                self._advance(ms=1)
                self._advance(ms=stable_rtt)
                peer_tsval += stable_rtt
                peer_ack = build_tcp4(
                    sport=PEER__PORT,
                    dport=STACK__PORT,
                    seq=PEER__ISS + 1,
                    ack=session._snd_seq.max,
                    flags=("ACK",),
                    win=PEER__WIN,
                    tsval=peer_tsval,
                    tsecr=self._timer.now_ms - stable_rtt,
                )
                self._drive_rx(frame=peer_ack)

        self.assertFalse(
            session._cc.hystart_state.in_css,
            msg=(
                "RFC 9406 §4.2 negative control: stable RTT "
                "across multiple rounds MUST NOT trigger "
                "SS->CSS. Got "
                f"in_css={session._cc.hystart_state.in_css}."
            ),
        )
