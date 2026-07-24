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
delay-based slow-start-exit algorithm, driven end-to-end through the
wire ACK path. A session is brought to ESTABLISHED with bilateral
TSopt, the send pipe is filled with real data segments (TCP_NODELAY so
the whole window goes out rather than one Nagle-gated partial at a
time), and RTT-bearing ACKs are then streamed in. Each ACK folds a real
per-round min-RTT sample through '_process_ack_packet', so the SS->CSS
delay-increase exit, the CSS conservative cwnd growth, the CSS_ROUNDS
exhaustion into congestion avoidance, and the CSS->SS spurious-exit
recovery are all exercised via genuine segment/ACK flow — no direct
poking of the HyStart++ state to force a transition.

pytcp/tests/integration/protocols/tcp/test__tcp__session__hystart.py

ver 3.0.9
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
PEER__MSS: int = 1460
# Peer receive window in bytes. Bounds the in-flight segment count (and
# so the number of RTT samples that accumulate per HyStart++ round);
# ~24 segments is comfortably above N_RTT_SAMPLE=8.
PEER__WIN: int = 24 * PEER__MSS
PEER__TSVAL_INITIAL: int = 0x1000_0000
# Realistic baseline RTT (ms) applied to the handshake and the first
# measurement rounds, so 'lastRoundMinRTT' establishes a non-zero
# baseline rather than the 0 ms artefact of a same-tick FakeTimer
# handshake.
BASE_RTT_MS: int = 50


class TestTcpSessionHyStartPP(TcpTestCase):
    """
    Integration tests for the RFC 9406 HyStart++ slow-start-exit
    state machine, driven through the wire ACK path.
    """

    def _establish(self, *, base_rtt_ms: int = BASE_RTT_MS) -> TcpSession:
        """
        Drive an active-open handshake with bilateral TSopt and a
        realistic 'base_rtt_ms' handshake RTT, then arm the session for
        a bulk transfer: TCP_NODELAY (so the whole window fills instead
        of one Nagle-gated partial), a large cwnd / ssthresh (so
        congestion control never gates the fill), and a large buffered
        write. Returns the ESTABLISHED session with the send pipe
        already full.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=base_rtt_ms)
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            tsval=PEER__TSVAL_INITIAL,
            tsecr=self._timer.now_ms - base_rtt_ms,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._ts.send_ts

        # Bulk-transfer arming.
        session._tcp_nodelay = True
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.ssthresh = 200 * PEER__MSS
        session._cc.snd_ewn = PEER__WIN
        session.send(data=b"X" * (600 * PEER__MSS))

        # Fill the pipe: the tx_pump dribbles one segment per discrete
        # 1 ms tick, so advance in single-ms steps until the window is
        # full. Record the on-wire segment size from the first emitted
        # data segment (MSS minus the TSopt overhead).
        una_start = session._snd_seq.una
        self._advance(ms=1)
        self._seg: int = session._snd_seq.nxt - una_start
        assert self._seg > 0
        for _ in range(PEER__WIN // self._seg + 2):
            self._advance(ms=1)

        # Peer-side ACK bookkeeping the driver advances per delivered ACK.
        self._peer_ack: int = session._snd_seq.una
        self._peer_tsval: int = PEER__TSVAL_INITIAL
        return session

    def _deliver_ack(self, session: TcpSession, *, rtt_ms: int) -> None:
        """
        Spend 'rtt_ms' of virtual time (which also fires the tx_pump to
        refill the send window) and deliver one cumulative ACK that
        advances SND.UNA by one on-wire segment, carrying a TSecr that
        makes the resulting RTT sample equal to 'rtt_ms'.
        """

        self._advance(ms=rtt_ms)
        self._peer_ack = min(self._peer_ack + self._seg, session._snd_seq.nxt)
        self._peer_tsval += rtt_ms
        ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=self._peer_ack,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=self._peer_tsval,
            tsecr=self._timer.now_ms - rtt_ms,
        )
        self._drive_rx(frame=ack)

    def _drive_until(self, session: TcpSession, *, rtt_ms: int, predicate: object, max_acks: int = 400) -> bool:
        """
        Stream ACKs at a constant 'rtt_ms' until 'predicate(session)'
        returns True or 'max_acks' ACKs have been delivered. Returns
        whether the predicate fired within the budget.
        """

        assert callable(predicate)
        for _ in range(max_acks):
            self._deliver_ack(session, rtt_ms=rtt_ms)
            if predicate(session):
                return True
        return False

    def test__hystart__initial_state_is_slow_start(self) -> None:
        """
        Ensure that post-handshake the HyStart++ state is in slow-start:
        in_css is False, css_rounds_remaining is zero, and the interface
        starts below ssthresh (the slow-start regime HyStart++ governs).

        Reference: RFC 9406 §4.2 (HyStart++ state initialisation).
        """

        session = self._establish()

        self.assertFalse(
            session._cc.hystart_state.in_css,
            msg="in_css MUST be False post-handshake (start in slow-start).",
        )
        self.assertEqual(
            session._cc.hystart_state.css_rounds_remaining,
            0,
            msg="css_rounds_remaining MUST be 0 outside CSS.",
        )
        self.assertLess(
            session._cc.cwnd,
            session._cc.ssthresh,
            msg="Setup invariant: post-handshake cwnd < ssthresh (slow-start).",
        )

    def test__hystart__rtt_sample_folded_during_slow_start(self) -> None:
        """
        Ensure that ACKs carrying a fresh TSecr during slow-start fold
        the resulting RTT sample into currentRoundMinRTT and increment
        rttSampleCount, tracking the per-round minimum.

        Reference: RFC 9406 §4.2 (currentRoundMinRTT = min(...)).
        """

        session = self._establish()

        for _ in range(4):
            self._deliver_ack(session, rtt_ms=BASE_RTT_MS)

        self.assertEqual(
            session._cc.hystart_state.current_round_min_rtt_ms,
            BASE_RTT_MS,
            msg=(
                "RFC 9406 §4.2: TSecr-driven RTT samples MUST fold into "
                "currentRoundMinRTT during slow-start. Got "
                f"{session._cc.hystart_state.current_round_min_rtt_ms}, expected {BASE_RTT_MS}."
            ),
        )
        self.assertGreaterEqual(
            session._cc.hystart_state.rtt_sample_count,
            1,
            msg=f"rttSampleCount MUST be >= 1 after folds. Got {session._cc.hystart_state.rtt_sample_count}.",
        )

    def test__hystart__delay_increase_drives_ss_to_css_end_to_end(self) -> None:
        """
        Ensure that a per-round min-RTT increase, observed entirely
        through streamed wire ACKs, drives the session from slow-start
        into the Conservative Slow Start (CSS) phase: after a stable
        baseline round the round rotates so lastRoundMinRTT is set, and
        once a later round's minRTT exceeds lastRoundMinRTT + RttThresh
        with N_RTT_SAMPLE samples the algorithm enters CSS, recording
        the inflated minRTT as the CSS baseline and arming CSS_ROUNDS.

        Reference: RFC 9406 §4.2 (delay-based slow-start exit to CSS).
        """

        session = self._establish()

        # Baseline round(s) at the stable RTT so lastRoundMinRTT settles
        # at BASE_RTT_MS without tripping the exit trigger.
        self.assertTrue(
            self._drive_until(
                session,
                rtt_ms=BASE_RTT_MS,
                predicate=lambda s: s._cc.hystart_state.last_round_min_rtt_ms == BASE_RTT_MS,
                max_acks=80,
            ),
            msg="A stable baseline round must rotate and set lastRoundMinRTT to the baseline.",
        )
        self.assertFalse(
            session._cc.hystart_state.in_css,
            msg="A stable baseline round MUST NOT enter CSS.",
        )

        # Inflate the per-round min-RTT; the trigger must fire from the
        # streamed samples alone.
        inflated_rtt = BASE_RTT_MS + 40
        self.assertTrue(
            self._drive_until(
                session,
                rtt_ms=inflated_rtt,
                predicate=lambda s: s._cc.hystart_state.in_css,
                max_acks=80,
            ),
            msg="A sustained per-round RTT increase MUST drive slow-start into CSS.",
        )
        self.assertEqual(
            session._cc.hystart_state.css_baseline_min_rtt_ms,
            inflated_rtt,
            msg=(
                "CSS entry MUST record the inflated currentRoundMinRTT as the baseline. Got "
                f"{session._cc.hystart_state.css_baseline_min_rtt_ms}, expected {inflated_rtt}."
            ),
        )
        self.assertEqual(
            session._cc.hystart_state.css_rounds_remaining,
            HYSTART__CSS_ROUNDS,
            msg=(
                "CSS entry MUST arm css_rounds_remaining to CSS_ROUNDS="
                f"{HYSTART__CSS_ROUNDS}. Got {session._cc.hystart_state.css_rounds_remaining}."
            ),
        )

    def test__hystart__css_conservative_growth_slower_than_slow_start(self) -> None:
        """
        Ensure the cwnd growth per ACK in CSS is strictly slower than in
        slow-start: slow-start adds ~1 SMSS per ACK, whereas CSS adds
        min(N, SMSS) / CSS_GROWTH_DIVISOR. Measures cwnd growth across a
        fixed number of ACKs in each phase and asserts the CSS rate is
        smaller.

        Reference: RFC 9406 §4.2 (CSS cwnd growth = 1/CSS_GROWTH_DIVISOR).
        """

        session = self._establish()

        # Slow-start growth rate: cwnd delta across a handful of ACKs
        # while below ssthresh and not yet in CSS.
        ss_before = session._cc.cwnd
        for _ in range(6):
            self._deliver_ack(session, rtt_ms=BASE_RTT_MS)
        ss_growth = session._cc.cwnd - ss_before
        self.assertFalse(session._cc.hystart_state.in_css, msg="Still in slow-start for the SS-rate sample.")

        # Establish the baseline round then drive into CSS.
        self._drive_until(
            session,
            rtt_ms=BASE_RTT_MS,
            predicate=lambda s: s._cc.hystart_state.last_round_min_rtt_ms == BASE_RTT_MS,
            max_acks=80,
        )
        self.assertTrue(
            self._drive_until(
                session,
                rtt_ms=BASE_RTT_MS + 40,
                predicate=lambda s: s._cc.hystart_state.in_css,
                max_acks=80,
            ),
            msg="Setup: must reach CSS before measuring CSS growth.",
        )

        # CSS growth rate: cwnd delta across the same number of ACKs
        # while in CSS (hold the inflated RTT steady so it neither
        # resumes SS nor exhausts CSS mid-measurement).
        css_before = session._cc.cwnd
        for _ in range(6):
            self._deliver_ack(session, rtt_ms=BASE_RTT_MS + 40)
            if not session._cc.hystart_state.in_css:
                break
        css_growth = session._cc.cwnd - css_before

        self.assertGreater(
            ss_growth,
            css_growth,
            msg=(
                "RFC 9406 §4.2: CSS cwnd growth per ACK MUST be slower than "
                f"slow-start. Got ss_growth={ss_growth}, css_growth={css_growth}."
            ),
        )

    def test__hystart__sustained_delay_exhausts_css_and_enters_ca(self) -> None:
        """
        Ensure that when the elevated per-round min-RTT persists for
        CSS_ROUNDS rounds, HyStart++ exits CSS into congestion avoidance
        by setting ssthresh = cwnd (rather than resuming slow-start).

        Reference: RFC 9406 §4.2 (CSS_ROUNDS exhausted -> ssthresh = cwnd).
        """

        session = self._establish()
        self._drive_until(
            session,
            rtt_ms=BASE_RTT_MS,
            predicate=lambda s: s._cc.hystart_state.last_round_min_rtt_ms == BASE_RTT_MS,
            max_acks=80,
        )
        inflated_rtt = BASE_RTT_MS + 40
        self.assertTrue(
            self._drive_until(
                session,
                rtt_ms=inflated_rtt,
                predicate=lambda s: s._cc.hystart_state.in_css,
                max_acks=80,
            ),
            msg="Setup: must reach CSS before exhausting it.",
        )

        # Hold the elevated RTT steady (>= baseline so it never resumes
        # SS) until CSS exhausts and the algorithm enters CA.
        self.assertTrue(
            self._drive_until(
                session,
                rtt_ms=inflated_rtt,
                predicate=lambda s: not s._cc.hystart_state.in_css,
                max_acks=400,
            ),
            msg="Sustained delay across CSS_ROUNDS MUST exit CSS.",
        )
        self.assertLessEqual(
            session._cc.ssthresh,
            session._cc.cwnd,
            msg=(
                "RFC 9406 §4.2 CSS exhaustion MUST enter CA by pinning ssthresh <= cwnd. Got "
                f"ssthresh={session._cc.ssthresh}, cwnd={session._cc.cwnd}."
            ),
        )
        self.assertEqual(
            session._cc.hystart_state.css_rounds_remaining,
            0,
            msg="css_rounds_remaining MUST be 0 after CSS exhaustion.",
        )

    def test__hystart__rtt_recovery_resumes_slow_start_from_css(self) -> None:
        """
        Ensure the CSS->SS spurious-exit recovery fires when a later
        round's min-RTT drops back below the CSS-entry baseline: the
        algorithm clears CSS and resumes slow-start WITHOUT pinning
        ssthresh = cwnd (the delay increase was transient, not real
        congestion).

        Reference: RFC 9406 §4.2 (CSS->SS spurious-exit recovery).
        """

        session = self._establish()
        self._drive_until(
            session,
            rtt_ms=BASE_RTT_MS,
            predicate=lambda s: s._cc.hystart_state.last_round_min_rtt_ms == BASE_RTT_MS,
            max_acks=80,
        )
        self.assertTrue(
            self._drive_until(
                session,
                rtt_ms=BASE_RTT_MS + 40,
                predicate=lambda s: s._cc.hystart_state.in_css,
                max_acks=80,
            ),
            msg="Setup: must reach CSS before testing recovery.",
        )
        ssthresh_at_css = session._cc.ssthresh

        # RTT recovers below the CSS baseline -> resume slow-start.
        recovered_rtt = BASE_RTT_MS - 20
        self.assertTrue(
            self._drive_until(
                session,
                rtt_ms=recovered_rtt,
                predicate=lambda s: not s._cc.hystart_state.in_css,
                max_acks=80,
            ),
            msg="A per-round RTT drop below the CSS baseline MUST resume slow-start.",
        )
        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_at_css,
            msg=(
                "CSS->SS recovery MUST NOT pin ssthresh = cwnd (that is the "
                "exhaustion path); ssthresh must be unchanged. Got "
                f"{session._cc.ssthresh}, expected {ssthresh_at_css}."
            ),
        )
        self.assertEqual(
            session._cc.hystart_state.css_rounds_remaining,
            0,
            msg="CSS resume MUST zero css_rounds_remaining.",
        )

    def test__hystart__stable_rtt_does_not_trigger_css(self) -> None:
        """
        Ensure that when the per-round min-RTT is stable across many
        rounds (no significant inflation), HyStart++ does NOT enter CSS.
        Negative control: the algorithm must not false-positive on a
        stable link, and lastRoundMinRTT must settle at the stable value.

        Reference: RFC 9406 §4.2 (delay-increase trigger gate).
        """

        session = self._establish()

        # Many rounds' worth of ACKs at a rock-steady RTT.
        for _ in range(200):
            self._deliver_ack(session, rtt_ms=BASE_RTT_MS)
            self.assertFalse(
                session._cc.hystart_state.in_css,
                msg=("RFC 9406 §4.2 negative control: stable RTT across many " "rounds MUST NOT enter CSS."),
            )

        self.assertEqual(
            session._cc.hystart_state.last_round_min_rtt_ms,
            BASE_RTT_MS,
            msg=(
                "A stable link's lastRoundMinRTT must settle at the stable "
                f"RTT. Got {session._cc.hystart_state.last_round_min_rtt_ms}, expected {BASE_RTT_MS}."
            ),
        )
        # The infinity sentinel must never leak into a settled baseline.
        self.assertNotEqual(
            session._cc.hystart_state.last_round_min_rtt_ms,
            HYSTART__RTT_INFINITY,
            msg="lastRoundMinRTT must be a real sample after multiple rounds, not the infinity sentinel.",
        )
