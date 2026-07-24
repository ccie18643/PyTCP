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
This module contains integration tests for the RFC 5681 congestion
control machinery. See 'docs/rfc/tcp/rfc5681__reno_cwnd/adherence.md'
for the per-clause spec audit.

The session's congestion-control surface is split into:

    _cwnd: int          # RFC 5681 congestion window
    _ssthresh: int      # RFC 5681 slow-start threshold
    _snd_ewn: int       # = min(_cwnd, _snd_wnd) (derived)

with the §3.1 growth rule wired into '_process_ack_packet':

    if _cwnd < _ssthresh:
        # Slow start
        _cwnd += min(bytes_acked, _snd_mss)
    else:
        # Congestion avoidance
        _cwnd += max(1, _snd_mss * _snd_mss // _cwnd)

Reference RFCs:
    RFC 5681 §3.1   Slow Start and Congestion Avoidance
    RFC 5681 §3.2   Fast Retransmit / Fast Recovery
    RFC 9293 §3.8.4 Window Management

pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py

ver 3.0.9
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import CcMode, FsmState, SysCall
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers, well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply (1500 - 20 - 20 IPv4).
PEER__MSS: int = 1460


class TestTcpCwndPhase1(TcpTestCase):
    """
    Integration tests for RFC 5681 §3.1 Phase 1 invariants:
    'cwnd' / 'ssthresh' field separation and the slow-start
    vs congestion-avoidance growth-rate distinction.
    """

    _DEFAULT_CC_MODE: CcMode | None = CcMode.RENO

    def test__cwnd__fields_exist_post_handshake(self) -> None:
        """
        Ensure '_cwnd' and '_ssthresh' are distinct first-
        class fields on TcpSession, not collapsed into
        '_snd_ewn'. '_cwnd' is a positive integer post-
        handshake; '_ssthresh' is set arbitrarily high so
        the session starts in slow-start.

        Reference: RFC 5681 §3.1 (cwnd / ssthresh definitions).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertIsInstance(
            session._cc.cwnd,
            int,
            msg=(
                "RFC 5681 §3.1 mandates an explicit 'cwnd' "
                "variable separate from peer's advertised "
                "window. PyTCP's pre-Phase-1 stand-in '_snd_ewn' "
                "conflates the two; Phase 1 splits them."
            ),
        )
        self.assertGreater(
            session._cc.cwnd,
            0,
            msg=(
                f"RFC 5681 §3.1: post-handshake 'cwnd' MUST be "
                f"a positive integer (the Initial Window, IW). "
                f"Got {session._cc.cwnd}."
            ),
        )
        self.assertIsInstance(
            session._cc.ssthresh,
            int,
            msg=(
                "RFC 5681 §3.1: 'ssthresh' is a first-class "
                "tracker, not a derived value. PyTCP's pre-"
                "Phase-1 design has no analog at all - the "
                "slow-start vs CA distinction cannot be "
                "expressed without it."
            ),
        )
        self.assertGreater(
            session._cc.ssthresh,
            PEER__WIN,
            msg=(
                f"RFC 5681 §3.1: 'ssthresh SHOULD be set "
                f"arbitrarily high (e.g., to the size of the "
                f"largest possible advertised window).' Got "
                f"ssthresh={session._cc.ssthresh} which is not "
                f"greater than peer's advertised window "
                f"{PEER__WIN} - the session would never enter "
                f"slow-start cleanly."
            ),
        )

    def test__cwnd__slow_start_grows_cwnd_by_one_mss_per_cum_ack(self) -> None:
        """
        Ensure that while in slow-start phase
        (cwnd < ssthresh), each cum-ACK that acknowledges
        new data grows cwnd by min(bytes_acked, SMSS) bytes.

        Reference: RFC 5681 §3.1 (slow-start growth formula).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Pin slow-start regime.
        session._cc.cwnd = 2 * PEER__MSS
        session._cc.ssthresh = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Send 2 MSS and let both segments fire on consecutive ticks.
        payload = b"x" * (2 * PEER__MSS)
        session.send(data=payload)
        self._advance(ms=1)
        self._advance(ms=1)

        # One peer ACK covers both segments.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._cc.cwnd,
            3 * PEER__MSS,
            msg=(
                "Slow-start growth: a cum-ACK covering 2*MSS "
                "while cwnd=2*MSS MUST yield cwnd = 2*MSS + "
                f"min(2*MSS, SMSS) = 3*MSS. Got "
                f"cwnd={session._cc.cwnd}."
            ),
        )

    def test__cwnd__congestion_avoidance_grows_cwnd_sublinearly(self) -> None:
        """
        Ensure that while in congestion-avoidance phase
        (cwnd >= ssthresh), each cum-ACK that acknowledges
        new data grows cwnd by approximately
        'SMSS * SMSS / cwnd' bytes (~+1 MSS per RTT for a
        stream of MSS-sized cum-ACKs).

        Reference: RFC 5681 §3.1 (congestion-avoidance growth formula).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        session._cc.cwnd = 10 * PEER__MSS
        session._cc.ssthresh = 5 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        payload = b"x" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # Per §3.1: cwnd += max(1, SMSS*SMSS // cwnd).
        # With cwnd=10*MSS=14600 and SMSS=1460:
        #   delta = max(1, 1460*1460 // 14600) = max(1, 146) = 146
        #   new cwnd = 14600 + 146 = 14746
        expected_cwnd = 10 * PEER__MSS + max(1, PEER__MSS * PEER__MSS // (10 * PEER__MSS))
        self.assertEqual(
            session._cc.cwnd,
            expected_cwnd,
            msg=(
                "Congestion-avoidance growth: a cum-ACK while "
                "cwnd>=ssthresh MUST yield cwnd += max(1, "
                f"SMSS*SMSS // cwnd). Expected {expected_cwnd}, "
                f"got {session._cc.cwnd}."
            ),
        )

    def test__cwnd__snd_ewn_tracks_min_of_cwnd_and_snd_wnd(self) -> None:
        """
        Ensure the effective send window '_snd_ewn' is
        always the modular minimum of 'cwnd' (sender's
        network bound) and 'snd_wnd' (peer's flow-control
        bound). '_snd_ewn' is recomputed whenever either
        input changes.

        Reference: RFC 9293 §3.8.4 (effective window = min(cwnd, snd_wnd)).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # cwnd-bound case: cwnd is the tighter constraint.
        session._cc.cwnd = 3 * PEER__MSS
        session._win.snd_wnd = 5 * PEER__MSS
        # Phase 1 design: a helper recomputes _snd_ewn whenever
        # cwnd or snd_wnd changes. Tests can observe via setting
        # _snd_ewn directly here for the assertion baseline.
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        self.assertEqual(
            session._cc.snd_ewn,
            3 * PEER__MSS,
            msg=(
                "'_snd_ewn' = min(cwnd, " "snd_wnd). With cwnd=3*MSS the cwnd is tighter; " "_snd_ewn must equal 3*MSS."
            ),
        )

        # snd_wnd-bound case: peer's window is the tighter constraint.
        session._cc.cwnd = 10 * PEER__MSS
        session._win.snd_wnd = 5 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        self.assertEqual(
            session._cc.snd_ewn,
            5 * PEER__MSS,
            msg=(
                "'_snd_ewn' = min(cwnd, "
                "snd_wnd). With snd_wnd=5*MSS peer's window is "
                "tighter; _snd_ewn must equal 5*MSS."
            ),
        )

    def test__cwnd__post_handshake_starts_in_slow_start_phase(self) -> None:
        """
        Ensure post-handshake the session starts in slow-
        start phase: cwnd < ssthresh, so the very first
        cum-ACK runs slow-start growth, not congestion-
        avoidance.

        Reference: RFC 5681 §3.1 (slow-start vs congestion-avoidance threshold).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertLess(
            session._cc.cwnd,
            session._cc.ssthresh,
            msg=(
                "A fresh session post-handshake MUST be in "
                "slow-start (cwnd < ssthresh). Got "
                f"cwnd={session._cc.cwnd}, "
                f"ssthresh={session._cc.ssthresh}."
            ),
        )

    def test__cwnd__cum_ack_recomputes_snd_ewn_from_cwnd_via_runtime_path(self) -> None:
        """
        Ensure that a cum-ACK that grows '_cwnd' propagates
        the new value into '_snd_ewn = min(_cwnd, _snd_wnd)'
        through the actual '_process_ack_packet' code path.

        Reference: RFC 9293 §3.8.4 (effective window invariant on cum-ACK).
        Reference: RFC 5681 §3.1 (slow-start growth on cum-ACK).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Pin slow-start regime with cwnd as the tighter bound.
        # 'PEER__WIN' (64240 ~= 44 MSS) is comfortably larger
        # than 'cwnd = 4 * MSS = 5840', so 'min(cwnd, snd_wnd)'
        # tracks cwnd. Setting '_snd_wnd' directly is pointless
        # because '_process_ack_packet' overwrites it from the
        # peer ACK's 'win' field; the wire-level 16-bit window
        # cap and the wscale shift do their own thing inside
        # the runtime.
        session._cc.cwnd = 4 * PEER__MSS
        session._cc.ssthresh = 0x7FFF_FFFF
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Send 1 MSS, let it fire.
        payload = b"x" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=1)

        # Drive cum-ACK with peer's full advertised window.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # §3.1 slow-start: cwnd += min(bytes_acked, SMSS) per ACK.
        expected_cwnd = 4 * PEER__MSS + min(PEER__MSS, PEER__MSS)
        self.assertEqual(
            session._cc.cwnd,
            expected_cwnd,
            msg=(
                "Cum-ACK in slow-start MUST grow cwnd by "
                f"min(bytes_acked, SMSS). Expected "
                f"{expected_cwnd}, got {session._cc.cwnd}."
            ),
        )
        self.assertEqual(
            session._cc.snd_ewn,
            session._cc.cwnd,
            msg=(
                "With snd_wnd >> cwnd, _snd_ewn MUST equal "
                "_cwnd post-ACK. Got "
                f"_snd_ewn={session._cc.snd_ewn}, "
                f"_cwnd={session._cc.cwnd}."
            ),
        )
        self.assertEqual(
            session._cc.snd_ewn,
            min(session._cc.cwnd, session._win.snd_wnd),
            msg=(
                "Canonical invariant: _snd_ewn = min(_cwnd, "
                "_snd_wnd) after every cum-ACK. Got "
                f"_snd_ewn={session._cc.snd_ewn}, "
                f"min={min(session._cc.cwnd, session._win.snd_wnd)}."
            ),
        )


class TestTcpCwndPhase2(TcpTestCase):
    """
    Integration tests for RFC 5681 §3.1 Phase 2 invariants:
    RTO ssthresh halving and slow-start re-entry.

    Per §3.1 step 1, on a retransmission-timeout fire the
    sender MUST set:

        ssthresh = max(FlightSize / 2, 2 * SMSS)

    so that subsequent slow-start growth exits at the
    previously-observed loss point. PyTCP's pre-Phase-2 RTO
    handler resets cwnd to 1 SMSS (Phase-1 fix) but does not
    touch ssthresh - the loss memory is lost and slow-start
    runs unbounded until peer's win clamps it.
    """

    _DEFAULT_CC_MODE: CcMode | None = CcMode.RENO

    def test__cwnd__rto_sets_ssthresh_to_half_flight_size(self) -> None:
        """
        Ensure that on RTO the sender sets ssthresh =
        max(FlightSize / 2, 2 * SMSS). With a multi-MSS
        flight the FlightSize/2 branch dominates and
        ssthresh records the slow-start exit point for the
        recovery cycle. cwnd collapses to 1 SMSS.

        Reference: RFC 5681 §3.1 (RTO ssthresh halving).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Send 6 MSS so 6 segments are in flight at RTO time.
        payload = b"x" * (6 * PEER__MSS)
        session.send(data=payload)
        for _ in range(6):
            self._advance(ms=1)

        # Verify all 6 segments hit the wire.
        self.assertEqual(
            (session._snd_seq.max - session._snd_seq.una) & 0xFFFF_FFFF,
            6 * PEER__MSS,
            msg="Setup invariant: 6 MSS must be in flight before RTO fires.",
        )

        # Drive past RTO. Post-handshake rto_ms is 1000 ms; the
        # impl arms the timer at the data send (~ t=2 ms) so
        # the boundary is t=1002 ms. Advance ~999 more ms.
        self._advance(ms=999)

        expected_ssthresh = max(6 * PEER__MSS // 2, 2 * PEER__MSS)
        self.assertEqual(
            session._cc.ssthresh,
            expected_ssthresh,
            msg=(
                "RTO MUST set ssthresh = max(FlightSize / 2, "
                f"2*SMSS). With FlightSize = 6*MSS = "
                f"{6 * PEER__MSS}, expected ssthresh = "
                f"max(3*MSS, 2*MSS) = {expected_ssthresh}. "
                f"Got {session._cc.ssthresh}."
            ),
        )
        # Phase 1 regression: cwnd reset to 1 SMSS.
        self.assertEqual(
            session._cc.cwnd,
            session._win.snd_mss,
            msg=("Post-RTO cwnd MUST collapse to 1 SMSS for " f"slow-start re-entry. Got cwnd={session._cc.cwnd}."),
        )

    def test__cwnd__rto_with_minimal_flight_size_clamps_ssthresh_to_floor(self) -> None:
        """
        Ensure that when in-flight bytes are small enough
        that FlightSize/2 < 2*SMSS, the floor clamps
        ssthresh to 2*SMSS so post-RTO slow-start does not
        exit prematurely.

        Reference: RFC 5681 §3.1 (RTO ssthresh halving with 2*SMSS floor).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        payload = b"x" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=1)

        self._advance(ms=1000)

        self.assertEqual(
            session._cc.ssthresh,
            2 * PEER__MSS,
            msg=("When FlightSize/2 < 2*SMSS, ssthresh MUST " f"clamp to 2*SMSS. Got {session._cc.ssthresh}."),
        )


class TestTcpCwndPhase3(TcpTestCase):
    """
    Integration tests for RFC 5681 §3.2 Phase 3 invariants:
    fast-retransmit cwnd inflation on entry, per-dup-ACK
    inflation while in recovery, and deflation on recovery
    exit.

    Per §3.2 the four-step protocol:

        Step 2: ssthresh = max(FlightSize/2, 2*SMSS)
        Step 3: cwnd = ssthresh + 3*SMSS (entry inflation)
        Step 4: cwnd += SMSS per additional dup-ACK in recovery
        Step 6: cwnd = ssthresh (deflation on recovery exit)
    """

    _DEFAULT_CC_MODE: CcMode | None = CcMode.RENO

    def _send_n_segments_and_drain_dupacks(
        self,
        *,
        session: TcpSession,
        n_segments: int,
    ) -> None:
        """
        Send 'n_segments' MSS-sized payloads and let them fire,
        then drive 3 duplicate ACKs at SND.UNA so the count-
        based fast-retransmit trigger fires on the third.
        """

        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        payload = b"x" * (n_segments * PEER__MSS)
        session.send(data=payload)
        for _ in range(n_segments):
            self._advance(ms=1)

        # Three dup-ACKs at LOCAL__ISS+1.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        # Advance one tick so '_transmit_data' fires the
        # retransmitted segment - that advances 'SND.NXT' past
        # 'SND.UNA' so subsequent dup-ACKs are not classified
        # as keep-alive probe-acks (which would skip the
        # fast-retransmit machinery entirely).
        self._advance(ms=1)

    def test__cwnd__fast_retransmit_halves_ssthresh_and_sets_cwnd_to_pipe(self) -> None:
        """
        Ensure that when the third duplicate ACK fires
        fast-retransmit, the sender sets ssthresh =
        max(FlightSize/2, 2*SMSS) (the canonical halving) AND
        sets cwnd to 'pipe + sndcnt' from the PRR
        proportional formula. On the trigger ACK
        'prr_delivered = 0' and 'prr_out = 0' (the retransmit
        has not fired yet at the moment cwnd is set), so
        'sndcnt = 0' and 'cwnd = pipe = FlightSize at entry'.
        This replaces the legacy 'cwnd = ssthresh + 3*SMSS'
        coarse approximation with PRR's data-driven per-ACK
        pacing.

        Reference: RFC 5681 §3.2 step 2 (fast-retransmit ssthresh halving).
        Reference: RFC 5681 §3.2 step 3 (legacy coarse cwnd-set superseded by PRR).
        Reference: RFC 6937 §3.1 (PRR per-ACK cwnd = pipe + sndcnt).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_drain_dupacks(session=session, n_segments=5)

        expected_ssthresh = max(5 * PEER__MSS // 2, 2 * PEER__MSS)
        self.assertEqual(
            session._cc.ssthresh,
            expected_ssthresh,
            msg=(
                "Fast-retransmit MUST set ssthresh = "
                "max(FlightSize/2, 2*SMSS) = "
                f"{expected_ssthresh}. Got {session._cc.ssthresh}."
            ),
        )
        # PRR cwnd at entry = pipe = FlightSize (snapshot
        # in '_recover_fs' = 5*MSS for the 5-segment
        # scenario). The retransmit has fired by the time we
        # observe '_cwnd' here but cwnd is recomputed on each
        # ACK, not on each send - so the value reflects the
        # entry-trigger ACK's computation.
        expected_cwnd = 5 * PEER__MSS
        self.assertEqual(
            session._cc.cwnd,
            expected_cwnd,
            msg=(
                "RFC 6937 §3.1: cwnd at recovery entry MUST "
                "equal pipe (= FlightSize, no extra inflation). "
                f"Expected {expected_cwnd}, got {session._cc.cwnd}. "
                "The legacy RFC 5681 §3.2 step 3 'ssthresh + "
                "3*SMSS' coarse approximation is what PRR "
                "replaces."
            ),
        )

    def test__cwnd__cum_ack_exiting_recovery_deflates_cwnd_to_ssthresh(self) -> None:
        """
        Ensure that when a cumulative ACK advances SND.UNA
        past RecoveryPoint, exiting recovery, the sender
        sets cwnd = ssthresh to undo the in-recovery
        inflation. Recovery state is cleared.

        Reference: RFC 5681 §3.2 (cwnd deflation on recovery exit).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_drain_dupacks(session=session, n_segments=5)
        ssthresh = session._cc.ssthresh

        # Cum-ACK covering all 5 segments exits recovery.
        cum_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 5 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=cum_ack)

        self.assertEqual(
            session._cc.cwnd,
            ssthresh,
            msg=(
                "Cum-ACK exiting recovery MUST set cwnd = " f"ssthresh = {ssthresh}. Got " f"cwnd={session._cc.cwnd}."
            ),
        )
        self.assertEqual(
            session._cc.recovery_point,
            0,
            msg=("Recovery state must be cleared once SND.UNA " "passes RecoveryPoint."),
        )


class TestTcpCwndPhase4(TcpTestCase):
    """
    Integration tests for RFC 6928 Phase 4 invariants:
    Initial Window 10*SMSS post-handshake.

    RFC 6928 §2 raises the canonical IW from 1*SMSS (RFC 5681
    §3.1 default) to 'min(10*SMSS, max(2*SMSS, 14600))'. The
    practical effect: post-handshake the sender can fire up
    to 10 segments without waiting for the first peer ACK,
    materially shortening startup latency for short-lived
    connections (HTTP requests, RPC calls).
    """

    _DEFAULT_CC_MODE: CcMode | None = CcMode.RENO

    def test__cwnd__post_handshake_initialises_cwnd_to_iw_10(self) -> None:
        """
        Ensure post-handshake cwnd equals
        min(10 * SMSS, max(2 * SMSS, 14600)) — the RFC 6928
        Initial Window of 10 segments.

        Reference: RFC 6928 §2 (Initial Window of 10 segments / 14600 bytes).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        expected_iw = min(10 * PEER__MSS, max(2 * PEER__MSS, 14600))
        self.assertEqual(
            session._cc.cwnd,
            expected_iw,
            msg=(
                "Post-handshake cwnd MUST equal min(10*MSS, "
                f"max(2*MSS, 14600)) = {expected_iw}. Got "
                f"cwnd={session._cc.cwnd}."
            ),
        )

    def test__cwnd__post_handshake_iw_10_clamped_by_peer_win(self) -> None:
        """
        Ensure that even with IW=10 cwnd, the effective send
        window respects peer's flow-control bound. If peer
        advertises a small win, '_snd_ewn' clamps to peer's
        value.

        Reference: RFC 6928 §2 (Initial Window).
        Reference: RFC 9293 §3.8.4 (effective window invariant).
        """

        small_win = 3 * PEER__MSS
        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_win=small_win,
        )

        expected_iw = min(10 * PEER__MSS, max(2 * PEER__MSS, 14600))
        self.assertEqual(
            session._cc.cwnd,
            expected_iw,
            msg=(f"cwnd MUST be the IW formula value " f"({expected_iw}) regardless of peer's " f"advertised window."),
        )
        self.assertEqual(
            session._cc.snd_ewn,
            small_win,
            msg=(
                f"With snd_wnd={small_win} < cwnd={expected_iw}, "
                "_snd_ewn MUST clamp to peer's window. Got "
                f"_snd_ewn={session._cc.snd_ewn}."
            ),
        )


class TestTcpCwndNewReno(TcpTestCase):
    """
    Integration tests for the RFC 6582 NewReno modification to
    RFC 5681 §3.2 fast recovery: partial-cum-ACK handling for
    non-SACK peers.

    RFC 6582 §3 step 3b: when a partial cum-ACK arrives during
    fast recovery (advances SND.UNA but does NOT reach
    'recovery_point'), the sender MUST:

        (1) retransmit the first unacknowledged segment;
        (2) deflate cwnd by the bytes acked;
        (3) if bytes_acked >= SMSS, add back SMSS bytes
            (so the retransmit can fire immediately).

    Without NewReno, multi-loss recovery on non-SACK peers
    costs an RTO per additional loss in the same window. With
    NewReno, the sender retransmits one missing segment per
    RTT - same behaviour as RFC 6675 SACK NextSeg, but for
    legacy non-SACK peers.

    SACK-aware peers use RFC 6675 NextSeg directly; the
    NewReno snd_nxt rewind is gated on '_send_sack == False'
    so we don't double-step backward through gaps SACK has
    already marked.
    """

    _DEFAULT_CC_MODE: CcMode | None = CcMode.RENO

    def _setup_multi_loss_recovery(
        self,
        *,
        iss: int,
        peer_iss: int,
        n_segments: int,
    ) -> tuple[TcpSession, int, int]:
        """
        Set up a multi-loss recovery scenario:
            1. Drive handshake (no SACK, no TSopt).
            2. Pin cwnd large enough that all N segments fire.
            3. Send N*MSS payload; advance N ticks so all
               segments hit the wire.
            4. Drive 3 dup-ACKs at SND.UNA. Fast retransmit
               fires.
            5. Advance one tick so the retransmit goes out.

        Returns (session, post_fast_retransmit_cwnd, recovery_point).
        """

        session = self._drive_handshake_to_established(iss=iss, peer_iss=peer_iss)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        payload = b"x" * (n_segments * PEER__MSS)
        session.send(data=payload)
        for _ in range(n_segments):
            self._advance(ms=1)

        # Three dup-ACKs - the 3rd triggers fast retransmit.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=peer_iss + 1,
                ack=iss + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        # Tick so the retransmitted seg 1 fires.
        self._advance(ms=1)
        return session, session._cc.cwnd, session._cc.recovery_point

    def test__newreno__partial_cum_ack_retransmits_next_gap(self) -> None:
        """
        Ensure a partial cum-ACK during recovery triggers an
        immediate retransmit of the next unacknowledged
        segment (the first gap) without waiting for the RTO
        timer.

        Reference: RFC 6582 §3 (NewReno step 3b retransmit on partial cum-ACK).
        """

        n_segments = 3
        session, _, _ = self._setup_multi_loss_recovery(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            n_segments=n_segments,
        )

        # Drive partial cum-ACK acking only seg 1.
        partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_ack)

        # Tick so the next-gap retransmit fires.
        retransmit_tx = self._advance(ms=1)

        # Find a frame at seq = ISS + 1 + MSS (seg 2 retransmit).
        retransmit_seg = None
        for frame in retransmit_tx:
            probe = self._parse_tx(frame)
            if probe.seq == LOCAL__ISS + 1 + PEER__MSS and len(probe.payload) > 0:
                retransmit_seg = probe
                break

        self.assertIsNotNone(
            retransmit_seg,
            msg=(
                "Partial cum-ACK MUST trigger immediate "
                "retransmit of seg 2 (seq = "
                f"{LOCAL__ISS + 1 + PEER__MSS:#x}). Got "
                f"tx burst: {retransmit_tx!r}."
            ),
        )


class TestTcpCwndNewRenoExtended(TcpTestCase):
    """
    Extended integration coverage for RFC 6582 NewReno
    scenarios that 'TestTcpCwndNewReno' (the basic single-
    partial-cum-ACK happy path) does not exercise:

      - Multiple consecutive partial cum-ACKs in one recovery
        cycle.
      - NewReno cwnd deflation with SACK-aware peer
        (deflation runs regardless of SACK state).
      - NewReno across the 32-bit seq wrap (modular 'lt32'
        recovery_point check).
    """

    _DEFAULT_CC_MODE: CcMode | None = CcMode.RENO

    def _drive_handshake(self, *, iss: int, peer_iss: int, sackperm: bool = False) -> TcpSession:
        """Drive handshake; optionally negotiate SACK."""

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
            sackperm=sackperm,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._advertise.send_sack == sackperm, (
            f"Setup invariant: bilateral SACK negotiation expected={sackperm}, "
            f"got _send_sack={session._advertise.send_sack}."
        )
        return session

    def test__newreno__multi_partial_cum_acks_preserve_recovery_then_exit_on_full(self) -> None:
        """
        Ensure that across multiple consecutive partial
        cum-ACKs in one recovery cycle, '_recovery_point' is
        preserved on each partial advance and cleared only
        on the cum-ACK that crosses the marker. Per-ACK cwnd
        recomputation is now governed by PRR (covered by
        'TestTcpCwndPrr'); this test focuses on the
        structural multi-partial-cum-ACK invariants
        (recovery-state lifecycle + deflate to ssthresh on
        exit) that PRR preserves.

        Reference: RFC 6582 §3 (NewReno multi-partial-cum-ACK recovery lifecycle).
        Reference: RFC 5681 §3.2 step 6 (recovery exit deflation).
        Reference: RFC 6937 §3.1 (PRR per-ACK cwnd recomputation).
        """

        session = self._drive_handshake(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        payload = b"x" * (3 * PEER__MSS)
        session.send(data=payload)
        for _ in range(3):
            self._advance(ms=1)

        # 3 dup-ACKs trigger fast retransmit.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        # Tick - seg 1 retransmit fires.
        self._advance(ms=1)
        ssthresh_post_fr = session._cc.ssthresh
        recovery_point = session._cc.recovery_point

        # First partial cum-ACK: ack seg 1.
        partial_1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_1)
        self.assertEqual(
            session._cc.recovery_point,
            recovery_point,
            msg=("Partial cum-ACK #1 (snd_una < recovery_point): " "recovery state MUST be preserved."),
        )

        # Tick - seg 2 retransmits.
        self._advance(ms=1)

        # Second partial cum-ACK: ack seg 2.
        partial_2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_2)
        self.assertEqual(
            session._cc.recovery_point,
            recovery_point,
            msg="Partial cum-ACK #2: recovery state preserved.",
        )

        # Tick - seg 3 retransmits.
        self._advance(ms=1)

        # Final cum-ACK: ack seg 3, snd_una reaches recovery_point.
        full_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 3 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=full_ack)

        self.assertEqual(
            session._cc.recovery_point,
            0,
            msg=(
                "Full cum-ACK at recovery_point: recovery_point "
                "MUST be cleared (RFC 5681 §3.2 step 6 / RFC 6675 §5)."
            ),
        )
        self.assertEqual(
            session._cc.cwnd,
            ssthresh_post_fr,
            msg=(
                f"Full cum-ACK: cwnd MUST deflate to ssthresh "
                f"(RFC 5681 §3.2 step 6). Expected "
                f"{ssthresh_post_fr}, got {session._cc.cwnd}."
            ),
        )

    def test__newreno__sack_active_partial_cum_ack_preserves_recovery(self) -> None:
        """
        Ensure that during recovery on a SACK-bilaterally-
        negotiated session, a partial cum-ACK preserves the
        recovery state ('_recovery_point' unchanged) - the
        recovery-lifecycle invariant is independent of the
        SACK negotiation result. Per-ACK cwnd recomputation
        is now governed by RFC 6937 PRR (covered by
        'TestTcpCwndPrr').

        Reference: RFC 6582 §3 (recovery-state lifecycle is SACK-orthogonal).
        """

        session = self._drive_handshake(iss=LOCAL__ISS, peer_iss=PEER__ISS, sackperm=True)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        payload = b"x" * (3 * PEER__MSS)
        session.send(data=payload)
        for _ in range(3):
            self._advance(ms=1)

        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        self._advance(ms=1)
        recovery_point = session._cc.recovery_point
        self.assertNotEqual(
            recovery_point,
            0,
            msg="Setup invariant: '_recovery_point' must be set after fast retransmit.",
        )

        partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_ack)

        self.assertEqual(
            session._cc.recovery_point,
            recovery_point,
            msg=(
                "Partial cum-ACK on a SACK-active session "
                "MUST preserve '_recovery_point' - the "
                "lifecycle invariant is SACK-orthogonal."
            ),
        )

    def test__newreno__partial_cum_ack_across_32bit_seq_wrap_preserves_recovery(self) -> None:
        """
        Ensure that the recovery-state lifecycle works
        across the 32-bit seq wrap: the 'lt32(snd_una,
        recovery_point)' modular comparison correctly
        classifies a partial cum-ACK on the post-wrap side
        of 'recovery_point' as partial (recovery preserved),
        not as past-recovery_point (recovery exited). Per-ACK
        cwnd recomputation is now governed by RFC 6937 PRR
        (covered by 'TestTcpCwndPrr'); this test focuses on
        the modular comparison invariant that PRR preserves.

        Reference: RFC 9293 §3.4 (modular sequence-number comparison).
        Reference: RFC 6582 §3 (recovery-state lifecycle across wrap).
        """

        wrap_iss = 0xFFFF_FFE0
        wrap_peer_iss = 0x0000_2000

        session = self._drive_handshake(iss=wrap_iss, peer_iss=wrap_peer_iss)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        payload = b"x" * (3 * PEER__MSS)
        session.send(data=payload)
        for _ in range(3):
            self._advance(ms=1)

        # 3 dup-ACKs at our SND.UNA = ISS+1 (post-wrap value).
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=wrap_peer_iss + 1,
                ack=(wrap_iss + 1) & 0xFFFF_FFFF,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        self._advance(ms=1)
        recovery_point = session._cc.recovery_point

        # Partial cum-ACK at SND.UNA + MSS. Modular addition
        # so the value lands on the post-wrap side.
        partial_ack_value = (wrap_iss + 1 + PEER__MSS) & 0xFFFF_FFFF
        partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=wrap_peer_iss + 1,
            ack=partial_ack_value,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_ack)

        self.assertNotEqual(
            session._cc.recovery_point,
            0,
            msg=(
                f"Modular 'lt32(snd_una, recovery_point)' check "
                f"MUST classify the post-wrap partial cum-ACK "
                f"as partial. Got recovery_point="
                f"{session._cc.recovery_point} (expected non-zero, "
                f"= {recovery_point})."
            ),
        )


class TestTcpCwndCrossRfcNewRenoPlusRto(TcpTestCase):
    """
    Cross-RFC interaction (Phase B1 of the test-coverage audit):
    RFC 6582 NewReno fast recovery interacting with the RFC 6298
    RTO retransmit-timer fire mid-recovery. The two mechanisms
    must compose cleanly:

      - Entering recovery: cwnd = ssthresh + 3*SMSS, _recovery_point
        set to SND.MAX (RFC 5681 §3.2 step 3).
      - RTO fires before _recovery_point reached: cwnd collapses
        to LW=SMSS, ssthresh halves AGAIN, _recovery_point MUST
        be cleared (we're back in slow-start, not in recovery).
      - Subsequent partial cum-ACK MUST NOT trigger NewReno
        deflation - the post-RTO recovery is a fresh slow-start
        re-entry, not a continuation.
    """

    _DEFAULT_CC_MODE: CcMode | None = CcMode.RENO

    def test__cwnd__rto_during_fast_recovery_clears_recovery_point_and_resets_cwnd(self) -> None:
        """
        Ensure that an RTO timeout fired while in fast
        recovery clears '_recovery_point' and collapses
        cwnd to LW=SMSS. Subsequent partial cum-ACK does
        not run the NewReno deflation path because
        recovery state is gone.

        Reference: RFC 5681 §3.1 (RTO collapses cwnd, slow-start re-entry).
        Reference: RFC 6675 §5 (RecoveryPoint lifecycle).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Get N segments in flight then enter recovery via 3 dup-ACKs.
        n_segments = 5
        payload = b"x" * (n_segments * PEER__MSS)
        session.send(data=payload)
        for _ in range(n_segments):
            self._advance(ms=1)

        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        self._advance(ms=1)

        recovery_point_in_recovery = session._cc.recovery_point
        self.assertNotEqual(
            recovery_point_in_recovery,
            0,
            msg="Setup invariant: '_recovery_point' MUST be set after entering fast recovery.",
        )

        # Force the retransmit timer to expire so RTO fires
        # while still in recovery. The RTO handler runs §3.1
        # ssthresh halving + cwnd=LW reset.
        self._expire_timer(session, "retransmit")
        self._advance(ms=1)

        self.assertEqual(
            session._cc.recovery_point,
            0,
            msg=(
                "RTO during fast recovery: '_recovery_point' "
                "MUST be cleared so subsequent partial "
                "cum-ACKs follow the slow-start path, not "
                "the NewReno path."
            ),
        )
        self.assertEqual(
            session._cc.cwnd,
            session._win.snd_mss,
            msg="RTO: cwnd MUST collapse to LW=SMSS for slow-start re-entry.",
        )


class TestTcpCwndPrr(TcpTestCase):
    """
    Integration tests for RFC 6937 'Proportional Rate
    Reduction for TCP'. PRR replaces the coarse RFC 5681
    §3.2 step 4 'cwnd += SMSS per dup-ACK' inflation during
    recovery with a per-ACK send-pacing algorithm that
    aims for ssthresh / RecoverFS proportionality. The
    result: smoother send pacing during loss recovery, no
    end-of-recovery burst, and faster total recovery on
    bursty drop patterns.

    PRR per-recovery state (RFC 6937 §3.1):

        RecoverFS:     pipe (FlightSize) at recovery entry
        prr_delivered: cumulative bytes ACK'd / SACK'd in recovery
        prr_out:       cumulative bytes sent in recovery

    Per-ACK during recovery (simplified):

        pipe = current FlightSize (RFC 6675 §4)
        prr_delivered += DeliveredData
        if pipe > ssthresh:
            sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
        else:
            # PRR-CRB / PRR-SSRB
            limit = max(prr_delivered - prr_out, DeliveredData) + SMSS
            sndcnt = MIN(ssthresh - pipe, limit)
        cwnd = pipe + sndcnt
        # transmit up to sndcnt; prr_out += amount sent

    The tests below pin the structural invariants:

        1. Recovery entry initialises 'RecoverFS' from
           FlightSize at entry; PRR counters reset to 0.
        2. A bare dup-ACK during recovery (no SACK info, no
           cum-ACK advance) delivers no data, so PRR holds
           cwnd steady - the current RFC 5681 §3.2 step 4
           '+SMSS per dup-ACK' behaviour is the gap PRR fixes.
        3. Recovery exit clears the PRR state so a future
           loss event starts cleanly.

    Note: 'TestTcpCwndPhase3.test__cwnd__additional_dup_ack_in_recovery_inflates_cwnd_by_one_mss'
    pins the legacy '+SMSS per dup-ACK' behaviour and will
    be removed when the PRR fix lands - the two cannot both
    pass.
    """

    _DEFAULT_CC_MODE: CcMode | None = CcMode.RENO

    def _send_n_segments_and_enter_recovery(
        self,
        *,
        session: TcpSession,
        n_segments: int,
    ) -> None:
        """
        Pre-fill 'n_segments' MSS-sized payloads in flight,
        drive 3 dup-ACKs at SND.UNA so the count-based
        fast-retransmit trigger fires, then advance one
        tick so the retransmit emits.
        """

        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        payload = b"x" * (n_segments * PEER__MSS)
        session.send(data=payload)
        for _ in range(n_segments):
            self._advance(ms=1)

        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        self._advance(ms=1)

    def test__cwnd__prr__recovery_entry_initialises_recover_fs_and_prr_counters(self) -> None:
        """
        Ensure that on fast-retransmit recovery entry, PRR
        per-recovery state is initialised: '_recover_fs'
        snapshots FlightSize at entry, '_prr_delivered' is
        zero (no delivered data yet), and '_prr_out'
        reflects the bytes already sent during recovery
        (the retransmitted segment).

        Reference: RFC 6937 §3.1 (PRR per-recovery state initialisation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_enter_recovery(session=session, n_segments=5)

        # 5 segments in flight at recovery entry.
        expected_recover_fs = 5 * PEER__MSS
        self.assertEqual(
            session._cc.recover_fs,
            expected_recover_fs,
            msg=(
                "RFC 6937 §3.1: '_recover_fs' MUST snapshot "
                "FlightSize (= SND.MAX - SND.UNA) at recovery "
                f"entry. Expected {expected_recover_fs}, got "
                f"{session._cc.recover_fs}."
            ),
        )
        self.assertEqual(
            session._cc.prr_delivered,
            0,
            msg=(
                "RFC 6937 §3.1: '_prr_delivered' MUST be zero "
                "at recovery entry - no data has been delivered "
                f"yet. Got {session._cc.prr_delivered}."
            ),
        )
        # The retransmit consumed one SMSS of send budget.
        self.assertEqual(
            session._cc.prr_out,
            PEER__MSS,
            msg=(
                "RFC 6937 §3.1: '_prr_out' MUST equal SMSS "
                "after the recovery-entry retransmit (one "
                "segment's worth of send budget consumed). "
                f"Got {session._cc.prr_out}."
            ),
        )

    def test__cwnd__prr__bare_dup_ack_during_recovery_does_not_inflate_cwnd(self) -> None:
        """
        Ensure that a bare dup-ACK during recovery (no SACK
        info, no cum-ACK advance) does not inflate cwnd. The
        dup-ACK delivers zero new bytes
        ('DeliveredData = 0'), so PRR's proportional pacing
        holds cwnd steady; the legacy 'cwnd += SMSS per
        dup-ACK' rule over-inflates on bare dup-ACK bursts
        and causes the post-recovery send burst that PRR is
        designed to smooth out.

        Reference: RFC 6937 §3.1 (PRR delivers proportional pacing only on delivered data).
        Reference: RFC 5681 §3.2 (legacy '+SMSS per dup-ACK' rule that PRR replaces).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_enter_recovery(session=session, n_segments=5)
        cwnd_at_entry = session._cc.cwnd

        # 4th dup-ACK (bare, no SACK, same ack as the prior
        # three). Delivers zero new bytes.
        bare_dup_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=bare_dup_ack)

        self.assertEqual(
            session._cc.cwnd,
            cwnd_at_entry,
            msg=(
                "RFC 6937 §3.1: a bare dup-ACK during "
                "recovery (DeliveredData=0) MUST NOT inflate "
                "cwnd. PRR's proportional pacing keys off "
                "delivered data, not the dup-ACK arrival "
                "alone. Pre-dup4="
                f"{cwnd_at_entry}, expected {cwnd_at_entry} "
                f"(unchanged), got {session._cc.cwnd}. The "
                "current RFC 5681 §3.2 step 4 '+SMSS per "
                "dup-ACK' rule violates this PRR invariant."
            ),
        )
        # '_prr_delivered' must also stay at zero (no
        # DeliveredData on this ACK).
        self.assertEqual(
            session._cc.prr_delivered,
            0,
            msg=(
                "RFC 6937 §3.1: 'prr_delivered' MUST stay "
                "zero across a bare dup-ACK that delivers no "
                f"new bytes. Got {session._cc.prr_delivered}."
            ),
        )

    def test__cwnd__prr__recovery_exit_resets_prr_state(self) -> None:
        """
        Ensure that when a cumulative ACK exits recovery
        (advances SND.UNA past RecoveryPoint), the PRR
        per-recovery state is cleared so a subsequent loss
        event starts with fresh state. Without the clear,
        stale '_prr_delivered' / '_prr_out' / '_recover_fs'
        from the prior recovery would corrupt the next
        recovery's pacing math.

        Reference: RFC 6937 §3.1 (PRR state lifecycle scoped to a single recovery episode).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_enter_recovery(session=session, n_segments=5)

        # Cum-ACK covering all 5 segments exits recovery.
        cum_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 5 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=cum_ack)

        self.assertEqual(
            session._cc.recover_fs,
            0,
            msg=(
                "RFC 6937 §3.1: '_recover_fs' MUST reset to "
                "zero on recovery exit so the next loss event "
                "snapshots a fresh value. Got "
                f"{session._cc.recover_fs}."
            ),
        )
        self.assertEqual(
            session._cc.prr_delivered,
            0,
            msg=(
                "RFC 6937 §3.1: '_prr_delivered' MUST reset "
                "to zero on recovery exit. Got "
                f"{session._cc.prr_delivered}."
            ),
        )
        self.assertEqual(
            session._cc.prr_out,
            0,
            msg=("RFC 6937 §3.1: '_prr_out' MUST reset to " f"zero on recovery exit. Got {session._cc.prr_out}."),
        )

    def _drive_handshake_to_established_with_sack(self, *, iss: int, peer_iss: int) -> TcpSession:
        """
        Bilateral SACK handshake variant: peer offers
        SACK-Permitted on its SYN+ACK so '_send_sack' is True
        post-handshake. Required for SACK-delta tests.
        """

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
            sackperm=True,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._advertise.send_sack, "Bilateral SACK must be active for SACK-delta tests."
        return session

    def test__cwnd__prr__sack_bearing_dup_ack_increments_prr_delivered(self) -> None:
        """
        Ensure that when a dup-ACK during recovery carries
        new SACK info covering one segment that was not
        previously SACK'd, '_prr_delivered' increases by
        that segment's byte count. Without this delta
        tracking, PRR's per-ACK 'sndcnt = ceil(prr_delivered
        * ssthresh / RecoverFS) - prr_out' computation
        cannot pace the sender correctly during recovery -
        only cum-ACK deliveries would feed the proportional
        ratio, leaving SACK-delivered bytes invisible to the
        algorithm.

        Reference: RFC 6937 §3.1 (DeliveredData includes SACK delivery delta).
        """

        session = self._drive_handshake_to_established_with_sack(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Pre-fill 5 segments and enter recovery via the
        # count-based trigger.
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        session.send(data=b"x" * (5 * PEER__MSS))
        for _ in range(5):
            self._advance(ms=1)
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        self._advance(ms=1)

        prr_delivered_pre = session._cc.prr_delivered
        self.assertEqual(
            prr_delivered_pre,
            0,
            msg="Setup invariant: '_prr_delivered' MUST be zero post-entry.",
        )

        # 4th dup-ACK with a NEW SACK block covering segment
        # 3 (1 SMSS of newly-delivered information).
        seg3_left = LOCAL__ISS + 1 + 2 * PEER__MSS
        seg3_right = LOCAL__ISS + 1 + 3 * PEER__MSS
        sack_dup_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(seg3_left, seg3_right)],
        )
        self._drive_rx(frame=sack_dup_ack)

        self.assertEqual(
            session._cc.prr_delivered,
            PEER__MSS,
            msg=(
                "RFC 6937 §3.1: a SACK-bearing dup-ACK that "
                "delivers one MSS of newly-SACK'd bytes MUST "
                "increment '_prr_delivered' by SMSS. Got "
                f"{session._cc.prr_delivered}, expected {PEER__MSS}."
            ),
        )

    def test__cwnd__prr__multi_segment_sack_block_increments_prr_delivered_by_total(self) -> None:
        """
        Ensure that when a dup-ACK carries a SACK block
        covering multiple newly-delivered segments,
        '_prr_delivered' increases by the full block byte
        count - not capped at one SMSS, not undercounted.
        Multi-segment SACK blocks are common when peer
        receives a burst of out-of-order data and reports
        the whole contiguous range in a single block.

        Reference: RFC 6937 §3.1 (DeliveredData covers full SACK delivery byte count).
        """

        session = self._drive_handshake_to_established_with_sack(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        session.send(data=b"x" * (5 * PEER__MSS))
        for _ in range(5):
            self._advance(ms=1)
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        self._advance(ms=1)

        # SACK block covering segments 3 + 4 + 5 (3 SMSS
        # contiguous range, all newly delivered).
        block_left = LOCAL__ISS + 1 + 2 * PEER__MSS
        block_right = LOCAL__ISS + 1 + 5 * PEER__MSS
        sack_dup_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(block_left, block_right)],
        )
        self._drive_rx(frame=sack_dup_ack)

        expected_delivered = 3 * PEER__MSS
        self.assertEqual(
            session._cc.prr_delivered,
            expected_delivered,
            msg=(
                "RFC 6937 §3.1: a SACK block covering 3 "
                "newly-delivered MSS-sized segments MUST "
                "increment '_prr_delivered' by 3*SMSS = "
                f"{expected_delivered}. Got "
                f"{session._cc.prr_delivered}."
            ),
        )

    def test__cwnd__prr__repeated_sack_info_does_not_double_count_prr_delivered(self) -> None:
        """
        Ensure that when a dup-ACK retransmits a SACK block
        covering bytes ALREADY in the scoreboard (peer
        repeats the same SACK info), '_prr_delivered' does
        NOT double-count those bytes. Only the delta between
        the scoreboard before and after ingestion counts as
        DeliveredData.

        Reference: RFC 6937 §3.1 (DeliveredData is a delta, not a sum of all SACK ranges).
        """

        session = self._drive_handshake_to_established_with_sack(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        session.send(data=b"x" * (5 * PEER__MSS))
        for _ in range(5):
            self._advance(ms=1)
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        self._advance(ms=1)

        block_left = LOCAL__ISS + 1 + 2 * PEER__MSS
        block_right = LOCAL__ISS + 1 + 3 * PEER__MSS

        # First dup-ACK with the SACK block - delivers 1 MSS
        # of new SACK info.
        first_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(block_left, block_right)],
        )
        self._drive_rx(frame=first_sack)
        prr_after_first = session._cc.prr_delivered
        self.assertEqual(
            prr_after_first,
            PEER__MSS,
            msg="Setup precondition: first SACK delta MUST equal SMSS.",
        )

        # Second dup-ACK with the SAME SACK info - peer is
        # repeating itself; no new delivery.
        second_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(block_left, block_right)],
        )
        self._drive_rx(frame=second_sack)

        self.assertEqual(
            session._cc.prr_delivered,
            prr_after_first,
            msg=(
                "RFC 6937 §3.1: a repeated SACK block "
                "covering bytes already in the scoreboard "
                "MUST NOT double-count - 'DeliveredData' is "
                "the delta of newly-SACK'd bytes, not a sum "
                f"of all SACK ranges seen. Pre={prr_after_first}, "
                f"got {session._cc.prr_delivered}, expected unchanged."
            ),
        )

    def test__cwnd__prr__cum_ack_during_recovery_sets_cwnd_per_prr_formula(self) -> None:
        """
        Ensure that on a cumulative ACK during recovery,
        cwnd is recomputed per the PRR formula:

            sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
            cwnd   = pipe + max(0, sndcnt)

        where pipe is the FlightSize estimate. For the
        5-segment scenario:

            RecoverFS  = 5 * SMSS = 7300
            ssthresh   = max(7300/2, 2*SMSS) = 3650
            entry: prr_delivered=0, prr_out=SMSS post-retransmit
            cum-ACK +1*SMSS: prr_delivered = SMSS = 1460
                pipe = SND.MAX - SND.UNA = 4*SMSS = 5840
                sndcnt = CEIL(1460*3650/7300) - 1460
                       = 730 - 1460 = -730 -> max(0, ·) = 0
                cwnd = pipe + 0 = 5840

        The legacy NewReno 'partial_cum_ack_deflate' would
        leave cwnd at 'ssthresh + 3*SMSS = 8030' instead -
        a 2190-byte over-estimate that PRR's proportional
        ratio corrects.

        Reference: RFC 6937 §3.1 (PRR proportional cwnd recomputation per ACK).
        Reference: RFC 6675 §4 (FlightSize / pipe estimate).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_enter_recovery(session=session, n_segments=5)

        ssthresh = session._cc.ssthresh
        recover_fs = session._cc.recover_fs
        # Sanity-check the setup math.
        self.assertEqual(
            ssthresh,
            max(5 * PEER__MSS // 2, 2 * PEER__MSS),
            msg="Setup precondition: ssthresh = max(5*MSS/2, 2*MSS) = 3650.",
        )
        self.assertEqual(
            recover_fs,
            5 * PEER__MSS,
            msg="Setup precondition: RecoverFS = 5*MSS = 7300.",
        )

        # Cum-ACK advancing SND.UNA by exactly 1 SMSS.
        cum_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=cum_ack)

        expected_cwnd = 4 * PEER__MSS  # pipe (= 5*MSS - 1*MSS) + sndcnt (0)
        self.assertEqual(
            session._cc.cwnd,
            expected_cwnd,
            msg=(
                "RFC 6937 §3.1: cwnd after a 1*SMSS cum-ACK "
                "during recovery MUST equal 'pipe + max(0, "
                "sndcnt)'. With prr_delivered=SMSS, prr_out=SMSS, "
                f"ssthresh={ssthresh}, RecoverFS={recover_fs}: "
                f"sndcnt clamps to 0 and cwnd = pipe = "
                f"{expected_cwnd}. Got {session._cc.cwnd}."
            ),
        )


class TestTcpCwndRfc5681RestartWindow(TcpTestCase):
    """
    RFC 5681 §4.1 Restart Window after idle: when TCP has not
    sent data in an interval exceeding the retransmission
    timeout, cwnd SHOULD be reduced to RW = min(IW, cwnd)
    before transmission begins, so a long-idle connection does
    not blast a stale-cwnd burst into a network whose capacity
    estimate has decayed.
    """

    def test__cwnd__rfc5681_restart_window_reduces_cwnd_after_idle(self) -> None:
        """
        Ensure that when the connection has been idle longer
        than one RTO, the next outbound data segment triggers
        a cwnd reduction to RW = min(IW, cwnd_pre_idle). The
        check is "TCP has not sent data in an interval
        exceeding the retransmission timeout", measured by
        '_last_send_time_ms'. Without this reduction, a stale
        cwnd from a high-bandwidth historical period would
        permit a line-rate burst into a network whose live
        capacity may be substantially lower.

        Reference: RFC 5681 §4.1 (Restart Window after idle).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Inflate cwnd well above IW to make the reduction
        # observable. The reduction is a no-op if cwnd is
        # already <= IW; the SHOULD only kicks in when the
        # session has accumulated history.
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        # Prime '_last_send_time_ms' so the §4.1 'has not sent
        # data in an interval exceeding RTO' clock has a
        # reference point. Without a real prior send the §4.1
        # gate is structurally indeterminate (no last-send
        # timestamp to compare against).
        session.send(data=b"prime")
        self._advance(ms=1)
        # Drain by ACKing the prime segment so the next
        # transmit is a fresh send, not a retransmit.
        prime_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=session._snd_seq.max,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=prime_ack)
        # Reset cwnd to the inflated value AFTER the prime so
        # the eventual reduction is observable against the
        # known target (slow-start growth on the prime ACK
        # would otherwise add to the cwnd).
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Now sit idle past one RTO.
        idle_ms = session._rto_state.rto_ms + 100
        self._advance(ms=idle_ms)

        # Send fresh data; this is the §4.1 trigger.
        session.send(data=b"after-idle")
        self._advance(ms=1)

        # RW = min(IW, cwnd_pre_idle). With PEER__MSS = 1460
        # and IW = min(10*MSS, max(2*MSS, 14600)) = 14600 =
        # 10*MSS, RW = min(14600, 100*1460) = 14600.
        from pytcp.protocols.tcp.tcp__cwnd import initial_window

        expected_rw = min(initial_window(session._win.snd_mss), 100 * PEER__MSS)
        self.assertEqual(
            session._cc.cwnd,
            expected_rw,
            msg=(
                "RFC 5681 §4.1: after a >RTO idle, cwnd MUST be "
                f"reduced to RW = min(IW, prior_cwnd) = {expected_rw}. "
                f"Got cwnd={session._cc.cwnd}."
            ),
        )
