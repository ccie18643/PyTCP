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
This module contains integration tests for the TCP TIME_WAIT state
behaviour in the 'TcpSession' state machine: the eventual transition
to CLOSED after the TIME_WAIT delay elapses, and the handling of
late peer-FIN retransmits per RFC 9293 §3.10.7.5.

Reference RFCs:
    RFC 9293 §3.10.7.5   TIME-WAIT state segment processing
    RFC 9293 §3.10.4     CLOSE Call
    RFC 9293 §3.4.2      MSL / 2 * MSL = TIME_WAIT delay (PyTCP
                         deviates from the RFC's 240 s suggestion;
                         see the TCP__TIME_WAIT__DELAY_MS constant)

pytcp/tests/integration/protocols/tcp/test__tcp__session__close__time_wait.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
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

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460

# Test-only override of the TIME_WAIT delay so the suite runs fast
# without burning 30 s of virtual time per scenario. Value chosen to
# be small enough that the test can step around the boundary cleanly
# but large enough that the boundary tick is unambiguous.
TEST__TIME_WAIT_DELAY_MS: int = 100


class TestTcpClose__TimeWait(TcpTestCase):
    """
    Integration tests for TIME_WAIT state behaviour - delay-driven
    transition to CLOSED and (per RFC 9293 §3.10.7.5) the response
    to a late-arriving peer-FIN retransmit.
    """

    def _drive_to_time_wait(self, *, iss: int, peer_iss: int) -> TcpSession:
        """
        Drive the session through an active-close that lands in
        TIME_WAIT: handshake -> close() -> FIN+ACK fires -> peer
        ACKs our FIN -> peer's FIN+ACK -> we ACK and transition
        to TIME_WAIT.
        """

        session = self._drive_handshake_to_established(iss=iss, peer_iss=peer_iss)
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

        # Peer ACKs our FIN.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        self.assertIs(
            session.state, FsmState.FIN_WAIT_2, msg=f"Setup failed: state is {session.state!r}, expected FIN_WAIT_2."
        )

        # Peer sends FIN+ACK.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state, FsmState.TIME_WAIT, msg=f"Setup failed: state is {session.state!r}, expected TIME_WAIT."
        )

        return session

    def test__close_time_wait__delay_expiry_transitions_to_closed(self) -> None:
        """
        Ensure the TIME_WAIT state transitions to CLOSED only
        after the configured TIME_WAIT delay elapses, and that
        the socket is unregistered from 'stack.sockets' on
        the transition.

        Reference: RFC 9293 §3.4.2 (TIME-WAIT 2*MSL).
        """

        # Patch TCP__TIME_WAIT__DELAY_MS before driving the FSM into TIME_WAIT
        # so the timer is registered with the small test value.
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__TIME_WAIT__DELAY_MS",
            TEST__TIME_WAIT_DELAY_MS,
        )

        session = self._drive_to_time_wait(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        self.assertIn(
            socket_id,
            stack.sockets,
            msg="Setup precondition: socket must be registered in TIME_WAIT.",
        )

        # Advance to one tick before the boundary. The timer is
        # still counting down; state must not have changed yet.
        pre_boundary_tx = self._advance(ms=TEST__TIME_WAIT_DELAY_MS - 1)
        self.assertEqual(
            pre_boundary_tx,
            [],
            msg=(
                f"During the {TEST__TIME_WAIT_DELAY_MS - 1} ms before "
                "TIME_WAIT timer expiry, no segments may fire - the "
                "session is idle awaiting the timer."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "Just before the TIME_WAIT timer expires, state must "
                "still be TIME_WAIT - the boundary tick is what "
                "triggers the transition."
            ),
        )

        # The boundary tick fires the timer-expired branch.
        boundary_tx = self._advance(ms=1)
        self.assertEqual(
            boundary_tx,
            [],
            msg=(
                "TIME_WAIT timer expiry must produce no outbound " "segment - it is a state-only transition to CLOSED."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=("After the TIME_WAIT delay elapses, state " "must transition to CLOSED."),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' so the "
                "4-tuple can be reused for a fresh connection."
            ),
        )

    def test__close_time_wait__late_peer_fin_retransmit_elicits_ack_and_rearms_timer(self) -> None:
        """
        Ensure a peer-issued FIN retransmit arriving while we
        are in TIME_WAIT elicits an ACK acknowledging peer's
        FIN AND restarts the 2*MSL timer. Without this
        behaviour, a peer that did not receive our original
        ACK of its FIN cannot confirm the connection is
        closed cleanly.

        Reference: RFC 9293 §3.10.7.5 (TIME-WAIT segment processing).
        """

        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__TIME_WAIT__DELAY_MS",
            TEST__TIME_WAIT_DELAY_MS,
        )

        session = self._drive_to_time_wait(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 2,
            msg=("Setup precondition: 'RCV.NXT' must have advanced " "past peer's FIN's one byte of sequence space."),
        )

        # Peer retransmits its FIN+ACK at the original wire shape.
        # The retransmit means peer did not receive our original
        # ACK so it is replaying the same byte of sequence space.
        peer_fin_retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        retransmit_inline = self._drive_rx(frame=peer_fin_retransmit)

        # The spec encoding: exactly one outbound ACK fires.
        self.assertEqual(
            len(retransmit_inline),
            1,
            msg=(
                "Peer's FIN retransmit in TIME_WAIT MUST elicit "
                "exactly one outbound ACK per RFC 9293 §3.10.7.5 "
                "('Acknowledge it, and restart the 2 MSL timeout'). "
                "Current code's '_tcp_fsm_time_wait' takes no "
                "'packet_rx_md' parameter and the FSM dispatcher "
                "(line 1898) does not pass one - the FIN is silently "
                "dropped, leaving the peer to retransmit until its "
                "own budget exhausts."
            ),
        )
        ack = self._parse_tx(retransmit_inline[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "After processing the FIN retransmit, state must "
                "remain TIME_WAIT - the retransmit is not a fresh "
                "close and should not advance the FSM."
            ),
        )

        # Step 5: advance (delay - 1) ms. The TIME_WAIT timer was
        # restarted on FIN retransmit, so we still have the full
        # delay grace period before expiry.
        pre_boundary_tx = self._advance(ms=TEST__TIME_WAIT_DELAY_MS - 1)
        self.assertEqual(
            pre_boundary_tx,
            [],
            msg=(
                "During the restarted-TIME_WAIT grace period, no "
                "segments may fire - the session is idle awaiting "
                "the new boundary."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                f"State must still be TIME_WAIT "
                f"{TEST__TIME_WAIT_DELAY_MS - 1} ms after the FIN "
                "retransmit - the timer was restarted by the FIN "
                "ACK path, not the original entry to TIME_WAIT, so "
                "the boundary is shifted out by the full delay."
            ),
        )

        # Step 6: one more ms past the restarted boundary -> CLOSED.
        boundary_tx = self._advance(ms=1)
        self.assertEqual(
            boundary_tx,
            [],
            msg="Restarted-TIME_WAIT timer expiry must produce no segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=("After the restarted TIME_WAIT timer expires, state " "must transition to CLOSED."),
        )


class TestTcpClose__TimeWaitRfc1337(TcpTestCase):
    """
    Integration tests for the RFC 1337 'TIME-WAIT Assassination
    Hazards' mitigations. RFC 1337 §4 identifies three hazards
    where late-arriving segments could prematurely terminate
    TIME-WAIT and corrupt subsequent connections:

        1. Old duplicate FIN: must re-ACK and stay in TIME-WAIT
           (RFC 9293 §3.10.7.5; covered by
           'late_peer_fin_retransmit_elicits_ack_and_rearms_timer'
           above).
        2. Old duplicate RST: MUST be silently dropped; TIME-
           WAIT MUST NOT close. PyTCP's '_tcp_fsm_time_wait'
           handler doesn't recognise RST as a recognised
           segment type, so it falls through to the implicit
           drop. This test pins that behaviour against future
           regressions.
        3. New SYN: must elicit a challenge ACK without
           transitioning out of TIME-WAIT.

    The PAWS check shipped in commit '79ed38e' (RFC 7323 §5)
    extends mitigation #2 to ALSO drop stale-TSval segments,
    not just RSTs.
    """

    def _drive_to_time_wait(self, *, iss: int, peer_iss: int) -> TcpSession:
        """Drive a normal active-close into TIME_WAIT."""

        session = self._drive_handshake_to_established(iss=iss, peer_iss=peer_iss)
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)

        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(session.state, FsmState.TIME_WAIT, msg=f"State precondition: expected {FsmState.TIME_WAIT}.")
        return session

    def test__rfc1337__rst_in_time_wait_does_not_terminate(self) -> None:
        """
        Ensure a peer RST arriving during TIME_WAIT is
        silently dropped: the session stays in TIME_WAIT
        until its 2*MSL delay timer naturally expires; no
        outbound segment fires in response.

        Reference: RFC 1337 §3 (TIME-WAIT assassination mitigations).
        """

        session = self._drive_to_time_wait(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_tx = self._drive_rx(frame=peer_rst)

        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "A peer RST during TIME_WAIT MUST be "
                "silently dropped; state MUST stay TIME_WAIT. "
                f"Got state={session.state!r}."
            ),
        )
        self.assertEqual(
            rst_tx,
            [],
            msg=("The RST MUST be silently dropped; no " "outbound segment may fire in response."),
        )

    def test__rfc1337__no_evidence_syn_in_time_wait_elicits_challenge_ack(self) -> None:
        """
        Ensure a SYN arriving at TIME_WAIT WITHOUT fresh
        evidence on either freshness axis (seq <= RCV.NXT
        AND no TSopt / TSval <= ts_recent) elicits a challenge
        ACK with our current SND.NXT and RCV.NXT and does NOT
        transition out of TIME_WAIT. SYNs with fresh seq or
        TSval evidence are accepted as fresh connections per
        the Linux-style OR'd freshness predicate; this test
        pins the no-evidence fallback.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 1337 §3 (TIME-WAIT assassination mitigations).
        Reference: RFC 6191 §2 A.4 / B.3 (no-evidence default).
        """

        session = self._drive_to_time_wait(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # No evidence: seq == RCV.NXT - 1 (replay of last seq
        # we ACKed); no TSopt on either side.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_seq.nxt - 1,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        challenge_tx = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(challenge_tx),
            1,
            msg=(
                "RFC 1337 §4 hazard #3 / RFC 9293 §3.10.7.4: "
                "a SYN in TIME_WAIT MUST elicit exactly one "
                f"challenge ACK. Got {len(challenge_tx)} "
                "frames."
            ),
        )
        probe = self._parse_tx(challenge_tx[0])
        self.assertEqual(
            probe.flags & frozenset({"ACK", "RST", "SYN", "FIN"}),
            frozenset({"ACK"}),
            msg=(
                "RFC 9293 §3.10.7.4: challenge ACK is an "
                "ACK-only segment (no RST/SYN/FIN). Got "
                f"flags={probe.flags!r}."
            ),
        )
        self.assertEqual(
            probe.seq,
            LOCAL__ISS + 2,  # post-FIN: seq = ISS + SYN + FIN = ISS + 2
            msg=("RFC 9293 §3.10.7.4: challenge ACK seq MUST " "equal SND.NXT."),
        )
        self.assertEqual(
            probe.ack,
            PEER__ISS + 2,  # post-peer-FIN: ack = peer_ISS + SYN + FIN = peer_ISS + 2
            msg=("RFC 9293 §3.10.7.4: challenge ACK ack MUST " "equal RCV.NXT."),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "RFC 1337 §4 hazard #3: a SYN in TIME_WAIT "
                "MUST NOT transition out of TIME_WAIT. Got "
                f"state={session.state!r}."
            ),
        )


# Peer's TS clock starting value (arbitrary, well clear of zero so
# the post-handshake _ts_recent is non-trivial).
PEER__TSVAL_INITIAL: int = 0x1000_0000


class TestTcpClose__TimeWaitRfc6191(TcpTestCase):
    """
    Integration tests for RFC 6191 'Reducing the TIME-WAIT
    State Using TCP Timestamps'. RFC 6191 §3 specifies an
    optimisation on top of RFC 9293 §3.10.7.4 / RFC 1337 §3
    Hazard #3: when a SYN to a TIME_WAIT 4-tuple carries a
    Timestamps option whose TSval is strictly greater than
    the cached '_ts_recent' of the TIME_WAIT session, the
    TIME_WAIT session MAY be terminated and the SYN accepted
    as a fresh connection.

    The Timestamps comparison is the safety guarantee: a
    TSval strictly greater than the last accepted TSval on
    this 4-tuple proves the new SYN cannot be a delayed
    segment from the previous incarnation (whose clock would
    have been monotonically lower at every send). The
    receiver can therefore short-circuit the 2*MSL wait
    without risking sequence-number confusion.

    Without RFC 6191, short-lived connection storms (e.g.
    HTTP keep-alive churn, repeated 'curl' hits, bench
    fixtures cycling sockets) accumulate stale TIME_WAIT
    entries that block legitimate reconnects on the same
    4-tuple for the full TCP__TIME_WAIT__DELAY_MS (~30 s in PyTCP).

    The bilateral matrix:

        TS-active TIME-WAIT, TSval > _ts_recent  -> reuse 4-tuple
        TS-active TIME-WAIT, TSval == _ts_recent -> challenge ACK
        TS-active TIME-WAIT, no TSopt on SYN     -> challenge ACK
        Non-TS TIME-WAIT, any SYN                -> challenge ACK
                          (covered by 'TestTcpClose__TimeWaitRfc1337
                          ::test__rfc1337__syn_in_time_wait_elicits_
                          challenge_ack_without_state_change')

    PAWS interaction: a SYN with TSval strictly less than
    '_ts_recent' is dropped silently by the PAWS check
    ('_check_paws_and_update_ts_recent') BEFORE it reaches
    the SYN-handling branch, so RFC 6191 never sees stale-
    TSval SYNs. The boundary case 'TSval == _ts_recent'
    passes PAWS (strict '<' comparison) but does NOT trigger
    RFC 6191 reuse (which requires strict '>') - so it must
    fall through to the challenge-ACK path.

    Per the active-close handshake with bilateral TSopt:
    after we transition into TIME_WAIT, '_ts_recent' equals
    the latest peer TSval seen (peer's final FIN+ACK's
    TSval). The new SYN's TSval is compared against that
    cached value.
    """

    def _drive_to_time_wait_with_tsopt(
        self,
        *,
        iss: int,
        peer_iss: int,
        peer_tsval_initial: int,
    ) -> TcpSession:
        """
        Drive an active-open + active-close cycle with
        bilateral TSopt so '_send_ts' is True post-handshake
        and '_ts_recent' is populated when we land in
        TIME_WAIT. Returns the session in TIME_WAIT with
        '_ts_recent == peer_tsval_initial + 2' (advanced by
        peer's SYN+ACK and FIN+ACK).
        """

        session = self._make_active_session(iss=iss)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # Peer SYN+ACK with TSopt.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss,
            ack=iss + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            tsval=peer_tsval_initial,
            tsecr=self._timer.now_ms,
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertIs(session.state, FsmState.ESTABLISHED, msg=f"State precondition: expected {FsmState.ESTABLISHED}.")
        assert session._ts.send_ts, "Bilateral TSopt must be active for RFC 6191 to apply."

        # Active close.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

        # Peer ACK of our FIN.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=peer_tsval_initial + 1,
            tsecr=self._timer.now_ms,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        self.assertIs(session.state, FsmState.FIN_WAIT_2, msg=f"State precondition: expected {FsmState.FIN_WAIT_2}.")

        # Peer FIN+ACK -> TIME_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
            tsval=peer_tsval_initial + 2,
            tsecr=self._timer.now_ms,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(session.state, FsmState.TIME_WAIT, msg=f"State precondition: expected {FsmState.TIME_WAIT}.")
        assert session._ts.ts_recent == peer_tsval_initial + 2, (
            "Setup invariant: post-TIME_WAIT '_ts_recent' must equal "
            f"peer's last TSval. Got {session._ts.ts_recent}, expected "
            f"{peer_tsval_initial + 2}."
        )
        return session

    def test__rfc6191__fresh_tsval_syn_terminates_time_wait_and_emits_syn_ack(self) -> None:
        """
        Ensure that when a peer SYN to our TIME_WAIT 4-tuple
        carries a TSval strictly greater than the cached
        '_ts_recent', the TIME_WAIT session is terminated
        and the SYN is accepted as a fresh connection — the
        outbound segment is a SYN+ACK at our fresh ISS, NOT
        a challenge ACK, and the session transitions to
        SYN_RCVD ready to complete a fresh three-way
        handshake.

        Reference: RFC 6191 §3 (TIME-WAIT termination via TSval comparison).
        """

        session = self._drive_to_time_wait_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval_initial=PEER__TSVAL_INITIAL,
        )
        ts_recent_before = session._ts.ts_recent

        # Peer's NEW SYN: fresh ISS, source port matches the
        # original 4-tuple, TSval strictly greater than our
        # cached '_ts_recent' (= peer_tsval_initial + 2). This
        # is the canonical RFC 6191 §3 trigger.
        new_peer_iss = 0x0000_5000
        fresh_tsval = ts_recent_before + 100
        new_peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=new_peer_iss,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            tsval=fresh_tsval,
            tsecr=0,
        )
        reuse_tx = self._drive_rx(frame=new_peer_syn)

        self.assertEqual(
            len(reuse_tx),
            1,
            msg=(
                "RFC 6191 §3: a fresh-TSval SYN to a TIME_WAIT "
                "4-tuple MUST elicit exactly one outbound "
                "segment (the SYN+ACK accepting the new "
                f"connection). Got {len(reuse_tx)} frames."
            ),
        )
        probe = self._parse_tx(reuse_tx[0])
        self.assertEqual(
            probe.flags & frozenset({"ACK", "RST", "SYN", "FIN"}),
            frozenset({"ACK", "SYN"}),
            msg=(
                "RFC 6191 §3: fresh-TSval SYN-on-TIME_WAIT MUST "
                "elicit a SYN+ACK (NOT a challenge ACK) — peer's "
                "new connection is being accepted, not rejected. "
                f"Got flags={probe.flags!r}."
            ),
        )
        self.assertEqual(
            probe.ack,
            new_peer_iss + 1,
            msg=(
                "RFC 6191 §3 / RFC 9293 §3.5: SYN+ACK's 'ack' MUST "
                "equal peer's new ISS + 1, acknowledging peer's "
                f"new SYN. Got ack={probe.ack}, expected "
                f"{new_peer_iss + 1}."
            ),
        )
        self.assertIsNotNone(
            probe.tsval,
            msg="RFC 7323 §3: outbound SYN+ACK MUST carry TSopt.",
        )
        self.assertEqual(
            probe.tsecr,
            fresh_tsval,
            msg=(
                "RFC 7323 §4: SYN+ACK's TSecr MUST echo the peer's "
                f"SYN TSval ({fresh_tsval}). Got TSecr={probe.tsecr}."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg=(
                "RFC 6191 §3: after accepting the fresh-TSval SYN, "
                "the session MUST transition out of TIME_WAIT into "
                f"SYN_RCVD. Got state={session.state!r}."
            ),
        )

    def test__rfc6191__equal_tsval_with_seq_evidence_accepts_reuse(self) -> None:
        """
        Ensure that a SYN to our TIME_WAIT 4-tuple carrying a
        TSval EQUAL to '_ts_recent' but a SEQ strictly greater
        than 'RCV.NXT' is accepted as a fresh connection (the
        Linux-style OR'd predicate: TSval-fresh OR seq-fresh).
        TSval=last alone is insufficient evidence (the
        TSval-fresh predicate requires strict '>'), but
        seq>last_seq proves the SYN cannot be a delayed
        segment from the previous incarnation (its seq is
        past anything we ever ACKed).

        Reference: RFC 6191 §2 A.2 (TSval == last + seq > last_seq).
        Reference: RFC 6191 §3 (TSval-fresh predicate requires strict '>').
        """

        session = self._drive_to_time_wait_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval_initial=PEER__TSVAL_INITIAL,
        )
        ts_recent_before = session._ts.ts_recent

        new_peer_iss = 0x0000_5000  # > peer_iss + 2 = 0x2002
        new_peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=new_peer_iss,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            tsval=ts_recent_before,  # equal — TSval evidence absent
            tsecr=0,
        )
        reuse_tx = self._drive_rx(frame=new_peer_syn)

        self.assertEqual(
            len(reuse_tx),
            1,
            msg=(
                "RFC 6191 A.2 (Linux-compatible): equal-TSval "
                "SYN with seq evidence (seq > rcv_nxt) MUST be "
                "accepted as a fresh connection. Got "
                f"{len(reuse_tx)} frames."
            ),
        )
        probe = self._parse_tx(reuse_tx[0])
        self.assertEqual(
            probe.flags & frozenset({"ACK", "RST", "SYN", "FIN"}),
            frozenset({"ACK", "SYN"}),
            msg=(
                "RFC 6191 A.2: equal-TSval + seq-evidence SYN MUST "
                "elicit SYN+ACK (accept), NOT challenge-ACK. Got "
                f"flags={probe.flags!r}."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg=(
                "RFC 6191 A.2: TIME_WAIT terminated and session "
                f"transitioned to SYN_RCVD. Got state={session.state!r}."
            ),
        )

    def test__rfc6191__syn_without_tsopt_with_seq_evidence_accepts_reuse(self) -> None:
        """
        Ensure that a SYN to our TIME_WAIT 4-tuple lacking
        TSopt but carrying a SEQ strictly greater than
        'RCV.NXT' is accepted as a fresh connection. The
        seq-based evidence proves the SYN cannot be a delayed
        segment from the previous incarnation regardless of
        TSopt presence.

        Reference: RFC 6191 §2 A.3 (no-new-TSopt + seq > last_seq).
        Reference: RFC 6191 §2 B.2 (no-prev-TSopt + no-new-TSopt + seq > last_seq).
        """

        session = self._drive_to_time_wait_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval_initial=PEER__TSVAL_INITIAL,
        )

        new_peer_iss = 0x0000_5000  # > peer_iss + 2 = 0x2002
        new_peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=new_peer_iss,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            # No tsval/tsecr -> SYN omits TSopt.
        )
        reuse_tx = self._drive_rx(frame=new_peer_syn)

        self.assertEqual(
            len(reuse_tx),
            1,
            msg=(
                "RFC 6191 A.3 (Linux-compatible): no-TSopt SYN "
                "with seq evidence (seq > rcv_nxt) MUST be "
                "accepted as a fresh connection. Got "
                f"{len(reuse_tx)} frames."
            ),
        )
        probe = self._parse_tx(reuse_tx[0])
        self.assertEqual(
            probe.flags & frozenset({"ACK", "RST", "SYN", "FIN"}),
            frozenset({"ACK", "SYN"}),
            msg=(
                "RFC 6191 A.3: no-TSopt SYN with seq evidence MUST "
                "elicit SYN+ACK (accept), NOT challenge-ACK. Got "
                f"flags={probe.flags!r}."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg=(
                "RFC 6191 A.3: TIME_WAIT terminated and session "
                f"transitioned to SYN_RCVD. Got state={session.state!r}."
            ),
        )

    def test__rfc6191__no_evidence_falls_back_to_challenge_ack(self) -> None:
        """
        Ensure that a SYN to our TIME_WAIT 4-tuple lacking
        BOTH TSval evidence AND seq evidence falls back to
        the canonical challenge-ACK path. With seq <= rcv_nxt
        and TSval <= ts_recent, the SYN cannot be distinguished
        from a delayed segment from the previous incarnation,
        so TIME_WAIT must be preserved.

        Reference: RFC 6191 §2 A.4 / B.3 (no evidence default drop / challenge-ACK).
        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 1337 §3 (TIME-WAIT assassination mitigations).
        """

        session = self._drive_to_time_wait_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval_initial=PEER__TSVAL_INITIAL,
        )
        ts_recent_before = session._ts.ts_recent

        # No evidence on either axis: seq == rcv_nxt - 1
        # (replay of last byte we ACKed) AND TSval == _ts_recent.
        new_peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_seq.nxt - 1,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            tsval=ts_recent_before,
            tsecr=0,
        )
        challenge_tx = self._drive_rx(frame=new_peer_syn)

        self.assertEqual(
            len(challenge_tx),
            1,
            msg=("No-evidence SYN-on-TIME_WAIT MUST elicit a " f"challenge ACK. Got {len(challenge_tx)} frames."),
        )
        probe = self._parse_tx(challenge_tx[0])
        self.assertEqual(
            probe.flags & frozenset({"ACK", "RST", "SYN", "FIN"}),
            frozenset({"ACK"}),
            msg=("No-evidence SYN MUST elicit ACK-only challenge ACK. " f"Got flags={probe.flags!r}."),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=("No-evidence SYN MUST NOT terminate TIME_WAIT. " f"Got state={session.state!r}."),
        )
