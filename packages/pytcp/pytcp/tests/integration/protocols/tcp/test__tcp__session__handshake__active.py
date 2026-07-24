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
This module contains integration tests for the TCP active-open
('connect') side of the 'TcpSession' state machine, covering the
client role of the three-way handshake defined in RFC 9293 §3.10.7.3.

The tests in this file drive the session's FSM directly via
'tcp_fsm(syscall=SysCall.CONNECT)' rather than going through the
blocking 'TcpSocket.connect()' BSD-API wrapper - the integration
scope is the session, not the socket facade. The full RX/TX path
is exercised end to end: outbound segments flow through the real
'PacketHandler._phtx_tcp -> _phtx_ip4 -> _phtx_ethernet' chain and
land in the mocked 'TxRing'; inbound segments are fed into the real
'_phrx_ethernet' entry point and dispatched to the session via the
real 'TcpSocket.process_tcp_packet'.

Reference RFCs:
    RFC 9293 §3.10.7.3   Active open / SYN-SENT state processing
    RFC 9293 §3.10.7.4   Synchronized state segment processing (challenge ACK)
    RFC 9293 §3.4.1      Initial sequence number selection
    RFC 9293 §3.5.1      Three-way handshake
    RFC 9293 §3.8.3      User Timeout / connection abort
    RFC 6298 §2          Computing TCP's retransmission timer
    RFC 5961 §4          Blind data injection / SYN-on-established mitigation
    RFC 1122 §4.2.3.5    R1 / R2 retransmission limits (R2 >= 100 s)

pytcp/tests/integration/protocols/tcp/test__tcp__session__handshake__active.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing chosen so log output and byte-frame comments
# stay readable. STACK is the host running the SUT, PEER is the
# 'HOST_A' fixture from 'NetworkTestCase' that has a working ARP entry.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap so
# this baseline test exercises ordinary modular comparisons; the
# wraparound corner is covered separately in the seq_wraparound file.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on the SYN+ACK reply. Picked to
# match the value typical OS stacks send (Linux's MSS-tuned default).
PEER__WIN: int = 64240

# Peer's MSS option value on the SYN+ACK. 1460 is the canonical IPv4
# Ethernet MSS (1500 MTU - 20 byte IPv4 header - 20 byte TCP header).
PEER__MSS: int = 1460


class TestTcpActiveOpen__Handshake(TcpTestCase):
    """
    Integration tests for the client-side three-way handshake driven
    out of 'TcpSession' in the active-open path.
    """

    def test__active_open__three_way_handshake_completes_to_established(self) -> None:
        """
        Ensure the canonical three-way handshake takes a freshly
        constructed 'TcpSession' from CLOSED through SYN_SENT to
        ESTABLISHED and emits exactly the prescribed segments for
        active open: an initial SYN carrying our ISS with MSS /
        WSCALE options, then a single third-leg ACK in response
        to the peer's SYN+ACK whose SEQ / ACK numbers track the
        established connection state.

        Reference: RFC 9293 §3.5 (Establishing a connection, active open).
        Reference: RFC 9293 §3.10.7.3 (SYN-SENT segment processing).
        """

        # Stage 1: CONNECT syscall.
        session = self._make_active_session(iss=LOCAL__ISS)
        self._assert_no_tx()

        session.tcp_fsm(syscall=SysCall.CONNECT)

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="CONNECT from CLOSED must transition the session to SYN_SENT.",
        )
        self.assertEqual(
            session._snd_seq.ini,
            LOCAL__ISS,
            msg="'_force_iss' must pin '_snd_ini' to the value supplied to '_make_active_session'.",
        )
        self.assertEqual(
            session._snd_seq.nxt,
            LOCAL__ISS,
            msg="'_snd_nxt' must equal '_snd_ini' immediately after CONNECT - no SYN sent yet.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="'_tcp_fsm_closed' must not transmit on the CONNECT syscall - the SYN is gated on the timer tick.",
        )

        # Stage 2: Initial SYN goes out on the first virtual-clock tick.
        tx_frames = self._advance(ms=1)

        self.assertEqual(
            len(tx_frames),
            1,
            msg="Exactly one TX frame (the initial SYN) must be emitted on the first SYN_SENT timer tick.",
        )

        syn = self._parse_tx(tx_frames[0])
        self._assert_segment(
            syn,
            flags=frozenset({"SYN"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS,
            ack=0,
            payload=b"",
            mss=1460,  # RFC 6691 - MTU(1500) - IPv4 hdr(20) - TCP hdr(20).
            wscale=7,  # PyTCP's default WSCALE shift; advertised on outbound SYN per RFC 7323 §2.2.
            win=65535,  # SYN's own win is unshifted per RFC 7323 §2.2.
        )
        self.assertEqual(
            session._snd_seq.nxt,
            LOCAL__ISS + 1,
            msg=(
                "After the SYN goes out, '_snd_nxt' must be ISS+1 to "
                "consume the SYN's one-byte sequence space (RFC 9293 §3.4)."
            ),
        )
        self.assertEqual(
            session._snd_seq.max,
            LOCAL__ISS + 1,
            msg="'_snd_max' must track the highest seq we have ever emitted, set to ISS+1 after the initial SYN.",
        )

        # Stage 3: Peer responds with SYN+ACK; we ACK and reach ESTABLISHED.
        syn_ack_frame = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=syn_ack_frame)

        self.assertEqual(
            len(tx_frames),
            1,
            msg="Exactly one TX frame (the third-leg ACK) must follow processing of the peer's SYN+ACK.",
        )

        ack = self._parse_tx(tx_frames[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            win=65535,
            mss=None,  # MSS is only exchanged on SYN-bearing segments (RFC 9293 §3.7.1).
            wscale=None,
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Receiving a valid SYN+ACK in SYN_SENT must transition the "
                "session to ESTABLISHED (RFC 9293 §3.10.7.3)."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg="'_snd_una' must equal ISS+1 after peer ACKs our SYN.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1,
            msg="'_rcv_nxt' must equal peer_ISS+1 after consuming the SYN's one byte of sequence space.",
        )
        self.assertEqual(
            session._win.snd_mss,
            PEER__MSS,
            msg="'_snd_mss' must be clamped to peer's advertised MSS once the handshake completes (RFC 6691).",
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must be released once the "
                "session reaches ESTABLISHED so a blocked 'connect()' "
                "caller unblocks."
            ),
        )

    def test__active_open__syn_ack_with_payload_completes_handshake_and_delivers_data(self) -> None:
        """
        Ensure an inbound SYN+ACK carrying piggybacked data
        completes the active-open handshake AND queues the data:
        the session transitions to ESTABLISHED, the data is
        enqueued into '_rx_buffer', RCV.NXT advances past both
        the SYN's one byte and every byte of payload, and the
        third-leg ACK acknowledges both.

        Reference: RFC 9293 §3.10.7.3 (SYN-SENT processing of SYN+ACK with text).
        Reference: RFC 9293 §3.10.7.4 (ESTABLISHED segment text delivery).
        """

        # Stage 1: drive into SYN_SENT and emit the initial SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT after the SYN tick.",
        )
        self._frames_tx.clear()

        # Stage 2: peer sends SYN+ACK with piggybacked data.
        payload = b"greetings-from-peer"
        syn_ack_with_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            payload=payload,
        )
        tx_frames = self._drive_rx(frame=syn_ack_with_data)

        # Stage 3: assert ESTABLISHED + data delivered + third-leg
        # ACK fired with the data-acknowledging ack value.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "An acceptable SYN+ACK in SYN_SENT MUST transition "
                "the session to ESTABLISHED, regardless of whether "
                f"the segment carries data. Got state: {session.state!r}."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            payload,
            msg=(
                "Data piggybacked on the SYN+ACK MUST be enqueued "
                "into '_rx_buffer' so the application can receive "
                f"it via 'recv()'. Got: {bytes(session._rx_buffer)!r}, "
                f"expected: {payload!r}."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + len(payload),
            msg=(
                "'RCV.NXT' MUST advance past BOTH the SYN's one "
                "byte AND every byte of payload. Got: "
                f"{session._rcv_seq.nxt:#x}, expected: "
                f"{PEER__ISS + 1 + len(payload):#x}."
            ),
        )
        self.assertGreaterEqual(
            len(tx_frames),
            1,
            msg=(
                "After enqueueing the SYN+ACK's payload the session "
                "MUST emit the third-leg ACK so peer learns the "
                f"data is received. Got {len(tx_frames)} TX frame(s)."
            ),
        )
        if tx_frames:
            third_leg = self._parse_tx(tx_frames[-1])
            self.assertEqual(
                third_leg.flags,
                frozenset({"ACK"}),
                msg="The third-leg reply must be a bare ACK (no SYN / FIN / RST flags).",
            )
            self.assertEqual(
                third_leg.seq,
                LOCAL__ISS + 1,
                msg="The third-leg ACK's SEQ must equal SND.NXT after our SYN was sent (= LOCAL__ISS + 1).",
            )
            self.assertEqual(
                third_leg.ack,
                PEER__ISS + 1 + len(payload),
                msg=(
                    "The third-leg ACK's ack field MUST acknowledge "
                    "both peer's SYN's one byte AND every byte of "
                    f"peer's piggybacked payload. Got: "
                    f"{third_leg.ack:#x}, expected: "
                    f"{PEER__ISS + 1 + len(payload):#x}."
                ),
            )

        # The connect-event semaphore must release on ESTABLISHED so
        # a blocked 'connect()' caller unblocks.
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must be released once "
                "the session reaches ESTABLISHED, even when the "
                "transition was driven by a data-bearing SYN+ACK."
            ),
        )

    def test__active_open__rst_ack_to_outbound_syn_yields_connection_refused(self) -> None:
        """
        Ensure that when our initial SYN provokes an acceptable
        RST+ACK from the peer (the canonical "connection refused"
        response), the SYN_SENT state machine accepts the RST,
        transitions directly to CLOSED, signals the connect-event
        semaphore with ConnError.REFUSED, emits no segment in
        response, and unregisters the socket from 'stack.sockets'.

        Reference: RFC 9293 §3.10.7.3 (RST acceptance in SYN-SENT).
        Reference: RFC 5961 §3 (blind RST mitigation).
        """

        # Drive the session to SYN_SENT and emit the initial SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        socket_id = session.socket.socket_id
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg=(
                "SYN_SENT setup precondition: exactly one SYN must have "
                "been transmitted before driving the RST scenario."
            ),
        )

        # Peer responds with RST+ACK acknowledging our SYN.
        rst_ack_frame = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=0,
        )

        tx_frames = self._drive_rx(frame=rst_ack_frame)

        self.assertEqual(
            tx_frames,
            [],
            msg=(
                "An accepted RST in SYN_SENT must not provoke any "
                "outbound segment - replying to a peer RST is "
                "forbidden by RFC 9293 §3.10.7.3 to avoid RST/RST "
                "loops."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "An RST+ACK with an acceptable ACK in SYN_SENT must "
                "transition the session to CLOSED (RFC 9293 §3.10.7.3)."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.REFUSED,
            msg=(
                "The session must record 'ConnError.REFUSED' so that a "
                "blocked 'TcpSession.connect()' caller raises "
                "'TcpSessionError(\"Connection refused\")' on unblock."
            ),
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must be released when the "
                "session is reset so a blocked 'connect()' caller "
                "unblocks rather than hanging until the retransmit "
                "timeout fires."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "Transitioning to CLOSED must unregister the socket from "
                "'stack.sockets' so subsequent packets to the same "
                "4-tuple do not reach the dead session "
                "(RFC 9293 §3.10.4 / TCB deletion)."
            ),
        )

    def test__active_open__bare_rst_in_syn_sent_dropped_silently_per_rfc_9293_3_10_7_3(self) -> None:
        """
        Ensure a peer-issued BARE RST (RST flag set, ACK flag
        cleared) arriving in SYN_SENT is dropped silently
        regardless of the seq/ack values carried on the
        segment. SYN_SENT lacks an established window so the
        only way to bind a RST to our connection is via the
        ACK field — a bare RST has no acceptable-ACK path so
        the spec mandates dropping it.

        Reference: RFC 9293 §3.10.7.3 (RST handling in SYN-SENT, "no ACK" branch).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        socket_id = session.socket.socket_id
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: exactly one SYN must have been emitted before the bare RST.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT after the SYN was emitted.",
        )

        # Peer sends a BARE RST with an "acceptable-looking" ack
        # value but the ACK flag CLEARED. Today the outer
        # 'all({rst, ack})' predicate filters this out before the
        # inner sanity check; the test pins that filter.
        bare_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0,
            ack=LOCAL__ISS + 1,
            flags=("RST",),
            win=0,
        )
        rst_inline = self._drive_rx(frame=bare_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "A bare RST in SYN_SENT must produce NO outbound "
                "segment - it is dropped silently per RFC 9293 "
                "§3.10.7.3 step 2 ('Otherwise (no ACK), drop the "
                "segment and return')."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg=(
                "A bare RST in SYN_SENT MUST NOT transition the "
                "session to CLOSED. RFC 9293 §3.10.7.3 step 2 "
                "explicitly requires 'no ACK -> drop the segment'. "
                "If this assertion fails, the SYN_SENT RST predicate "
                "has been over-broadened (likely as part of a "
                "uniform 'all({rst, ack}) -> tcp__flag_rst' rewrite "
                "that conflated the synchronized-state rule with "
                "SYN_SENT's stricter rule). The fix for the five "
                "synchronized-state RST branches MUST NOT be applied "
                "to SYN_SENT - the strict-ACK predicate at line "
                "~2092 is intentional. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg=(
                "'_connection_error' must remain ConnError.NONE - a "
                "dropped bare RST does not signal the user an error. "
                "If this fires, the SYN_SENT RST handler ran "
                "erroneously on a segment it should have ignored."
            ),
        )
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must NOT be released by "
                "a bare RST in SYN_SENT - the connection has not been "
                "refused, just spuriously poked. A blocked 'connect()' "
                "caller must remain blocked until the legitimate "
                "RST+ACK refusal or the R2 timeout fires."
            ),
        )
        self.assertIn(
            socket_id,
            stack.sockets,
            msg=(
                "The socket must remain registered in 'stack.sockets' - "
                "a dropped bare RST does not delete the TCB. If this "
                "fires, the SYN_SENT branch erroneously called "
                "'_change_state(CLOSED)' which unregisters the socket."
            ),
        )

    def test__active_open__silent_peer_retransmits_per_rfc6298_until_r2(self) -> None:
        """
        Ensure that when the peer never replies to our SYN, the
        SYN_SENT state machine retransmits at the prescribed
        cadence (initial RTO 1 s, doubling on every retry) and
        does NOT abort the connection before R2 = 100 s of total
        elapsed time has been exhausted. By t = 60 s we observe at
        least six SYN transmissions and the session is still in
        SYN_SENT.

        Reference: RFC 6298 §5.5 (binary backoff).
        Reference: RFC 1122 §4.2.3.5 (R2 >= 100 s before connection abort).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Drive 60 seconds of virtual time with the peer staying silent.
        # All TX produced during the window is captured in one list.
        tx_frames = self._advance(ms=60_000)

        # Every TX must be a SYN retransmission of our original ISS - no
        # state-change side effects allowed while waiting for the peer.
        probes = [self._parse_tx(frame) for frame in tx_frames]
        for index, probe in enumerate(probes):
            self.assertEqual(
                probe.flags & frozenset({"SYN", "ACK", "FIN", "RST"}),
                frozenset({"SYN"}),
                msg=(
                    f"Retransmit #{index} must carry only the SYN flag "
                    f"(no ACK / RST / FIN). Got flags={probe.flags!r}."
                ),
            )
            self.assertEqual(
                probe.seq,
                LOCAL__ISS,
                msg=(
                    f"Retransmit #{index} must reuse the original ISS "
                    f"as SEQ (RFC 6298 §2 retransmits the same segment). "
                    f"Got seq=0x{probe.seq:08x}, expected 0x{LOCAL__ISS:08x}."
                ),
            )
            self.assertEqual(
                probe.ack,
                0,
                msg=(
                    f"Retransmit #{index} must carry ACK=0 since we have "
                    f"not yet received any segment from the peer."
                ),
            )

        # By t = 60 s, the RFC 6298 doubling cadence (1, 3, 7, 15, 31, 63 s)
        # must have produced at least six SYN transmissions: the initial
        # SYN at t = ~1 ms plus five retransmits within 60 s.
        self.assertGreaterEqual(
            len(probes),
            6,
            msg=(
                f"By t = 60 s of peer silence, the RFC 6298 cadence "
                f"(initial + retransmits at 1, 3, 7, 15, 31 s) must "
                f"produce at least 6 SYN transmissions. Got {len(probes)} "
                f"- 'TCP__RETRANSMIT__MAX_COUNT = 3' aborts the "
                f"connection too early per RFC 1122 §4.2.3.5 R2 >= 100 s."
            ),
        )

        # Most important: the session must NOT have aborted yet. R2 is
        # at least 100 s, so at t = 60 s the connection is still alive
        # and 'TcpSession.connect()' is still blocked waiting.
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg=(
                "After 60 s of peer silence, the session must remain in "
                "SYN_SENT. RFC 1122 §4.2.3.5 R2 (incorporated by RFC "
                "9293 §3.8.3) requires the connection-abort timeout to "
                "be at least 100 s; aborting at t < 100 s violates the "
                "spec and causes 'connect()' to return ETIMEDOUT to the "
                "caller far earlier than required."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg=(
                "No connection error must be recorded while the session "
                "is still legitimately retrying SYN within R2."
            ),
        )
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must not yet be released "
                "while the session is still validly retransmitting "
                "within R2 - releasing it would unblock 'connect()' "
                "with a spurious timeout."
            ),
        )

    def test__active_open__retransmitted_syn_ack_in_established_emits_challenge_ack(self) -> None:
        """
        Ensure that when a peer's third-leg ACK gets lost in
        flight and the peer retransmits its SYN+ACK while we
        have already moved to ESTABLISHED, we respond with a
        challenge ACK keyed to our current SND.NXT / RCV.NXT
        rather than silently dropping the segment. State
        remains ESTABLISHED and SND.UNA / RCV.NXT are unchanged.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 5961 §4 (blind SYN-in-window mitigation).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Drive the handshake to ESTABLISHED.
        self._advance(ms=1)  # initial SYN goes out
        syn_ack_frame = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=syn_ack_frame)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Setup precondition: handshake must have reached " "ESTABLISHED before driving the lost-ACK scenario."
            ),
        )
        snd_una_before = session._snd_seq.una
        rcv_nxt_before = session._rcv_seq.nxt

        # Peer's third-leg ACK was lost in flight; their RTO fires and
        # they retransmit the SAME SYN+ACK. Drive it into our session.
        retransmitted_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        tx_frames = self._drive_rx(frame=retransmitted_syn_ack)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "Receiving a SYN-bearing segment in ESTABLISHED must "
                "emit exactly one challenge ACK per RFC 9293 §3.10.7.4 "
                "/ RFC 5961 §4. Got "
                f"{len(tx_frames)} TX frames."
            ),
        )

        challenge_ack = self._parse_tx(tx_frames[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=None,
            wscale=None,
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "A challenge ACK is informational only - it must NOT "
                "transition the session out of ESTABLISHED "
                '(RFC 5961 §4: "the connection state is not changed").'
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=(
                "A challenge ACK does not consume sequence space - "
                "'_snd_una' must be unchanged. Reprocessing the "
                "retransmitted SYN's ACK would double-count and "
                "corrupt the send window."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_before,
            msg=(
                "Reprocessing a retransmitted SYN+ACK must not advance "
                "'_rcv_nxt' - the SYN's one byte of sequence space was "
                "already consumed during the original handshake."
            ),
        )

    def test__active_open__bare_ack_with_unacceptable_ack_in_syn_sent_emits_rst(self) -> None:
        """
        Ensure a bare ACK (no SYN, no RST, no FIN) arriving in
        SYN_SENT with an unacceptable ACK number triggers an
        outbound bare RST whose sequence number is the offending
        SEG.ACK and that the segment is then discarded. The
        session remains in SYN_SENT and SND.UNA / SND.NXT are
        unchanged.

        Reference: RFC 9293 §3.10.7.3 (step 1 ACK acceptability in SYN-SENT).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg=(
                "SYN_SENT setup precondition: exactly one SYN must "
                "have been transmitted before driving the bare-ACK "
                "scenario."
            ),
        )

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt

        # Peer sends a bare ACK with an unacceptable ACK number. ack=0
        # is clearly outside (SND.UNA=ISS, SND.NXT=ISS+1] so RFC 9293
        # §3.10.7.3 step 1 mandates a RST in response.
        bogus_ack_value = 0
        bogus_bare_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0,
            ack=bogus_ack_value,
            flags=("ACK",),
            win=PEER__WIN,
        )

        tx_frames = self._drive_rx(frame=bogus_bare_ack)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "An unacceptable bare ACK in SYN_SENT must elicit "
                "exactly one outbound segment (a bare RST) per RFC "
                f"9293 §3.10.7.3 step 1. Got {len(tx_frames)} TX frames."
            ),
        )

        rst = self._parse_tx(tx_frames[0])
        self._assert_segment(
            rst,
            flags=frozenset({"RST"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=bogus_ack_value,
            ack=0,
            payload=b"",
            mss=None,
            wscale=None,
        )

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg=(
                "A spurious bare ACK must NOT transition the session "
                "out of SYN_SENT - we keep waiting for the legitimate "
                "SYN+ACK from the peer (RFC 9293 §3.10.7.3 step 1: "
                "the segment is discarded after the RST is sent)."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=("A bogus bare ACK must not advance '_snd_una' - it " "acknowledged nothing we sent."),
        )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_before,
            msg=(
                "Sending the RST in response to a bogus ACK must not "
                "advance our own '_snd_nxt' - the RST consumes no "
                "sequence space (RFC 9293 §3.4)."
            ),
        )

    def test__active_open__syn_ack_with_unacceptable_ack_in_syn_sent_emits_rst(self) -> None:
        """
        Ensure a SYN+ACK arriving in SYN_SENT whose ACK number is
        outside the acceptable window '(SND.UNA, SND.NXT]' is
        rejected: a bare RST with seq=SEG.ACK is emitted, the
        segment is discarded, and the session stays in SYN_SENT
        without releasing the connect-event semaphore.

        Reference: RFC 9293 §3.10.7.3 (step 1 ACK acceptability in SYN-SENT).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg=(
                "SYN_SENT setup precondition: exactly one SYN must "
                "have been transmitted before driving the bogus "
                "SYN+ACK scenario."
            ),
        )

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        # Peer sends SYN+ACK with a clearly unacceptable ACK number.
        # 0xDEADBEEF is far outside the only valid value ISS+1=0x1001
        # and is visually unambiguous in failure output.
        bogus_ack_value = 0xDEAD_BEEF
        rogue_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=bogus_ack_value,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=rogue_syn_ack)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A SYN+ACK with an unacceptable ACK in SYN_SENT must "
                "elicit exactly one outbound segment (a bare RST) per "
                f"RFC 9293 §3.10.7.3 step 1. Got {len(tx_frames)} "
                "TX frames."
            ),
        )

        rst = self._parse_tx(tx_frames[0])
        self._assert_segment(
            rst,
            flags=frozenset({"RST"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=bogus_ack_value,
            ack=0,
            payload=b"",
            mss=None,
            wscale=None,
        )

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg=(
                "A SYN+ACK with an unacceptable ACK must NOT transition "
                "the session to ESTABLISHED - step 1 of RFC 9293 "
                "§3.10.7.3 mandates discarding the whole segment, so "
                "the SYN is never processed and the session stays in "
                "SYN_SENT awaiting a legitimate SYN+ACK."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=("A bogus SYN+ACK must not advance '_snd_una' - the " "rejected ACK acknowledged nothing."),
        )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_before,
            msg=(
                "Sending the RST must not advance '_snd_nxt' - the " "RST consumes no sequence space (RFC 9293 §3.4)."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_before,
            msg=(
                "A rejected SYN+ACK's SYN must not be processed - "
                "'_rcv_nxt' must not advance to peer_ISS+1, since we "
                "are still treating the peer's ISN as unknown."
            ),
        )
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must not be released by "
                "a rejected SYN+ACK - 'connect()' must keep blocking "
                "until a legitimate handshake completes or R2 elapses."
            ),
        )

    def test__active_open__rst_in_simultaneous_open_syn_rcvd_unblocks_connect(self) -> None:
        """
        Ensure that when an active-open caller is blocked on
        '_event__connect' and the session traverses
        SYN_SENT → SYN_RCVD (via the simultaneous-open path)
        → CLOSED (via peer RST), the connect-event semaphore
        is released with ConnError.REFUSED so the blocked
        connect() caller unblocks rather than hanging forever.

        Reference: RFC 9293 §3.10.7.4 (RST handling in synchronized states).
        """

        # Step 1: drive active-open to SYN_SENT and emit our SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT after CONNECT and SYN emit.",
        )
        # Step 2: connect-event semaphore is NOT yet released.
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "Setup precondition: connect-event semaphore must "
                "not be released while the handshake is still in "
                "progress (SYN_SENT)."
            ),
        )

        # Step 3: peer sends bare SYN (simultaneous-open trigger).
        # SYN_SENT's SYN-only branch transitions to SYN_RCVD and
        # emits a SYN+ACK.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        syn_ack_tx = self._drive_rx(frame=peer_syn)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg=(
                "Setup precondition: peer's bare SYN in SYN_SENT "
                "must elicit one outbound SYN+ACK as the "
                "simultaneous-open response."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg=(
                "Setup precondition: peer's bare SYN must transition " "the session to SYN_RCVD per RFC 9293 §3.10.7.3."
            ),
        )
        # Step 4: connect-event semaphore is STILL not released.
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "Setup precondition: connect-event semaphore must "
                "still not be released in SYN_RCVD - the handshake "
                "is not complete yet."
            ),
        )

        # Step 5: peer sends RST+ACK at canonical match position.
        # Post-Bug-C fix ('d7a57f6'): the simultaneous-open
        # handler bootstraps '_rcv_nxt' from peer's SYN, so
        # 'RCV.NXT == PEER__ISS + 1' here. The RST's seq must
        # match.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,  # == _rcv_nxt
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_tx = self._drive_rx(frame=peer_rst)
        self.assertEqual(
            rst_tx,
            [],
            msg=(
                "Peer's RST+ACK in SYN_RCVD must produce NO outbound "
                "segment - RST is unilateral and the receiver does "
                "not reply (RFC 9293 §3.10.7.3)."
            ),
        )

        # The actual contract checks: state, connection_error, and
        # connect-event release.
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with acceptable seq/ack in SYN_RCVD "
                "must transition the session to CLOSED per RFC 9293 "
                "§3.10.7.4."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.REFUSED,
            msg=(
                "On RST in SYN_RCVD with a blocked active-open "
                "caller, the session MUST record "
                "'ConnError.REFUSED' so the blocked "
                "'TcpSession.connect()' raises "
                "'TcpSessionError(\"Connection refused\")' on "
                "unblock, mirroring the SYN_SENT RST handler "
                "behaviour. Today the SYN_RCVD RST branch only "
                "calls '_change_state(CLOSED)' without setting "
                "'_connection_error'."
            ),
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "On RST in SYN_RCVD, the connect-event semaphore "
                "MUST be released so the blocked active-open caller "
                "unblocks. Today the SYN_RCVD RST branch only "
                "transitions state to CLOSED; the semaphore is "
                "never released, so any 'connect()' caller that "
                "reached SYN_RCVD via simultaneous open hangs "
                "forever on '_event__connect.acquire()'. Fix: "
                "mirror the SYN_SENT RST handler (line 2032 of "
                "'tcp__session.py') which sets "
                "'_connection_error = ConnError.REFUSED' and calls "
                "'_event__connect.release()' before the state "
                "transition."
            ),
        )

    def test__active_open__simultaneous_open_bootstraps_peer_state_from_bare_syn(self) -> None:
        """
        Ensure that when peer's bare SYN crosses our outbound
        SYN (simultaneous-open), the SYN+ACK we emit reuses
        our original SYN's seq, acknowledges peer's SYN
        (ack=PEER_ISS+1), and we bootstrap peer-derived state
        (_rcv_nxt, _rcv_ini, _snd_mss clamp, _snd_wnd,
        _peer_contacted) from peer's SYN options. State
        transitions to SYN_RCVD.

        Reference: RFC 9293 §3.5 (simultaneous connection synchronization).
        """

        # Step 1: drive active-open to SYN_SENT and emit SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT.",
        )

        # Step 2: peer sends bare SYN (simultaneous-open trigger).
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        syn_ack_tx = self._drive_rx(frame=peer_syn)

        # Step 3: inspect outbound SYN+ACK and bootstrapped state.
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg=(
                "Peer's bare SYN in SYN_SENT must elicit exactly "
                "one outbound SYN+ACK (the simultaneous-open "
                "response per RFC 9293 §3.10.7.3)."
            ),
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])

        # The fundamental wire-level assertion: the SYN+ACK MUST
        # acknowledge peer's SYN.
        self.assertEqual(
            syn_ack_probe.ack,
            PEER__ISS + 1,
            msg=(
                "The SYN+ACK we emit in response to peer's bare "
                "SYN MUST carry 'ack = PEER__ISS + 1' to "
                "acknowledge peer's SYN. Today the SYN-only "
                "handler at '_tcp_fsm_syn_sent' line ~2024 calls "
                "'_transmit_packet' without bootstrapping "
                "'_rcv_nxt' from peer's SYN, so the default "
                "'ack = self._rcv_seq.nxt = 0' is used. Peer's TCP "
                "rejects our SYN+ACK as not acknowledging their "
                "SYN, and the connection never establishes."
            ),
        )

        # The SYN+ACK should reuse our original SYN's seq
        # (LOCAL__ISS), not advance past it. RFC 9293 §3.5.1:
        # the simultaneous-open SYN+ACK is functionally a
        # retransmit of our original SYN with peer's ACK
        # piggybacked.
        self.assertEqual(
            syn_ack_probe.seq,
            LOCAL__ISS,
            msg=(
                "The SYN+ACK MUST carry 'seq = LOCAL__ISS' (= "
                "the same seq as our original SYN); the "
                "SYN+ACK is RFC 9293 §3.5.1's 'reuse of our "
                "SYN seq with peer's ACK piggybacked'. Today "
                "the SYN+ACK uses 'seq = LOCAL__ISS + 1' (the "
                "post-original-SYN advance of SND.NXT)."
            ),
        )

        # Bootstrapped peer-side state.
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1,
            msg=(
                "'_rcv_nxt' MUST be advanced past peer's SYN "
                "seq before the SYN+ACK is emitted - mirroring "
                "the listener-fork bootstrap pattern."
            ),
        )
        self.assertEqual(
            session._rcv_seq.ini,
            PEER__ISS,
            msg="'_rcv_ini' MUST record peer's ISN for downstream consistency.",
        )
        self.assertEqual(
            session._win.snd_mss,
            PEER__MSS,
            msg=("'_snd_mss' MUST be clamped to peer's MSS " "advertisement (RFC 6691)."),
        )
        self.assertEqual(
            session._win.snd_wnd,
            PEER__WIN,
            msg="'_snd_wnd' MUST be initialised from peer's advertised window.",
        )
        self.assertTrue(
            session._peer_contacted,
            msg=(
                "'_peer_contacted' MUST be set to True once peer's "
                "first segment has been processed - same flag "
                "introduced in commit 'e5e12dc' for the R2-abort "
                "RST emission gate."
            ),
        )

        # State transition.
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg="State must transition to SYN_RCVD per RFC 9293 §3.10.7.3.",
        )

    def test__active_open__simultaneous_open_completes_to_established_without_parent_socket(self) -> None:
        """
        Ensure the simultaneous-open path completes the
        three-way handshake to ESTABLISHED when peer's
        third-leg ACK arrives. The blocked active-open caller
        unblocks (the connect-event semaphore is released)
        even though the session has no parent socket — the
        SYN_RCVD ACK-only handler must not assert that
        '_parent_socket is not None'.

        Reference: RFC 9293 §3.5 (simultaneous connection synchronization).
        """

        # Step 1: drive active-open to SYN_SENT and emit SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        # Sanity precondition: the socket has no parent. This is
        # what makes the simultaneous-open path different from
        # the listener-fork path.
        self.assertIsNone(
            session._socket._parent_socket,
            msg=(
                "Setup precondition: an active-open socket has "
                "no parent (it was created directly via "
                "'TcpSocket(family=...)' rather than via the "
                "listener-fork pattern in '_tcp_fsm_listen')."
            ),
        )
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )

        # Step 2: peer sends bare SYN (simultaneous open). This
        # transitions us to SYN_RCVD and emits SYN+ACK. Already
        # tested by 'test__active_open__simultaneous_open_bootstraps_peer_state_from_bare_syn';
        # we just drive past it here.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: peer's bare SYN must transition session to SYN_RCVD.",
        )

        # Step 3: peer sends third-leg ACK to our SYN+ACK.
        # Today this raises AssertionError on the
        # 'parent_socket is not None' assert; post-fix it
        # transitions cleanly to ESTABLISHED.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,  # == _rcv_nxt
            ack=LOCAL__ISS + 1,  # == _snd_nxt (post-SYN+ACK at _snd_ini)
            flags=("ACK",),
            win=PEER__WIN,
        )
        # The drive itself MUST NOT raise. Wrap in 'try' so the
        # test failure carries a specific message rather than
        # an opaque traceback if the AssertionError propagates.
        try:
            self._drive_rx(frame=peer_ack)
        except AssertionError as exc:
            self.fail(
                "Driving peer's third-leg ACK in simultaneous-open "
                "SYN_RCVD raised 'AssertionError' from the production "
                "code's 'assert parent_socket is not None' at "
                f"'_tcp_fsm_syn_rcvd' line ~2153: {exc}. The active-"
                "open simultaneous-open path has no parent socket; "
                "the SYN_RCVD ACK-only handler must gate the parent-"
                "socket plumbing on 'parent_socket is not None' so "
                "it skips it cleanly for the active-open path while "
                "preserving it for passive-open."
            )

        # Spec: state transitions to ESTABLISHED.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "After peer's third-leg ACK in simultaneous-open "
                "SYN_RCVD, state MUST transition to ESTABLISHED "
                "per RFC 9293 §3.5.1 figure 8 step 5."
            ),
        )
        # Spec: connect-event semaphore released.
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "On simultaneous-open completion, "
                "'_event__connect' MUST be released so the "
                "blocked active-open CONNECT caller unblocks."
            ),
        )

    def test__active_open__close_in_syn_sent_unblocks_connect_with_canceled(self) -> None:
        """
        Ensure 'close()' issued mid-handshake from SYN_SENT
        releases the connect-event semaphore with the
        dedicated ConnError.CANCELED signal, so a blocked
        connect() caller (typically a different thread)
        unblocks with TcpSessionError("Connection canceled")
        rather than hanging forever on the dead session.

        Reference: RFC 9293 §3.10.4 (CLOSE call processing).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT.",
        )
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "Setup precondition: connect-event semaphore must "
                "not be released while the handshake is in progress."
            ),
        )

        # Issue CLOSE syscall while in SYN_SENT (simulating a
        # different thread calling 'session.close()' while the
        # connect-thread is blocked on '_event__connect').
        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=("CLOSE in SYN_SENT must transition to CLOSED per " "RFC 9293 §3.10.4."),
        )
        self.assertIs(
            session._connection_error,
            ConnError.CANCELED,
            msg=(
                "CLOSE in SYN_SENT MUST record "
                "'ConnError.CANCELED' so the blocked CONNECT "
                "caller raises "
                "'TcpSessionError(\"Connection canceled\")' on "
                "unblock. Today the SYN_SENT CLOSE handler only "
                "calls '_change_state(CLOSED)' without setting "
                "'_connection_error'."
            ),
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "On CLOSE in SYN_SENT, '_event__connect' MUST be "
                "released so the blocked CONNECT caller unblocks. "
                "Today the SYN_SENT CLOSE handler doesn't release "
                "the semaphore; multi-threaded apps that close a "
                "connecting session deadlock the connect thread."
            ),
        )

    def test__active_open__close_in_syn_rcvd_unblocks_connect_with_canceled(self) -> None:
        """
        Ensure 'close()' issued mid-handshake from SYN_RCVD
        (reached via simultaneous open) releases the connect-
        event semaphore with ConnError.CANCELED so a blocked
        CONNECT caller unblocks. State transitions to
        FIN_WAIT_1 per the close-during-handshake path.

        Reference: RFC 9293 §3.10.4 (CLOSE call processing in SYN-RECEIVED).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # Drive SYN_SENT -> SYN_RCVD via peer's bare SYN
        # (simultaneous-open trigger).
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: state must be SYN_RCVD.",
        )

        # Issue CLOSE syscall while in SYN_RCVD.
        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "CLOSE in SYN_RCVD must transition to FIN_WAIT_1 "
                "per RFC 9293 §3.10.4 (so the FIN exchange can "
                "drive the post-half-close cleanup)."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.CANCELED,
            msg=(
                "CLOSE in SYN_RCVD MUST record "
                "'ConnError.CANCELED' so the blocked CONNECT "
                "caller raises "
                "'TcpSessionError(\"Connection canceled\")' on "
                "unblock."
            ),
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "On CLOSE in SYN_RCVD, '_event__connect' MUST be "
                "released so the blocked CONNECT caller unblocks. "
                "Today the handler only changes state to FIN_WAIT_1 "
                "without releasing the semaphore; the eventual "
                "CLOSED transition (via the FIN exchange) also "
                "doesn't release it, so the CONNECT caller is "
                "stuck for the entire graceful-close lifecycle."
            ),
        )

    def test__active_open__outbound_syn_carries_tsopt_wscale_sackperm_together(self) -> None:
        """
        Ensure the active-open SYN simultaneously carries MSS,
        WSCALE, Timestamps, and SACK-Permitted — the canonical
        modern-TCP option set. Pins that the four shipped
        option emitters compose without one accidentally
        suppressing another.

        Reference: RFC 6691 §2 (MSS calculation from MTU).
        Reference: RFC 7323 §2 (WSCALE bilateral negotiation).
        Reference: RFC 7323 §3 (Timestamps option wire format).
        Reference: RFC 2018 §3 (SACK-Permitted option).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        tx = self._advance(ms=1)

        self.assertEqual(len(tx), 1, msg="Active-open SYN tick must emit exactly one frame.")
        syn = self._parse_tx(tx[0])
        self.assertIn("SYN", syn.flags)
        self.assertEqual(syn.mss, 1460, msg="Outbound SYN MUST advertise MSS=1460 (RFC 6691).")
        self.assertEqual(syn.wscale, 7, msg="Outbound SYN MUST advertise WSCALE=7 (RFC 7323 §2).")
        self.assertIsNotNone(
            syn.tsval,
            msg="Outbound SYN MUST advertise TSopt with TSval set (RFC 7323 §3).",
        )
        self.assertEqual(
            syn.tsecr,
            0,
            msg="Outbound SYN's TSecr MUST be 0 (peer's TSval is unknown).",
        )
        self.assertTrue(
            syn.sackperm,
            msg="Outbound SYN MUST advertise SACK-Permitted (RFC 2018).",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="State must be SYN_SENT after the initial SYN.",
        )
