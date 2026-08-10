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
This module contains integration tests for the normal TCP connection
termination paths in the 'TcpSession' state machine - the active-close
4-way handshake (ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT)
and the passive-close path (ESTABLISHED → CLOSE_WAIT → LAST_ACK →
CLOSED) per RFC 9293 §3.10.4.

The simultaneous-close path (ESTABLISHED → FIN_WAIT_1 → CLOSING →
TIME_WAIT) is covered by 'close__simultaneous.py'; the TIME_WAIT
expiry mechanics are covered by 'close__time_wait.py'.

Reference RFCs:
    RFC 9293 §3.10.4    CLOSE Call
    RFC 9293 §3.5       Closing a Connection
    RFC 9293 §3.10.7.5  TIME-WAIT state segment processing

pytcp/tests/integration/protocols/tcp/test__tcp__session__close__normal.py

ver 3.0.10
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


class TestTcpClose__Normal(TcpTestCase):
    """
    Integration tests for the normal active-close and passive-close
    paths through the TCP FSM.
    """

    def test__close_active__textbook_4way_close_walks_through_fin_wait_1_fin_wait_2_time_wait(self) -> None:
        """
        Ensure an application-driven 'close()' on an idle
        ESTABLISHED session walks the FSM through the
        canonical active-close 4-way handshake: ESTABLISHED ->
        FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT, with our FIN
        emitted, peer's ACK accepted, peer's FIN ACKed, and
        the final ACK emitted at each step.

        Reference: RFC 9293 §3.6 (closing a connection).
        Reference: RFC 9293 §3.10.4 (CLOSE call processing).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Setup precondition: idle ESTABLISHED, no in-flight data.
        self.assertEqual(
            len(session._tx.buffer),
            0,
            msg="Setup precondition: TX buffer must be empty before close().",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED before close().",
        )

        # Application calls close(). _closing flag is set; state
        # is still ESTABLISHED at this exact moment (the transition
        # happens on the next timer tick).
        session.close()
        self.assertTrue(
            session._closing,
            msg=(
                "After close() in ESTABLISHED, '_closing' must be "
                "set (line 1505 of _tcp_fsm_established's CLOSE branch)."
            ),
        )

        # Tick #1: ESTABLISHED's timer branch sees _closing AND empty
        # buffer; transitions to FIN_WAIT_1. No segment emitted on
        # this tick - the FIN fires from the FIN_WAIT_1 handler on
        # the next tick.
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg=(
                "The ESTABLISHED -> FIN_WAIT_1 transition tick must "
                "emit no segment - state changes only; the FIN goes "
                "out from FIN_WAIT_1's timer handler on the next "
                "tick."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "After the transition tick, state must be FIN_WAIT_1 "
                "('_closing AND not _tx_buffer' triggers the "
                "transition in '_tcp_fsm_established's timer branch)."
            ),
        )

        # Tick #2: FIN_WAIT_1's timer handler emits the FIN+ACK.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg=(
                "FIN_WAIT_1's first timer tick must emit exactly one "
                "FIN+ACK segment via '_transmit_data's "
                "FIN-retransmit branch (line 770)."
            ),
        )
        fin_seg = self._parse_tx(fin_tx[0])
        self._assert_segment(
            fin_seg,
            flags=frozenset({"FIN", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
        )

        # Peer ACKs our FIN. ack = LOCAL__ISS + 2 covers the FIN's
        # one byte of sequence space.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        peer_ack_inline = self._drive_rx(frame=peer_ack_of_fin)
        self.assertEqual(
            peer_ack_inline,
            [],
            msg=(
                "Peer's ACK of our FIN must not elicit any inline "
                "TX - ACK of an ACK is not a thing in TCP. The "
                "session simply transitions FIN_WAIT_1 -> FIN_WAIT_2."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg=(
                "After peer's ACK of our FIN (with 'ack >= _snd_fin'), "
                "state must transition to FIN_WAIT_2 per RFC 9293 "
                "§3.10.7.4."
            ),
        )

        # Peer sends its own FIN+ACK to close its half of the
        # connection. seq = PEER__ISS + 1 (no peer data was sent),
        # ack = LOCAL__ISS + 2 (still covers our FIN).
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        peer_fin_inline = self._drive_rx(frame=peer_fin)
        self.assertEqual(
            len(peer_fin_inline),
            1,
            msg=(
                "Peer's FIN+ACK must elicit exactly one outbound ACK "
                "(acknowledging peer's FIN byte). FIN_WAIT_2 -> "
                "TIME_WAIT transition per RFC 9293 §3.10.7.4."
            ),
        )
        final_ack = self._parse_tx(peer_fin_inline[0])
        self._assert_segment(
            final_ack,
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
                "After receiving peer's FIN+ACK in FIN_WAIT_2, state "
                "must transition to TIME_WAIT per RFC 9293 §3.10.7.4."
            ),
        )

    def test__close_passive__peer_fin_first_walks_through_close_wait_last_ack_closed(self) -> None:
        """
        Ensure that when the peer initiates the close
        (sends FIN before our application calls close()),
        the FSM walks through the canonical passive-close
        path: ESTABLISHED -> CLOSE_WAIT -> LAST_ACK ->
        CLOSED. Peer's FIN is acknowledged via delayed-ACK,
        our subsequent close() flushes a FIN+ACK in
        LAST_ACK, and peer's ACK of our FIN tears down
        the connection.

        Reference: RFC 9293 §3.6 (closing a connection).
        Reference: RFC 9293 §3.10.4 (CLOSE call processing in CLOSE-WAIT).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED before peer initiates close.",
        )

        # Peer sends FIN+ACK to close its half. No data; the FIN
        # alone consumes one byte of sequence space.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        fin_inline = self._drive_rx(frame=peer_fin)
        self.assertEqual(
            fin_inline,
            [],
            msg=(
                "Peer's pure FIN+ACK (no data) must not produce an "
                "inline ACK from the ESTABLISHED FIN+ACK branch - "
                "the inline ACK fires only when the FIN-bearing "
                "segment also carries data; a delayed-ACK from the "
                "first CLOSE_WAIT tick covers the pure-FIN case."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg=("After peer's FIN+ACK in ESTABLISHED, state must " "transition to CLOSE_WAIT per RFC 9293 §3.10.7.4."),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 2,
            msg=(
                "'RCV.NXT' must advance past the FIN's one byte of "
                "sequence space - '_process_ack_packet' adds "
                "'flag_fin' into 'seg_end' (line 893)."
            ),
        )

        # Tick #1: CLOSE_WAIT's timer branch fires the delayed ACK
        # acknowledging peer's FIN.
        delayed_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(delayed_ack_tx),
            1,
            msg=(
                "First CLOSE_WAIT tick must emit exactly one bare ACK "
                "acknowledging peer's FIN. The delayed-ACK timer is "
                "not yet armed at this point, so the ACK is not "
                "deferred and fires immediately."
            ),
        )
        delayed_ack = self._parse_tx(delayed_ack_tx[0])
        self._assert_segment(
            delayed_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 2,
            payload=b"",
        )

        # Application calls close().
        session.close()
        self.assertTrue(
            session._closing,
            msg=(
                "After close() in CLOSE_WAIT, '_closing' must be set "
                "(line 1772 of '_tcp_fsm_close_wait's CLOSE branch)."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg=(
                "close() in CLOSE_WAIT only sets '_closing'; the "
                "transition to LAST_ACK happens on the next timer "
                "tick when the buffer is observed empty."
            ),
        )

        # Tick #2: CLOSE_WAIT -> LAST_ACK transition. No segment.
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg=(
                "The CLOSE_WAIT -> LAST_ACK transition tick must "
                "emit no segment - state changes only; the FIN goes "
                "out from LAST_ACK's timer handler on the next tick."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg=(
                "After the transition tick, state must be LAST_ACK "
                "('_closing AND not _tx_buffer' triggers the "
                "transition in '_tcp_fsm_close_wait's timer branch, "
                "line 1706)."
            ),
        )

        # Tick #3: LAST_ACK's timer handler emits our FIN+ACK.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg=(
                "LAST_ACK's first timer tick must emit exactly one "
                "FIN+ACK segment via '_transmit_data's FIN-retransmit "
                "branch (line 770)."
            ),
        )
        fin_seg = self._parse_tx(fin_tx[0])
        self._assert_segment(
            fin_seg,
            flags=frozenset({"FIN", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 2,
            payload=b"",
        )

        # Peer ACKs our FIN with ack = LOCAL__ISS + 2.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        peer_ack_inline = self._drive_rx(frame=peer_ack_of_fin)
        self.assertEqual(
            peer_ack_inline,
            [],
            msg=(
                "Peer's ACK of our FIN must not elicit any inline TX "
                "- LAST_ACK's ACK handler simply transitions to CLOSED."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=("After peer's ACK of our FIN in LAST_ACK, state must " "be CLOSED per RFC 9293 §3.10.7.4."),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' (line "
                "540) so the 4-tuple can be reused."
            ),
        )

    def test__close_active__pending_tx_data_drains_before_fin_is_emitted(self) -> None:
        """
        Ensure an application-driven close() on an
        ESTABLISHED session with unacknowledged data still
        in the TX buffer does not preempt the in-flight data:
        the buffered bytes are segmentized and acknowledged
        by the peer before the FIN segment goes out, so the
        FIN's SEQ follows the last data byte.

        Reference: RFC 9293 §3.10.4 (CLOSE call queues FIN until SENDs are segmentized).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        # Application enqueues 2 * MSS of data.
        payload_a = b"A" * 1460
        payload_b = b"B" * 1460
        session.send(data=payload_a + payload_b)

        # Application calls close() while data is still in '_tx_buffer'.
        session.close()
        self.assertTrue(
            session._closing,
            msg="Setup precondition: '_closing' must be set after close().",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "close() with a non-empty TX buffer must not transition "
                "out of ESTABLISHED - the FIN must follow the data."
            ),
        )
        self.assertEqual(
            len(session._tx.buffer),
            2 * 1460,
            msg="Setup precondition: '_tx_buffer' must hold 2 MSS of unsent data.",
        )

        # Tick #1: first data segment fires. No FIN.
        seg1_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg1_tx),
            1,
            msg="Tick #1 must emit exactly one segment (the first data segment).",
        )
        seg1 = self._parse_tx(seg1_tx[0])
        self._assert_segment(
            seg1,
            seq=LOCAL__ISS + 1,
            payload=payload_a,
        )
        self.assertNotIn(
            "FIN",
            seg1.flags,
            msg=(
                "First data segment MUST NOT carry FIN - the FIN may "
                "only appear after all queued data is segmentized "
                "(RFC 9293 §3.10.4 'Queue this until all preceding "
                "SENDs have been segmentized')."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED while data is still in '_tx_buffer'.",
        )

        # Tick #2: second data segment fires. Still no FIN.
        seg2_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg2_tx),
            1,
            msg="Tick #2 must emit exactly one segment (the second data segment).",
        )
        seg2 = self._parse_tx(seg2_tx[0])
        self._assert_segment(
            seg2,
            seq=LOCAL__ISS + 1 + len(payload_a),
            payload=payload_b,
        )
        self.assertNotIn(
            "FIN",
            seg2.flags,
            msg=(
                "Second data segment MUST NOT carry FIN - the FIN "
                "follows the data tail, not riding on the last data "
                "segment."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED until '_tx_buffer' drains.",
        )

        # Peer cumulatively ACKs both segments.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * 1460,
            flags=("ACK",),
            win=PEER__WIN,
        )
        peer_ack_inline = self._drive_rx(frame=peer_ack)
        self.assertEqual(
            peer_ack_inline,
            [],
            msg=(
                "Peer's cumulative ACK must not produce inline TX; "
                "data drain alone does not trigger the FIN immediately."
            ),
        )
        self.assertEqual(
            len(session._tx.buffer),
            0,
            msg="'_tx_buffer' must be drained after the peer's cumulative ACK.",
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1 + 2 * 1460,
            msg="'SND.UNA' must advance to cover all ACKed data.",
        )

        # Tick #3: empty-buffer transition to FIN_WAIT_1. No segment.
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg=(
                "The ESTABLISHED -> FIN_WAIT_1 transition tick (after "
                "buffer drain) must emit no segment; the FIN goes out "
                "from FIN_WAIT_1's timer handler on the next tick."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "After the buffer drains, '_closing AND not _tx_buffer' "
                "fires the ESTABLISHED -> FIN_WAIT_1 transition."
            ),
        )

        # Tick #4: FIN+ACK fires at SEQ immediately after the data
        # tail.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg=(
                "FIN_WAIT_1's first timer tick must emit exactly one "
                "FIN+ACK segment via '_transmit_data's FIN-retransmit "
                "branch."
            ),
        )
        fin_seg = self._parse_tx(fin_tx[0])
        self._assert_segment(
            fin_seg,
            flags=frozenset({"FIN", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 2 * 1460,
            ack=PEER__ISS + 1,
            payload=b"",
        )
        self.assertEqual(
            session._snd_seq.fin,
            LOCAL__ISS + 1 + 2 * 1460 + 1,
            msg=(
                "After emitting the FIN, '_snd_fin' must equal the "
                "post-FIN 'SND.NXT' (data_end + 1) - this is what "
                "FIN_WAIT_1's ACK-acceptance check uses to recognise "
                "the peer's ACK of our FIN."
            ),
        )

    def test__close_passive__data_bearing_fin_elicits_inline_cumulative_ack(self) -> None:
        """
        Ensure a peer FIN+ACK that also carries data is
        handled atomically: the data is enqueued into
        '_rx_buffer', RCV.NXT advances past both the data
        and the FIN's one byte of sequence space, an inline
        cumulative ACK fires immediately (not delayed), and
        the FSM transitions to CLOSE_WAIT. The data remains
        readable via recv() after peer closed its half.

        Reference: RFC 9293 §3.10.7.4 (FIN with text, immediate ACK).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends FIN+ACK with a payload. The segment carries
        # both new data and the connection-close signal.
        peer_payload = b"final-data"
        peer_fin_with_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK", "PSH"),
            win=PEER__WIN,
            payload=peer_payload,
        )
        inline_tx = self._drive_rx(frame=peer_fin_with_data)

        # The inline ACK fires immediately for FIN-bearing segments
        # with data per RFC 9293 §3.10.7.4 and the explicit
        # 'if packet_rx_md.tcp__data' branch in
        # '_tcp_fsm_established's FIN+ACK handler (line 1478).
        self.assertEqual(
            len(inline_tx),
            1,
            msg=(
                "Peer's data-bearing FIN+ACK must produce exactly one "
                "inline ACK - RFC 9293 §3.10.7.4 mandates 'send an "
                "acknowledgment for the FIN' and the data-bearing "
                "branch fires the ACK without waiting for the "
                "delayed-ACK timer."
            ),
        )
        ack = self._parse_tx(inline_tx[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1 + len(peer_payload) + 1,
            payload=b"",
            win=65535 - len(peer_payload),
        )

        # State assertions: the FSM has moved to CLOSE_WAIT, the
        # data is in '_rx_buffer' awaiting application recv(), and
        # RCV.NXT has advanced past both data and FIN.
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg=(
                "After peer's data-bearing FIN+ACK in ESTABLISHED, "
                "state must transition to CLOSE_WAIT per RFC 9293 "
                "§3.10.7.4."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + len(peer_payload) + 1,
            msg=(
                "'RCV.NXT' must advance past BOTH the data ("
                f"{len(peer_payload)} bytes) AND the FIN's one byte "
                "of sequence space - '_process_ack_packet' adds "
                "'len(tcp__data) + flag_fin' into 'seg_end' so a "
                "single update covers both."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_payload,
            msg=(
                "The data piggybacked on peer's FIN must be enqueued "
                "into '_rx_buffer' so the application can recv() it "
                "even after the peer has closed its half. Discarding "
                "the data because of the FIN flag would break the "
                "'FIN implies PUSH' RFC clause and lose application "
                "bytes."
            ),
        )
        self.assertTrue(
            session._event__rx_buffer.is_set(),
            msg=(
                "The '_event__rx_buffer' must be set on the FIN+ACK "
                "branch (line 1482 of '_tcp_fsm_established') so a "
                "blocked 'recv()' wakes up and observes both the "
                "final data and the connection-closing signal."
            ),
        )

    def test__close_passive__close_wait_pre_fin_data_retransmit_elicits_ack_per_rfc_3_10_7_4(self) -> None:
        """
        Ensure that when a peer retransmits previously-
        received pre-FIN data while we are in CLOSE_WAIT, we
        respond with an ACK reply rather than silently
        dropping the segment. The retransmit's payload is
        unacceptable (entire seq range below RCV.NXT) but
        the spec requires an ACK so peer's retransmit
        machinery can stop. State and SND.UNA / RCV.NXT /
        '_rx_buffer' are unchanged.

        Reference: RFC 9293 §3.10.7.4 (step 1 unacceptable-segment ACK).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends 50 bytes of data.
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)
        # Drain the delayed ACK.
        self._advance(ms=200)

        # Peer sends FIN. We transition to CLOSE_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 50,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: peer's FIN must put session in CLOSE_WAIT.",
        )

        # Application sends 4 bytes so SND.MAX > SND.UNA. This
        # gives peer's retransmit-with-piggybacked-ACK something
        # to potentially (incorrectly) advance SND.UNA against;
        # per RFC the ACK info MUST be ignored because the
        # segment fails the acceptability check.
        session._cc.snd_ewn = PEER__WIN
        session.send(data=b"OUT!")
        self._advance(ms=1)

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt
        rx_buffer_before = bytes(session._rx_buffer)

        # Peer retransmits the original 50-byte data segment
        # with a piggybacked ACK that would advance SND.UNA if
        # processed (it cum-ACKs our 4-byte send). The segment
        # is unacceptable per RFC 9293 §3.10.7.4 - SEG.SEQ +
        # SEG.LEN = PEER__ISS + 1 + 50 = current RCV.NXT - 1
        # (just below RCV.NXT, fully duplicate).
        retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 4,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        retransmit_tx = self._drive_rx(frame=retransmit)

        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 1: an unacceptable "
                "segment in CLOSE_WAIT MUST elicit an ACK reply "
                "carrying our current SND.NXT and RCV.NXT, so "
                "peer's retransmit machinery sees fresh activity "
                "and can stop retransmitting. PyTCP today drops "
                "the segment silently; peer keeps retransmitting "
                "until RTO."
            ),
        )
        ack_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=(
                "An unacceptable segment is dropped before "
                "the ACK-field processing step; peer's "
                "piggybacked ACK info MUST NOT advance SND.UNA."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_before,
            msg="RCV.NXT must not advance on a fully-duplicate segment.",
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_before,
            msg=(
                "Already-delivered data must not be re-enqueued "
                "into '_rx_buffer'; the retransmit's payload "
                "duplicates bytes the application has already "
                "consumed (or will, on next 'recv()')."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="State must remain CLOSE_WAIT after a fully-duplicate retransmit.",
        )

    def test__close_active__fin_wait_1_unacceptable_segment_elicits_ack_per_rfc_3_10_7_4(self) -> None:
        """
        Ensure FIN_WAIT_1 emits an ACK reply on unacceptable
        inbound segments (e.g. a fully-duplicate retransmit
        with seq below RCV.NXT) rather than silently
        dropping them. State remains FIN_WAIT_1.

        Reference: RFC 9293 §3.10.7.4 (step 1 unacceptable-segment ACK).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends 50 bytes of data and we drain the delayed-ACK
        # so RCV.NXT advances.
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)
        self._advance(ms=200)

        # Application close() -> two ticks: state transition then
        # FIN emit. Final state: FIN_WAIT_1.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: close() must transition to FIN_WAIT_1.",
        )
        self.assertEqual(
            session._snd_seq.fin,
            LOCAL__ISS + 2,
            msg="Setup precondition: our FIN must have fired (SND.FIN = LOCAL__ISS + 2).",
        )

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        # Peer retransmits the original 50-byte data segment - seq
        # entirely below RCV.NXT, fully duplicate, unacceptable per
        # RFC §3.10.7.4 step 1.
        retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        retransmit_tx = self._drive_rx(frame=retransmit)

        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 1: an unacceptable segment "
                "in FIN_WAIT_1 MUST elicit an ACK reply with our "
                "current SND.NXT and RCV.NXT, the same way ESTABLISHED "
                "and CLOSE_WAIT handle it. PyTCP today drops the "
                "segment silently because '_tcp_fsm_fin_wait_1' has "
                "no acceptability check at the top."
            ),
        )
        ack_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=("An unacceptable segment is dropped after " "the ACK reply; SND.UNA must NOT advance."),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="State must remain FIN_WAIT_1 after a fully-duplicate retransmit.",
        )

    def test__close_active__fin_wait_2_unacceptable_segment_elicits_ack_per_rfc_3_10_7_4(self) -> None:
        """
        Ensure FIN_WAIT_2 emits an ACK reply on unacceptable
        inbound segments rather than silently dropping them.
        State remains FIN_WAIT_2.

        Reference: RFC 9293 §3.10.7.4 (step 1 unacceptable-segment ACK).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)
        self._advance(ms=200)

        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        # Peer ACKs our FIN -> FIN_WAIT_2.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 50,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="Setup precondition: peer's ACK of our FIN must transition to FIN_WAIT_2.",
        )

        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        retransmit_tx = self._drive_rx(frame=retransmit)

        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=("An unacceptable segment in FIN_WAIT_2 MUST " "elicit an ACK reply rather than being dropped."),
        )
        ack_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="State must remain FIN_WAIT_2 after a fully-duplicate retransmit.",
        )

    def test__close_passive__last_ack_unacceptable_segment_elicits_ack_per_rfc_3_10_7_4(self) -> None:
        """
        Ensure LAST_ACK emits an ACK reply on unacceptable
        inbound segments rather than silently dropping them.
        State remains LAST_ACK.

        Reference: RFC 9293 §3.10.7.4 (step 1 unacceptable-segment ACK).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)
        self._advance(ms=200)

        # Peer FIN -> CLOSE_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 50,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: peer's FIN must transition to CLOSE_WAIT.",
        )

        # Application close() in CLOSE_WAIT -> deferred LAST_ACK.
        # First tick transitions CLOSE_WAIT -> LAST_ACK; second
        # tick fires our FIN.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: close() in CLOSE_WAIT must transition to LAST_ACK.",
        )

        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        retransmit_tx = self._drive_rx(frame=retransmit)

        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 1: an unacceptable segment "
                "in LAST_ACK MUST elicit an ACK reply. PyTCP today "
                "drops it silently because '_tcp_fsm_last_ack' has "
                "no acceptability check at the top."
            ),
        )
        ack_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="State must remain LAST_ACK after a fully-duplicate retransmit.",
        )

    def test__close_active__fin_wait_1_unacceptable_ack_beyond_snd_max_triggers_empty_ack(self) -> None:
        """
        Ensure FIN_WAIT_1's ACK-only handler emits an
        empty-ACK reply when peer sends 'tcp__ack > SND.MAX'.
        State remains FIN_WAIT_1.

        Reference: RFC 9293 §3.10.7.4 (step 5 ACK acknowledging unsent data).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1.",
        )

        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        peer_unacceptable_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 0xDEAD,
            flags=("ACK",),
            win=PEER__WIN,
        )
        unacceptable_ack_inline = self._drive_rx(frame=peer_unacceptable_ack)

        self.assertEqual(
            len(unacceptable_ack_inline),
            1,
            msg=(
                "An ACK acknowledging unsent data "
                "('SEG.ACK > SND.NXT') in FIN_WAIT_1 MUST "
                "elicit an empty-ACK reply."
            ),
        )
        ack_probe = self._parse_tx(unacceptable_ack_inline[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="State must remain FIN_WAIT_1 after an unacceptable ACK.",
        )

    def test__close_active__fin_wait_2_unacceptable_ack_beyond_snd_max_triggers_empty_ack(self) -> None:
        """
        Ensure FIN_WAIT_2's ACK-only handler emits an
        empty-ACK reply when peer sends 'tcp__ack > SND.MAX'.
        State remains FIN_WAIT_2.

        Reference: RFC 9293 §3.10.7.4 (step 5 ACK acknowledging unsent data).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)

        # Peer ACKs our FIN -> FIN_WAIT_2.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="Setup precondition: state must be FIN_WAIT_2.",
        )

        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        peer_unacceptable_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 0xDEAD,
            flags=("ACK",),
            win=PEER__WIN,
        )
        unacceptable_ack_inline = self._drive_rx(frame=peer_unacceptable_ack)

        self.assertEqual(
            len(unacceptable_ack_inline),
            1,
            msg=(
                "An ACK acknowledging unsent data "
                "('SEG.ACK > SND.NXT') in FIN_WAIT_2 MUST "
                "elicit an empty-ACK reply."
            ),
        )
        ack_probe = self._parse_tx(unacceptable_ack_inline[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="State must remain FIN_WAIT_2 after an unacceptable ACK.",
        )

    def test__close_passive__last_ack_unacceptable_ack_beyond_snd_max_triggers_empty_ack(self) -> None:
        """
        Ensure LAST_ACK's ACK-only handler emits an
        empty-ACK reply when peer sends 'tcp__ack > SND.MAX'.
        State remains LAST_ACK.

        Reference: RFC 9293 §3.10.7.4 (step 5 ACK acknowledging unsent data).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Peer FIN -> CLOSE_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: peer's FIN must transition to CLOSE_WAIT.",
        )
        # Application close() in CLOSE_WAIT -> LAST_ACK.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK.",
        )

        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        peer_unacceptable_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,  # past peer's FIN
            ack=LOCAL__ISS + 0xDEAD,
            flags=("ACK",),
            win=PEER__WIN,
        )
        unacceptable_ack_inline = self._drive_rx(frame=peer_unacceptable_ack)

        self.assertEqual(
            len(unacceptable_ack_inline),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 5: an ACK acknowledging "
                "unsent data ('SEG.ACK > SND.NXT') in LAST_ACK "
                "MUST elicit an empty-ACK reply."
            ),
        )
        ack_probe = self._parse_tx(unacceptable_ack_inline[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="State must remain LAST_ACK after an unacceptable ACK.",
        )

    def test__close_passive__close_wait_post_fin_data_elicits_ack_without_enqueue(self) -> None:
        """
        Ensure that when peer sends data after their own FIN
        in CLOSE_WAIT (a protocol violation), the receiver
        emits an empty ACK so peer's retransmit machinery
        backs off, but does NOT enqueue the data into
        '_rx_buffer' or advance RCV.NXT — CLOSE_WAIT is not
        a segment-text-delivery state. State stays CLOSE_WAIT.

        Reference: RFC 9293 §3.10.7.4 (segment text delivery, post-half-close).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Step 2: peer FIN+ACK -> CLOSE_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: state must be CLOSE_WAIT after peer FIN.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 2,
            msg=("Setup precondition: RCV.NXT must have advanced past " "peer's FIN to PEER__ISS+2."),
        )
        rx_buffer_before = bytes(session._rx_buffer)
        rcv_nxt_before = session._rcv_seq.nxt

        # Step 3: peer sends post-FIN data at seq == RCV.NXT.
        # RFC violation by peer, but PyTCP must respond
        # gracefully.
        post_fin_data = b"X" * 50
        peer_post_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,  # == RCV.NXT
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=post_fin_data,
        )
        post_fin_tx = self._drive_rx(frame=peer_post_fin)

        # Spec: exactly one ACK fires inline.
        self.assertEqual(
            len(post_fin_tx),
            1,
            msg=(
                "Peer's post-FIN data segment in CLOSE_WAIT MUST "
                "elicit exactly one outbound ACK so peer's "
                "retransmit machinery backs off. Today the "
                "regular-data branch's 'not packet_rx_md.tcp__data' "
                "clause makes the segment fall through to silent "
                "drop. Fix: drop the clause and add an explicit "
                f"'data in CLOSE_WAIT' ACK-without-enqueue path. Got: {post_fin_tx!r}"
            ),
        )
        ack_probe = self._parse_tx(post_fin_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            ack=rcv_nxt_before,
        )

        # Spec: '_rx_buffer' is unchanged - the data must not
        # leak past peer's FIN into the application's view of
        # the stream.
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_before,
            msg=(
                "Peer's post-FIN data MUST NOT be enqueued into "
                "'_rx_buffer'. Application's recv() returns b\"\" "
                "after peer's FIN signals EOF; appending fresh "
                "bytes after that signal breaks BSD socket "
                "semantics. RFC 9293 §3.10.7.4 step 7 lists only "
                "ESTABLISHED / FIN-WAIT-1 / FIN-WAIT-2 as the "
                "states that deliver segment text - CLOSE_WAIT "
                "is NOT among them."
            ),
        )

        # Spec: 'RCV.NXT' is unchanged - accepting the data into
        # the receive sequence space would violate the "FIN
        # consumes the last byte of seq space" invariant.
        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_before,
            msg=(
                "Peer's post-FIN data MUST NOT advance RCV.NXT - "
                "RCV.NXT was set to 'peer_fin_seq + 1' when peer's "
                "FIN was processed; advancing it further would "
                "treat post-FIN bytes as legitimate sequence space."
            ),
        )

        # Spec: state stays CLOSE_WAIT - the post-FIN data is
        # an anomaly, not a state-transition trigger.
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="State must remain CLOSE_WAIT after post-FIN data.",
        )

    def test__close_passive__close_wait_ooo_post_fin_data_must_not_queue(self) -> None:
        """
        Ensure that when peer sends OOO data in CLOSE_WAIT
        (past their own FIN, with seq > RCV.NXT), the
        segment is NOT stored in '_ooo_packet_queue' (no
        drain path exists in CLOSE_WAIT). A bare cum-ACK
        nudges peer's retransmit machinery toward backoff;
        '_rx_buffer', RCV.NXT, and OOO queue stay unchanged.

        Reference: RFC 9293 §3.10.7.4 (segment text delivery, post-half-close).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: state must be CLOSE_WAIT after peer FIN.",
        )
        rx_buffer_before = bytes(session._rx_buffer)
        rcv_nxt_before = session._rcv_seq.nxt
        ooo_count_before = len(session._ooo_packet_queue)
        self.assertEqual(
            ooo_count_before,
            0,
            msg="Setup precondition: OOO queue must be empty after the FIN-only transition.",
        )

        # Peer sends OOO data segment past their own FIN.
        ooo_payload = b"X" * 50
        peer_ooo_post_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,  # > RCV.NXT (= PEER__ISS+2)
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=ooo_payload,
        )
        ooo_tx = self._drive_rx(frame=peer_ooo_post_fin)

        self.assertEqual(
            len(ooo_tx),
            1,
            msg=(
                "Peer's OOO post-FIN data segment in CLOSE_WAIT "
                "MUST elicit exactly one outbound ACK; the queue-"
                "size assertion below pins that the segment is "
                "not stored."
            ),
        )
        ack_probe = self._parse_tx(ooo_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            ack=rcv_nxt_before,
        )

        # Spec: the segment must NOT be stored in the OOO queue.
        # Today's code stores it indefinitely (no path to drain
        # because RCV.NXT cannot advance past peer's FIN).
        self.assertEqual(
            len(session._ooo_packet_queue),
            0,
            msg=(
                "Peer's OOO post-FIN data MUST NOT be stored in "
                "'_ooo_packet_queue'. RCV.NXT in CLOSE_WAIT can "
                "NEVER advance past peer's FIN seq + 1 (peer "
                "FIN'd so the receive sequence space is capped), "
                "so any OOO entry stored here is a permanent leak "
                "with no drain path. Today the branch at "
                "'tcp__session.py:2704' stores the segment "
                "regardless. Fix: replace the OOO-storage branch "
                "with a bare ACK reply."
            ),
        )

        # Spec: '_rx_buffer' unchanged (no enqueue) and RCV.NXT
        # unchanged (no advance).
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_before,
            msg="Peer's OOO post-FIN data MUST NOT be enqueued into '_rx_buffer'.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_before,
            msg="Peer's OOO post-FIN data MUST NOT advance RCV.NXT.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="State must remain CLOSE_WAIT after OOO post-FIN data.",
        )


class TestTcpClose__IdempotencyHalfClose(TcpTestCase):
    """
    Integration tests for the RFC 9293 §3.10.4 'CLOSE in
    half-close states' invariant: a second 'close()' call after
    the connection has already entered FIN_WAIT_1 / FIN_WAIT_2
    / CLOSING / LAST_ACK / TIME_WAIT MUST NOT emit a SECOND
    distinct FIN, MUST NOT corrupt FSM state, and MUST NOT
    interfere with timers (e.g. cancel TIME_WAIT). The first
    FIN may be retransmitted by the existing retransmit
    machinery; that is permitted by the RFC.

    PyTCP's per-state FSM modules for the five half-close
    states have NO SysCall.CLOSE handler, so the syscall is
    silently dropped (the canonical no-op in PyTCP). These
    tests pin that no-op behavior so a future refactor that
    accidentally re-fires the FIN-emission logic on a second
    close() call is caught.
    """

    def _drive_to_fin_wait_1(self, *, iss: int, peer_iss: int) -> TcpSession:
        """ESTABLISHED + close() + 2 ticks -> FIN_WAIT_1 with FIN sent."""

        session = self._drive_handshake_to_established(iss=iss, peer_iss=peer_iss)
        session.close()
        self._advance(ms=1)  # transition tick
        self._advance(ms=1)  # FIN emit tick
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=f"Setup invariant: session must be in FIN_WAIT_1 with FIN " f"sent, got {session.state}",
        )
        return session

    def test__close_idempotent__close_in_fin_wait_1_does_not_emit_second_fin(self) -> None:
        """
        Ensure a second close() call in FIN_WAIT_1 is a silent
        no-op: no new FIN at a fresh seq is emitted; the first
        FIN's retransmit cadence is unaffected.

        Reference: RFC 9293 §3.10.4 (CLOSE call is idempotent across half-close states).
        """

        session = self._drive_to_fin_wait_1(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        snd_nxt_pre = session._snd_seq.nxt
        snd_max_pre = session._snd_seq.max

        session.close()
        idempotent_tx = self._advance(ms=1)

        for frame in idempotent_tx:
            probe = self._parse_tx(frame)
            self.assertEqual(
                probe.seq,
                LOCAL__ISS + 1,
                msg=(
                    "Any TX after a redundant close() in "
                    "FIN_WAIT_1 MUST be a retransmit of the "
                    f"original FIN at seq=LOCAL__ISS+1={LOCAL__ISS + 1}, "
                    f"NOT a second FIN at a higher seq. Got "
                    f"seq={probe.seq}."
                ),
            )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_pre,
            msg="Idempotent close() in FIN_WAIT_1 MUST NOT advance SND.NXT.",
        )
        self.assertEqual(
            session._snd_seq.max,
            snd_max_pre,
            msg="Idempotent close() in FIN_WAIT_1 MUST NOT advance SND.MAX.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Idempotent close() in FIN_WAIT_1 MUST NOT change FSM state.",
        )

    def test__close_idempotent__close_in_fin_wait_2_does_not_emit_anything(self) -> None:
        """
        Ensure a second close() call in FIN_WAIT_2 is a silent
        no-op: peer already ACKed our FIN so there is nothing
        to retransmit; the idle session stays quiet.

        Reference: RFC 9293 §3.10.4 (CLOSE call is idempotent across half-close states).
        """

        session = self._drive_to_fin_wait_1(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        self.assertIs(session.state, FsmState.FIN_WAIT_2, msg=f"Setup: state={session.state}")

        snd_nxt_pre = session._snd_seq.nxt
        session.close()
        idempotent_tx = self._advance(ms=1)

        self.assertEqual(
            idempotent_tx,
            [],
            msg=(
                "Idempotent close() in FIN_WAIT_2 MUST NOT "
                "emit any segment. Peer already ACKed our FIN; "
                "nothing to retransmit. Got "
                f"{len(idempotent_tx)} outbound frame(s)."
            ),
        )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_pre,
            msg="Idempotent close() in FIN_WAIT_2 MUST NOT advance SND.NXT.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="Idempotent close() in FIN_WAIT_2 MUST NOT change FSM state.",
        )

    def test__close_idempotent__close_in_closing_does_not_emit_second_fin(self) -> None:
        """
        Ensure a second close() call in CLOSING (simultaneous-
        close path with both sides having sent FIN) is a
        silent no-op: no second FIN is emitted at a fresh seq.

        Reference: RFC 9293 §3.10.4 (CLOSE call is idempotent across half-close states).
        """

        session = self._drive_to_fin_wait_1(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Peer's FIN crosses our FIN on the wire (simultaneous
        # close). Per the FSM: FIN_WAIT_1 + peer FIN before peer
        # ACKs ours -> CLOSING.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,  # peer hasn't seen our FIN's seq yet
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSING,
            msg=f"Simultaneous-close must deterministically reach CLOSING; got {session.state}.",
        )

        snd_nxt_pre = session._snd_seq.nxt
        session.close()
        idempotent_tx = self._advance(ms=1)

        for frame in idempotent_tx:
            probe = self._parse_tx(frame)
            self.assertEqual(
                probe.seq,
                LOCAL__ISS + 1,
                msg=(
                    "Idempotent close() in CLOSING MUST NOT " "emit a second FIN at a new seq. Got " f"seq={probe.seq}."
                ),
            )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_pre,
            msg="Idempotent close() in CLOSING MUST NOT advance SND.NXT.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSING,
            msg="Idempotent close() in CLOSING MUST NOT change FSM state.",
        )

    def test__close_idempotent__close_in_last_ack_does_not_emit_second_fin(self) -> None:
        """
        Ensure a second close() call in LAST_ACK (passive-
        close path) is a silent no-op: no second FIN at a
        new seq is emitted.

        Reference: RFC 9293 §3.10.4 (CLOSE call is idempotent across half-close states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Peer FINs first -> CLOSE_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(session.state, FsmState.CLOSE_WAIT, msg=f"Setup: state={session.state}")

        # App close() -> LAST_ACK with our FIN sent.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg=f"Setup invariant: state must be LAST_ACK after CLOSE in " f"CLOSE_WAIT, got {session.state}",
        )

        snd_nxt_pre = session._snd_seq.nxt
        session.close()  # the redundant call under test
        idempotent_tx = self._advance(ms=1)

        for frame in idempotent_tx:
            probe = self._parse_tx(frame)
            self.assertEqual(
                probe.seq,
                LOCAL__ISS + 1,
                msg=(
                    "Idempotent close() in LAST_ACK MUST NOT "
                    "emit a second FIN at a new seq. Got "
                    f"seq={probe.seq}."
                ),
            )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_pre,
            msg="Idempotent close() in LAST_ACK MUST NOT advance SND.NXT.",
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Idempotent close() in LAST_ACK MUST NOT change FSM state.",
        )

    def test__close_idempotent__close_in_time_wait_does_not_disturb_timer_or_state(self) -> None:
        """
        Ensure a redundant close() call in TIME_WAIT does not
        cancel the TIME_WAIT timer, emit any segment, or
        change FSM state. The 2*MSL delay continues to count
        down to its natural expiry.

        Reference: RFC 9293 §3.4.2 (TIME-WAIT 2*MSL).
        Reference: RFC 9293 §3.10.4 (CLOSE call is idempotent in TIME_WAIT).
        """

        session = self._drive_to_fin_wait_1(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state, FsmState.TIME_WAIT, msg=f"Setup invariant: state must be TIME_WAIT, got {session.state}"
        )

        time_wait_timer_name = f"{session}-time_wait"
        self.assertIn(
            time_wait_timer_name,
            self._pending_session_timers(session),
            msg="Setup invariant: TIME_WAIT timer MUST be registered.",
        )
        timer_remaining_pre = self._pending_session_timers(session)[time_wait_timer_name]

        session.close()
        idempotent_tx = self._advance(ms=1)

        self.assertEqual(
            idempotent_tx,
            [],
            msg=(
                "Idempotent close() in TIME_WAIT MUST NOT "
                "emit any segment. Got "
                f"{len(idempotent_tx)} outbound frame(s)."
            ),
        )
        self.assertIn(
            time_wait_timer_name,
            self._pending_session_timers(session),
            msg=(
                "Idempotent close() MUST NOT cancel the "
                "TIME_WAIT timer. The 2*MSL delay must run "
                "to natural expiry."
            ),
        )
        timer_remaining_post = self._pending_session_timers(session)[time_wait_timer_name]
        # The advance(ms=1) above should have decremented the
        # timer by 1 ms; if close() cancelled-and-rearmed it,
        # the value would jump to TCP__TIME_WAIT__DELAY_MS (much
        # larger).
        self.assertLessEqual(
            timer_remaining_post,
            timer_remaining_pre,
            msg=(
                "Idempotent close() MUST NOT re-arm the "
                "TIME_WAIT timer. Pre-close remaining: "
                f"{timer_remaining_pre} ms; post-close: "
                f"{timer_remaining_post} ms (a re-arm would "
                "push remaining BACK UP)."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg="Idempotent close() in TIME_WAIT MUST NOT change FSM state.",
        )
