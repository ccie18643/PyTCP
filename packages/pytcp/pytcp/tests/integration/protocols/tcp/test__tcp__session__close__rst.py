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
This module contains integration tests for RST-driven termination
of a synchronized TCP session in the 'TcpSession' state machine.
A peer-issued RST in any synchronized state drops the connection
to CLOSED with no graceful 4-way handshake; the application's
pending 'recv()' / 'send()' calls observe the abort.

The tests cover:

    - RST acceptance per RFC 9293 §3.10.7.4 / RFC 5961 §3:
        * RCV.NXT == SEG.SEQ           -> reset connection
        * in-window but != RCV.NXT     -> challenge ACK
        * out of receive window        -> silently drop
    - State coverage: ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2,
      CLOSE_WAIT, LAST_ACK.

Reference RFCs:
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 9293 §3.5        Reset Generation / Acceptance
    RFC 5961 §3          Mitigating Blind RST Attacks (folded
                         into 9293; cited for the original threat
                         model)

pytcp/tests/integration/protocols/tcp/test__tcp__session__close__rst.py

ver 3.0.10
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__enums import FsmState
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


class TestTcpClose__Rst(TcpTestCase):
    """
    Integration tests for RST-driven termination of synchronized
    TCP sessions across all close-related states.
    """

    def test__close_rst__rst_in_established_drops_to_closed_and_wakes_blocked_recv(self) -> None:
        """
        Ensure a peer-issued RST+ACK on a synchronized
        ESTABLISHED session with seq == RCV.NXT drops the FSM
        to CLOSED with no outbound segment, sets
        '_event__rx_buffer' so blocked recv() / send()
        callers wake, and unregisters the socket from
        'stack.sockets'.

        Reference: RFC 9293 §3.10.7.4 (RST handling in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED before RST.",
        )
        self.assertIn(
            socket_id,
            stack.sockets,
            msg="Setup precondition: socket must be registered before RST.",
        )

        # Peer sends RST+ACK at the canonical "matches RCV.NXT,
        # in-window ACK" position - the unambiguous abort signal.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "Peer's RST+ACK must produce NO outbound segment. "
                "RFC 9293 §3.5.2 / §3.10.7.4 - 'an incoming segment "
                "containing a RST is discarded after processing'. The "
                "receiver does not generate any reply to a RST."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with seq==RCV.NXT and in-window ack "
                "must transition state to CLOSED per RFC 9293 §3.10.7.4."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' (line 540) "
                "so the 4-tuple can be reused for a fresh connection."
            ),
        )
        self.assertTrue(
            session._event__rx_buffer.is_set(),
            msg=(
                "The RST handler must set '_event__rx_buffer' (line "
                "1497) so a blocked 'recv()' wakes up and observes "
                "the connection-reset signal. RFC 9293 §3.10.7.4: "
                "'any outstanding RECEIVEs and SEND should receive "
                '"reset" responses ... Users should also receive '
                'an unsolicited general "connection reset" signal\'.'
            ),
        )

    def test__close_rst__rst_in_fin_wait_1_drops_to_closed(self) -> None:
        """
        Ensure a peer-issued RST+ACK arriving in FIN_WAIT_1
        with seq == RCV.NXT and ack in [SND.UNA, SND.MAX]
        drops the connection to CLOSED with no outbound
        segment and unregisters the socket.

        Reference: RFC 9293 §3.10.7.4 (RST handling in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        # Walk into FIN_WAIT_1 by closing and ticking through the
        # transition + FIN-emit ticks.
        session.close()
        self._advance(ms=1)
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: FIN_WAIT_1's first tick must emit our FIN+ACK.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1 after the FIN-emit tick.",
        )
        self.assertEqual(
            session._snd_seq.max,
            LOCAL__ISS + 2,
            msg=("Setup precondition: 'SND.MAX' must reflect the " "post-FIN sequence number (LOCAL__ISS + 2)."),
        )

        # Peer sends RST+ACK with seq matching RCV.NXT and ack in
        # the valid send window (here at LOCAL__ISS + 2, the FIN's
        # post-byte boundary).
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "Peer's RST+ACK in FIN_WAIT_1 must produce NO "
                "outbound segment - RST is unilateral and the "
                "receiver does not reply."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with seq==RCV.NXT and in-window ack "
                "while in FIN_WAIT_1 must transition state to CLOSED "
                "per RFC 9293 §3.10.7.4. The graceful 4-way close "
                "is aborted; we do not wait for the FIN+ACK exchange."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' so the "
                "4-tuple can be reused."
            ),
        )

    def test__close_rst__rst_in_fin_wait_2_drops_to_closed(self) -> None:
        """
        Ensure a peer-issued RST+ACK arriving in FIN_WAIT_2
        with seq == RCV.NXT and ack in [SND.UNA, SND.MAX]
        drops the connection to CLOSED with no outbound
        segment and unregisters the socket.

        Reference: RFC 9293 §3.10.7.4 (RST handling in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        # Walk into FIN_WAIT_2: close, transition tick, FIN-emit
        # tick, then peer ACKs our FIN.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1 after FIN-emit tick.",
        )

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
            msg="Setup precondition: state must be FIN_WAIT_2 after peer ACKs our FIN.",
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 2,
            msg="Setup precondition: 'SND.UNA' must have advanced past our FIN.",
        )

        # Peer sends RST+ACK at the canonical match position.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg="Peer's RST+ACK in FIN_WAIT_2 must produce NO outbound segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with seq==RCV.NXT and in-window ack "
                "while in FIN_WAIT_2 must transition state to CLOSED "
                "per RFC 9293 §3.10.7.4."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=("On transition to CLOSED, '_change_state' must " "unregister the socket from 'stack.sockets'."),
        )

    def test__close_rst__rst_with_ack_in_close_wait_must_reset_per_rfc9293(self) -> None:
        """
        Ensure a peer-issued RST+ACK arriving in CLOSE_WAIT
        (peer closed its half; we have not yet called close())
        drops the connection to CLOSED with no outbound
        segment, regardless of whether the ACK flag is set
        on the RST segment.

        Reference: RFC 9293 §3.10.7.4 (RST handling in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        # Walk into CLOSE_WAIT by having peer send FIN+ACK first.
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
            msg="Setup precondition: state must be CLOSE_WAIT after peer's FIN+ACK.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 2,
            msg="Setup precondition: 'RCV.NXT' must have advanced past peer's FIN.",
        )

        # Tick to fire the delayed ACK of peer's FIN. This drains
        # the housekeeping state and leaves the session in a clean
        # CLOSE_WAIT.
        self._advance(ms=1)

        # Peer sends RST+ACK at the canonical "matches RCV.NXT,
        # in-window ACK" position.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "Peer's RST+ACK in CLOSE_WAIT must produce NO "
                "outbound segment - RST is unilateral and the "
                "receiver does not reply."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK in CLOSE_WAIT MUST transition state "
                "to CLOSED per RFC 9293 §3.10.7.4 - any RST in a "
                "synchronized state aborts the connection regardless "
                "of the ACK flag. Current code's CLOSE_WAIT RST "
                "handler (lines 1752-1767) only matches pure RST "
                "(no ACK), so it ignores the canonical RST+ACK "
                "shape that conformant TCPs send."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' so the "
                "4-tuple can be reused."
            ),
        )

    def test__close_rst__rst_in_last_ack_drops_to_closed(self) -> None:
        """
        Ensure a peer-issued RST+ACK arriving in LAST_ACK
        (passive-close path; we sent our FIN and are
        awaiting peer's ACK of our FIN) drops the connection
        to CLOSED with no outbound segment and unregisters
        the socket.

        Reference: RFC 9293 §3.10.7.4 (RST handling in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        # Walk into LAST_ACK via the passive-close path.
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
            msg="Setup precondition: state must be CLOSE_WAIT after peer's FIN+ACK.",
        )

        # Tick to drain delayed ACK.
        self._advance(ms=1)

        # close() then transition tick + FIN-emit tick.
        session.close()
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK after the transition tick.",
        )
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: LAST_ACK's first tick must emit our FIN+ACK.",
        )
        self.assertEqual(
            session._snd_seq.max,
            LOCAL__ISS + 2,
            msg=("Setup precondition: 'SND.MAX' must reflect the " "post-FIN sequence number (LOCAL__ISS + 2)."),
        )

        # Peer sends RST+ACK at the canonical match position.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg="Peer's RST+ACK in LAST_ACK must produce NO outbound segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with seq==RCV.NXT and in-window ack "
                "while in LAST_ACK must transition state to CLOSED "
                "per RFC 9293 §3.10.7.4."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=("On transition to CLOSED, '_change_state' must " "unregister the socket from 'stack.sockets'."),
        )

    def test__close_rst__bare_rst_in_established_must_drop_to_closed(self) -> None:
        """
        Ensure a peer-issued bare RST (RST flag set, ACK
        flag cleared) with seq == RCV.NXT in ESTABLISHED
        aborts the connection: state drops to CLOSED, no
        outbound segment, socket unregistered. The ACK flag
        is not a precondition for valid RST processing;
        both bare RST and RST+ACK are spec-legal abort
        signals.

        Reference: RFC 9293 §3.10.7.4 (RST validation by SEQ window in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED before RST.",
        )
        self.assertIn(
            socket_id,
            stack.sockets,
            msg="Setup precondition: socket must be registered before RST.",
        )

        # Peer sends a BARE RST (no ACK flag) at the canonical
        # "matches RCV.NXT" position. 'ack=0' is meaningless for a
        # bare RST and ignored by '_check_rst_acceptability' per
        # the bare-RST short-circuit at line ~1014-1021.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=0,
            flags=("RST",),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "Peer's bare RST must produce NO outbound segment. "
                "RFC 9293 §3.5.2 / §3.10.7.4 - 'an incoming segment "
                "containing a RST is discarded after processing'."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's bare RST (no ACK flag) with seq==RCV.NXT MUST "
                "abort the connection per RFC 9293 §3.10.7.4 - the "
                "RST validity check is a pure SEG.SEQ window check; "
                "the ACK flag is not a precondition. Today the "
                "ESTABLISHED RST branch predicate "
                "'all({tcp__flag_rst, tcp__flag_ack})' silently drops "
                "bare RSTs, leaving the connection stuck in "
                "ESTABLISHED. Fix: replace the predicate with bare "
                "'tcp__flag_rst', mirroring CLOSE_WAIT / SYN_RCVD. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On the bare-RST-driven transition to CLOSED, "
                "'_change_state' must unregister the socket from "
                "'stack.sockets' so the 4-tuple can be reused. "
                "Today the predicate gate prevents the transition "
                "from happening at all, leaving the socket "
                "registered indefinitely."
            ),
        )

    def test__close_rst__bare_rst_in_fin_wait_1_must_drop_to_closed(self) -> None:
        """
        Ensure a peer-issued bare RST with seq == RCV.NXT in
        FIN_WAIT_1 aborts the connection: state drops to
        CLOSED, no outbound segment, socket unregistered.

        Reference: RFC 9293 §3.10.7.4 (RST validation by SEQ window in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        session.close()
        self._advance(ms=1)
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: FIN_WAIT_1's first tick must emit our FIN+ACK.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1 after the FIN-emit tick.",
        )

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=0,
            flags=("RST",),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=("Peer's bare RST in FIN_WAIT_1 must produce NO " "outbound segment."),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's bare RST (no ACK flag) with seq==RCV.NXT in "
                "FIN_WAIT_1 MUST abort the connection per RFC 9293 "
                "§3.10.7.4. Today the FIN_WAIT_1 RST branch predicate "
                "'all({tcp__flag_rst, tcp__flag_ack})' silently drops "
                "bare RSTs. Fix: replace with bare 'tcp__flag_rst'. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On the bare-RST-driven transition to CLOSED, " "the socket must be unregistered from 'stack.sockets'."
            ),
        )

    def test__close_rst__bare_rst_in_fin_wait_2_must_drop_to_closed(self) -> None:
        """
        Ensure a peer-issued bare RST with seq == RCV.NXT in
        FIN_WAIT_2 aborts the connection: state drops to
        CLOSED, no outbound segment, socket unregistered.

        Reference: RFC 9293 §3.10.7.4 (RST validation by SEQ window in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
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
            msg="Setup precondition: state must be FIN_WAIT_2 after peer ACKs our FIN.",
        )

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=0,
            flags=("RST",),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg="Peer's bare RST in FIN_WAIT_2 must produce NO outbound segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's bare RST with seq==RCV.NXT in "
                "FIN_WAIT_2 MUST abort the connection. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertNotIn(socket_id, stack.sockets, msg="Socket must be unregistered after CLOSED transition.")

    def test__close_rst__bare_rst_in_last_ack_must_drop_to_closed(self) -> None:
        """
        Ensure a peer-issued bare RST with seq == RCV.NXT in
        LAST_ACK aborts the connection: state drops to
        CLOSED, no outbound segment, socket unregistered.

        Reference: RFC 9293 §3.10.7.4 (RST validation by SEQ window in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

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
            msg="Setup precondition: state must be CLOSE_WAIT after peer's FIN+ACK.",
        )
        self._advance(ms=1)

        session.close()
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK after the transition tick.",
        )
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: LAST_ACK's first tick must emit our FIN+ACK.",
        )

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=0,
            flags=("RST",),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg="Peer's bare RST in LAST_ACK must produce NO outbound segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's bare RST with seq==RCV.NXT in "
                "LAST_ACK MUST abort the connection. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertNotIn(socket_id, stack.sockets, msg="Socket must be unregistered after CLOSED transition.")

    def test__close_rst__in_window_rst_not_at_rcv_nxt_must_elicit_challenge_ack(self) -> None:
        """
        Ensure that a peer-issued RST with a sequence number that
        falls within the current receive window but does not
        exactly match RCV.NXT elicits a challenge ACK rather
        than being silently dropped or accepted as a reset.
        The challenge ACK carries seq=SND.NXT, ack=RCV.NXT,
        flags={ACK}; state stays ESTABLISHED.

        Reference: RFC 9293 §3.10.7.4 (RST acceptance three-way classification).
        Reference: RFC 5961 §3 (blind RST mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1,
            msg="Setup precondition: RCV.NXT after handshake must be PEER__ISS + 1.",
        )

        # Peer sends RST+ACK at seq = RCV.NXT + 10 - 10 bytes past
        # the next-expected, but well within the 65535-byte receive
        # window. This is the RFC 5961 §3.2 / RFC 9293 §3.10.7.4
        # case (2) input: in-window but mismatched seq.
        bogus_offset = 10
        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + bogus_offset,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        # The spec encoding: exactly one challenge ACK fires.
        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq MUST elicit "
                "exactly one challenge ACK per RFC 9293 §3.10.7.4 "
                "case (2) / RFC 5961 §3.2. Current code's strict "
                "'seq == rcv_nxt' check (line 1494) makes the RST+ACK "
                "branch fall through with no reply, leaving the "
                "blind-RST attack mitigation absent."
            ),
        )

        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
        )

        # The RST is REJECTED. State stays ESTABLISHED.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "An in-window-but-mismatched RST MUST NOT reset the "
                "connection - only an exact 'seq == RCV.NXT' RST "
                "qualifies for case (1)'s reset. State must remain "
                "ESTABLISHED while the challenge ACK invites the peer "
                "to retransmit at the correct seq if the RST is "
                "legitimate."
            ),
        )

    def test__close_rst__in_window_rst_in_fin_wait_1_must_elicit_challenge_ack(self) -> None:
        """
        Ensure FIN_WAIT_1's RST handler emits a challenge ACK
        on an in-window-but-mismatched RST (seq != RCV.NXT)
        rather than silently dropping. State stays FIN_WAIT_1.

        Reference: RFC 9293 §3.10.7.4 (RST acceptance three-way classification).
        Reference: RFC 5961 §3 (blind RST mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1.",
        )
        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 10,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq in "
                "FIN_WAIT_1 MUST elicit exactly one challenge ACK "
                "per RFC 9293 §3.10.7.4 case (2). Today the RST "
                "handler's strict 'seq == rcv_nxt' check makes the "
                "branch fall through with no reply."
            ),
        )
        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="In-window-mismatched RST must NOT reset the connection in FIN_WAIT_1.",
        )

    def test__close_rst__in_window_rst_in_fin_wait_2_must_elicit_challenge_ack(self) -> None:
        """
        Ensure FIN_WAIT_2's RST handler emits a challenge ACK
        on an in-window-but-mismatched RST (seq != RCV.NXT)
        rather than silently dropping. State stays FIN_WAIT_2.

        Reference: RFC 9293 §3.10.7.4 (RST acceptance three-way classification).
        Reference: RFC 5961 §3 (blind RST mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

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

        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 10,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq in "
                "FIN_WAIT_2 MUST elicit exactly one challenge ACK "
                "per RFC 9293 §3.10.7.4 case (2)."
            ),
        )
        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="In-window-mismatched RST must NOT reset the connection in FIN_WAIT_2.",
        )

    def test__close_rst__in_window_rst_in_close_wait_must_elicit_challenge_ack(self) -> None:
        """
        Ensure CLOSE_WAIT's RST handler emits a challenge ACK
        on an in-window-but-mismatched RST (seq != RCV.NXT)
        rather than silently dropping. State stays CLOSE_WAIT.

        Reference: RFC 9293 §3.10.7.4 (RST acceptance three-way classification).
        Reference: RFC 5961 §3 (blind RST mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Drive into CLOSE_WAIT via peer FIN+ACK.
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
            msg="Setup precondition: state must be CLOSE_WAIT.",
        )
        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=rcv_nxt_before + 10,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq in "
                "CLOSE_WAIT MUST elicit exactly one challenge ACK "
                "per RFC 9293 §3.10.7.4 case (2)."
            ),
        )
        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="In-window-mismatched RST must NOT reset the connection in CLOSE_WAIT.",
        )

    def test__close_rst__in_window_rst_in_last_ack_must_elicit_challenge_ack(self) -> None:
        """
        Ensure LAST_ACK's RST handler emits a challenge ACK
        on an in-window-but-mismatched RST (seq != RCV.NXT)
        rather than silently dropping. State stays LAST_ACK.

        Reference: RFC 9293 §3.10.7.4 (RST acceptance three-way classification).
        Reference: RFC 5961 §3 (blind RST mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Drive CLOSE_WAIT then LAST_ACK.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        session.close()
        self._advance(ms=1)  # CLOSE_WAIT → LAST_ACK transition tick
        self._advance(ms=1)  # FIN-emit tick
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK.",
        )
        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=rcv_nxt_before + 10,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq in "
                "LAST_ACK MUST elicit exactly one challenge ACK "
                "per RFC 9293 §3.10.7.4 case (2)."
            ),
        )
        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="In-window-mismatched RST must NOT reset the connection in LAST_ACK.",
        )

    def test__close_rst__session_teardown_unregisters_per_session_timer_entries(self) -> None:
        """
        Ensure that when a session terminates (state -> CLOSED
        via peer RST or any other path), per-session entries
        registered into 'stack.timer' are unregistered so they
        do not accumulate as stale entries on long-running
        stacks.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        # Send 100 bytes so a per-seq retransmit timer is armed.
        session.send(data=b"X" * 100)
        self._advance(ms=1)

        # Peer sends data so the delayed-ACK timer is armed.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"hello",
        )
        self._drive_rx(frame=peer_data)

        session_prefix = f"{session}"
        timers_before = {
            name: ms for name, ms in self._pending_session_timers(session).items() if name.startswith(session_prefix)
        }
        self.assertGreater(
            len(timers_before),
            0,
            msg=(
                "Setup precondition: at least one session-prefixed "
                "timer entry must be registered in 'stack.timer' "
                "after 'send()' and inbound peer-data have armed "
                "'-retransmit_seq-{seq}' and '-delayed_ack' entries. "
                f"Got: {timers_before}"
            ),
        )

        # Peer sends a clean RST. State -> CLOSED via
        # '_tcp_fsm_established's RST handler.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 5,  # RCV.NXT after we processed peer's 5-byte data
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_rst)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="Setup precondition: peer's clean RST must transition session to CLOSED.",
        )

        # The bug: per-session timer entries survive the session's
        # CLOSED transition.
        timers_after = {
            name: ms for name, ms in self._pending_session_timers(session).items() if name.startswith(session_prefix)
        }
        self.assertEqual(
            len(timers_after),
            0,
            msg=(
                "After the session has terminated (state -> CLOSED), "
                "every per-session entry in the session's "
                "'_timers._deadlines' map MUST be cleared. Today "
                f"the entries persist ({timers_after}). On a "
                "long-running stack handling many connection "
                "churns this accumulates as a slow memory leak. "
                "Fix: '_change_state' on CLOSED must pop every "
                "per-session entry."
            ),
        )

    def test__close_rst__session_teardown_releases_event_driven_timer_state(self) -> None:
        """
        Ensure that when a session terminates (state ->
        CLOSED) the event-driven timer state is fully released
        — the coalesced 'TcpTimerService' service handle is
        cancelled-and-None and its deadline map is empty — so
        no callback can fire on the dead session and it is
        GC-eligible (no dead-session ticks, no leak).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must reach ESTABLISHED.",
        )

        # Peer sends a clean RST. State -> CLOSED via
        # '_tcp_fsm_established's RST handler, which runs the
        # CLOSED teardown ('_cancel_all_timers').
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,  # RCV.NXT
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_rst)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="Setup precondition: peer's clean RST must transition session to CLOSED.",
        )

        # Post-migration teardown contract: no per-tick periodic
        # exists anymore; the session is driven by the coalesced
        # 'TcpTimerService' service handle + deadline map, both
        # of which '_cancel_all_timers' must release on CLOSED.
        # Otherwise a stale handle could fire 'tcp_fsm' on a
        # dead session (CPU per dead session) and pin it against
        # GC.
        self.assertIsNone(
            session._timers._service_handle,
            msg="On CLOSED the coalesced service handle MUST be cancelled and cleared to None.",
        )
        self.assertEqual(
            session._timers._deadlines,
            {},
            msg="On CLOSED the timer-service deadline map MUST be empty (every logical timer cancelled).",
        )
