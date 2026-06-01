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
This module contains integration tests for the simultaneous-close
path through the TCP FSM in the 'TcpSession' state machine, where
both peers send FIN before either acknowledges the other's FIN.
The trajectory is ESTABLISHED → FIN_WAIT_1 → CLOSING → TIME_WAIT
per RFC 9293 §3.10.4 / §3.10.7.4.

The active-close and passive-close paths are covered by
'close__normal.py'; the TIME_WAIT expiry mechanics are covered
by 'close__time_wait.py'.

Reference RFCs:
    RFC 9293 §3.10.4    CLOSE Call
    RFC 9293 §3.10.7.4  Synchronized state segment processing
    RFC 9293 §3.5       Closing a Connection (state diagram)

pytcp/tests/integration/protocols/tcp/test__tcp__session__close__simultaneous.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
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


class TestTcpClose__Simultaneous(TcpTestCase):
    """
    Integration tests for the simultaneous-close path where both
    peers send FIN before either acknowledges the other's FIN.
    """

    def test__close_simultaneous__both_sides_fin_walks_through_fin_wait_1_closing_time_wait(self) -> None:
        """
        Ensure the simultaneous-close path — where both peers
        send FIN before either has ACKed the other's FIN —
        walks the FSM through ESTABLISHED -> FIN_WAIT_1 ->
        CLOSING -> TIME_WAIT, with the inline ACK of peer's
        FIN emitted from FIN_WAIT_1 and the final transition
        to TIME_WAIT triggered by peer's ACK of our FIN.

        Reference: RFC 9293 §3.6 (closing a connection, simultaneous close).
        Reference: RFC 9293 §3.10.7.4 (CLOSING segment processing).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Application initiates close. Tick to fire the
        # ESTABLISHED -> FIN_WAIT_1 transition, then tick again to
        # emit our FIN+ACK.
        session.close()
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg="ESTABLISHED -> FIN_WAIT_1 transition tick must emit no segment.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="State must be FIN_WAIT_1 after the transition tick.",
        )

        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="FIN_WAIT_1's first timer tick must emit our FIN+ACK.",
        )
        our_fin = self._parse_tx(fin_tx[0])
        self._assert_segment(
            our_fin,
            flags=frozenset({"FIN", "ACK"}),
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
        )
        self.assertEqual(
            session._snd_seq.fin,
            LOCAL__ISS + 2,
            msg="'_snd_fin' must equal post-FIN 'SND.NXT' (LOCAL__ISS + 2).",
        )

        # Peer's FIN+ACK arrives but its ACK does NOT cover our FIN.
        # This is the defining characteristic of simultaneous close:
        # peer was closing concurrently and had not yet seen our FIN.
        peer_fin_simultaneous = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        peer_fin_inline = self._drive_rx(frame=peer_fin_simultaneous)

        # The FIN+ACK branch in FIN_WAIT_1 emits an inline ACK
        # acknowledging peer's FIN, then transitions to CLOSING
        # (because peer's ack < our SND.FIN).
        self.assertEqual(
            len(peer_fin_inline),
            1,
            msg=(
                "Peer's simultaneous FIN+ACK must elicit exactly one "
                "inline ACK acknowledging peer's FIN per the FIN+ACK "
                "branch in '_tcp_fsm_fin_wait_1' (line 1559)."
            ),
        )
        ack_of_peer_fin = self._parse_tx(peer_fin_inline[0])
        self._assert_segment(
            ack_of_peer_fin,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSING,
            msg=(
                "After peer's FIN+ACK whose ack does NOT cover our FIN "
                "(ack=LOCAL__ISS+1 < SND.FIN=LOCAL__ISS+2), state must "
                "transition to CLOSING per RFC 9293 §3.10.7.4 - NOT to "
                "TIME_WAIT (TIME_WAIT requires peer to also have ACKed "
                "our FIN)."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 2,
            msg="'RCV.NXT' must advance past peer's FIN's one byte of sequence space.",
        )

        # Peer ACKs our FIN. ack=LOCAL__ISS+2 covers our FIN's seq
        # byte.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        closing_ack_inline = self._drive_rx(frame=peer_ack_of_fin)
        self.assertEqual(
            closing_ack_inline,
            [],
            msg=(
                "Peer's ACK of our FIN in CLOSING must not produce "
                "inline TX - CLOSING's ACK handler simply transitions "
                "to TIME_WAIT and arms the TIME_WAIT timer."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "After peer's ACK of our FIN in CLOSING, state must "
                "transition to TIME_WAIT per RFC 9293 §3.10.7.4 - "
                "both halves of the connection have now had their "
                "FINs acknowledged."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 2,
            msg=("'SND.UNA' must advance to LOCAL__ISS+2 after CLOSING's " "ACK handler runs (line 1672)."),
        )

    def test__close_simultaneous__closing_unacceptable_ack_beyond_snd_nxt_triggers_empty_ack_reply(self) -> None:
        """
        Ensure that when we are in CLOSING and peer sends an
        ACK whose value is beyond SND.NXT (acknowledges
        unsent data), we emit the empty-ACK reply rather
        than silently dropping it. State stays CLOSING and
        SND.UNA is unchanged.

        Reference: RFC 9293 §3.10.7.4 (step 5 ACK acknowledging unsent data).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Application close() -> deferred FIN_WAIT_1. First tick
        # transitions ESTABLISHED -> FIN_WAIT_1 (after TX buffer
        # drains, which is empty); second tick fires our FIN.
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

        # Peer's simultaneous FIN+ACK (ack does NOT cover our FIN)
        # transitions us to CLOSING.
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
            FsmState.CLOSING,
            msg="Setup precondition: simultaneous FIN must transition to CLOSING.",
        )

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        # Peer sends a bare ACK with ack acknowledging unsent
        # data. The receiver MUST emit an empty-ACK reply.
        peer_unacceptable_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
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
                "('SEG.ACK > SND.NXT') in CLOSING MUST elicit "
                "an empty-ACK reply carrying our current "
                "SND.NXT and RCV.NXT."
            ),
        )
        reply_probe = self._parse_tx(unacceptable_ack_inline[0])
        self._assert_segment(
            reply_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=("The unacceptable ACK is dropped after the " "empty-ACK reply; SND.UNA must NOT advance."),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSING,
            msg="Unacceptable ACK is discarded; state must remain CLOSING.",
        )

    def test__close_simultaneous__closing_unacceptable_segment_elicits_ack_per_rfc_3_10_7_4(self) -> None:
        """
        Ensure CLOSING emits an ACK reply on unacceptable
        inbound segments (e.g. fully-duplicate retransmit
        with seq below RCV.NXT) rather than silently dropping
        them. State stays CLOSING.

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

        # Application close() -> two ticks: state transition then
        # FIN emit. Final state: FIN_WAIT_1 with SND.FIN = LOCAL__ISS+1+50+1 = ?
        # No wait — peer didn't ACK our 0 outbound bytes, so our
        # SND.MAX = LOCAL__ISS + 1 still. After close() and 2 ticks:
        # SND.NXT = SND.MAX = LOCAL__ISS + 2 (the +1 byte for FIN).
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: close() must transition to FIN_WAIT_1.",
        )

        # Peer's simultaneous FIN+ACK with ack=LOCAL__ISS+1 (does
        # NOT cover our FIN). State -> CLOSING.
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
            FsmState.CLOSING,
            msg="Setup precondition: simultaneous FIN must transition to CLOSING.",
        )

        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        # Peer retransmits the original 50-byte data segment - seq
        # below RCV.NXT, fully duplicate. We MUST emit an ACK reply.
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
            msg=("An unacceptable segment in CLOSING MUST " "elicit an ACK reply rather than being dropped."),
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
            FsmState.CLOSING,
            msg="State must remain CLOSING after a fully-duplicate retransmit.",
        )

    def test__close_simultaneous__in_window_rst_in_closing_must_elicit_challenge_ack(self) -> None:
        """
        Ensure CLOSING's RST handler emits a challenge ACK
        on an in-window-but-mismatched RST (seq != RCV.NXT)
        rather than silently dropping. State stays CLOSING.

        Reference: RFC 9293 §3.10.7.4 (RST acceptance three-way classification).
        Reference: RFC 5961 §3 (blind RST mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

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
            FsmState.CLOSING,
            msg="Setup precondition: state must be CLOSING.",
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
            msg=("Peer's RST with in-window mismatched seq in " "CLOSING MUST elicit exactly one challenge ACK."),
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
            FsmState.CLOSING,
            msg="In-window-mismatched RST must NOT reset the connection in CLOSING.",
        )

    def test__close_simultaneous__bare_rst_in_closing_must_drop_to_closed(self) -> None:
        """
        Ensure a peer-issued bare RST with seq == RCV.NXT in
        CLOSING aborts the connection: state drops to CLOSED,
        no outbound segment, socket unregistered.

        Reference: RFC 9293 §3.10.7.4 (RST validation by SEQ window in synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

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
            FsmState.CLOSING,
            msg="Setup precondition: state must be CLOSING.",
        )

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=0,
            flags=("RST",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_rst)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's bare RST (no ACK flag) with seq==RCV.NXT in "
                "CLOSING MUST abort the connection per RFC 9293 "
                "§3.10.7.4. Today the CLOSING RST branch predicate "
                "'all({tcp__flag_rst, tcp__flag_ack})' silently drops "
                "bare RSTs. Fix: replace with bare 'tcp__flag_rst'. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg="Socket must be unregistered after the CLOSED transition.",
        )
