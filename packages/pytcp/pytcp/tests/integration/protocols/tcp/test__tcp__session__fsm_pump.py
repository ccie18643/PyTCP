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
This module contains the FSM-pump characterization pins for the
TCP timer-client migration Phase 4 (attempt #2). They pin the
behaviour the 1 ms periodic provided as a load-bearing FSM pump
(SYN / FIN emission and chained state progression driven by the
timer tick, plus the idle-quiescence baseline) so the Phase-4b
coalesced + 'tx_pump' redesign can be proven byte-identical.
These pass on the current periodic code (characterization pins).

pytcp/tests/integration/protocols/tcp/test__tcp__session__fsm_pump.py

ver 3.0.10
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__cwnd import initial_window
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__rto import initial_state
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


class TestTcpFsmPump(TcpTestCase):
    """
    The FSM-pump characterization pins (Phase 4a — strengthen
    the net on the unchanged Phase-3 periodic code).
    """

    def test__pump__connect_emits_syn_on_first_advance(self) -> None:
        """
        Ensure active-open emits the SYN on the first timer tick
        after CONNECT: the CONNECT syscall only transitions to
        SYN_SENT, the SYN is pumped out by the SYN_SENT timer
        handler. This is the exact archetype the Phase-4 attempt
        #1 coalesced-only design stalled on.

        Reference: RFC 9293 §3.5 (connection establishment).
        """

        session = self._make_active_session(iss=LOCAL__ISS)

        session.tcp_fsm(syscall=SysCall.CONNECT)
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="CONNECT from CLOSED must transition the session to SYN_SENT.",
        )

        tx = self._advance(ms=1)
        self.assertEqual(
            len(tx),
            1,
            msg="The first timer tick after CONNECT MUST pump exactly one SYN out.",
        )
        self.assertIn(
            "SYN",
            self._parse_tx(tx[0]).flags,
            msg="The segment pumped on the first tick after CONNECT MUST be the SYN.",
        )

    def test__pump__handshake_completes_through_first_advance(self) -> None:
        """
        Ensure the canonical handshake drive (CONNECT, advance,
        inject peer SYN+ACK) reaches ESTABLISHED. This guards the
        whole 392-failure class the attempt-#1 design produced
        when the SYN never pumped out.

        Reference: RFC 9293 §3.5 (connection establishment).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="The handshake drive MUST reach ESTABLISHED (SYN pumped, SYN+ACK consumed, ACK sent).",
        )

    def test__pump__close_with_empty_buffer_emits_fin(self) -> None:
        """
        Ensure close() with an already-drained TX buffer pumps
        the FIN out: the ESTABLISHED->FIN_WAIT_1 transition tick
        carries no segment, and FIN_WAIT_1's next timer tick
        emits the FIN. The close->FIN progression is timer-pump
        driven, not syscall-driven.

        Reference: RFC 9293 §3.6 (closing a connection).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        session.close()

        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg="The ESTABLISHED->FIN_WAIT_1 transition tick MUST NOT carry a segment.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="close() with an empty TX buffer MUST transition to FIN_WAIT_1 on the first tick.",
        )

        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="FIN_WAIT_1's first timer tick MUST pump exactly one FIN segment out.",
        )
        self.assertIn(
            "FIN",
            self._parse_tx(fin_tx[0]).flags,
            msg="The segment pumped from FIN_WAIT_1 MUST carry FIN.",
        )

    def test__pump__close_with_pending_data_drains_then_fins(self) -> None:
        """
        Ensure a close() with buffered data chains correctly: the
        data segment is pumped out first, the session stays in
        ESTABLISHED until the peer's cumulative ACK drains the TX
        buffer, then the FIN is pumped out. This pins the
        multi-step state progression the pump drives.

        Reference: RFC 9293 §3.6 (closing a connection).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Bypass slow-start so the buffered payload flows without
        # waiting on a window-opening ACK (mirrors the canonical
        # close-with-data tests).
        session._cc.snd_ewn = PEER__WIN

        payload = b"pending-payload"
        session.send(data=payload)
        session.close()

        data_tx = self._advance(ms=1)
        self.assertEqual(
            len(data_tx),
            1,
            msg="The buffered data segment MUST be pumped out first.",
        )
        data_seg = self._parse_tx(data_tx[0])
        self.assertEqual(
            data_seg.payload,
            payload,
            msg="The first pumped segment MUST carry the buffered payload.",
        )
        self.assertNotIn(
            "FIN",
            data_seg.flags,
            msg="The data segment MUST NOT carry FIN while the TX buffer is unacked.",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State MUST remain ESTABLISHED until the TX buffer drains.",
        )

        # Peer cumulatively ACKs the data, draining the TX buffer.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        emitted_fin = False
        for _ in range(5):
            for frame in self._advance(ms=1):
                if "FIN" in self._parse_tx(frame).flags:
                    emitted_fin = True
            if emitted_fin:
                break

        self.assertTrue(
            emitted_fin,
            msg="The FIN MUST be pumped out after the peer ACK drains the TX buffer.",
        )
        self.assertIn(
            session.state,
            (FsmState.FIN_WAIT_1, FsmState.FIN_WAIT_2),
            msg="After data drain + FIN the session MUST have progressed past ESTABLISHED.",
        )

    def test__pump__quiescent_established_session_is_idle(self) -> None:
        """
        Ensure a fully quiescent ESTABLISHED session (no data, no
        close, nothing in flight, keep-alive off) emits nothing
        across a long advance. This is the zero-idle baseline the
        Phase-4b coalesced + tx_pump design must preserve (no
        spurious wakeups / no spurious segments).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Drain any post-handshake delayed-ACK so the measurement
        # window starts genuinely quiescent.
        self._advance(ms=300)

        idle_tx = self._advance(ms=5000)
        self.assertEqual(
            idle_tx,
            [],
            msg="A quiescent ESTABLISHED session MUST emit nothing across a 5 s idle advance.",
        )

    def test__pump__bare_send_with_no_other_activity_transmits(self) -> None:
        """
        Ensure a bare 'send()' on an otherwise-quiescent
        ESTABLISHED session results in the data being
        transmitted on the next tick. 'TcpSession.send()' does
        NOT route through 'tcp_fsm' (it only extends the TX
        buffer), so the FSM pump — not the syscall path — emits
        the segment; this pins the non-'tcp_fsm'-mutator gap
        the Phase-4c '_kick_pump' must close.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN
        self._advance(ms=300)

        session.send(data=b"bare")
        tx = self._advance(ms=1)

        self.assertEqual(
            len(tx),
            1,
            msg="A bare send() with nothing else active MUST transmit the data on the next tick.",
        )
        self.assertEqual(
            self._parse_tx(tx[0]).payload,
            b"bare",
            msg="The pumped segment MUST carry the sent payload.",
        )

    def test__pump__send_after_idle_transmits_and_resets_rto(self) -> None:
        """
        Ensure a 'send()' after an idle period longer than the
        RTO both transmits the data and resets '_rto_state' to
        'initial_state()'. The idle-reset runs in the
        per-segment send pipeline, so it only fires if the
        post-idle send is actually pumped out.

        Reference: RFC 6298 §5.7 (restart-after-idle).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        session.send(data=b"first")
        self._advance(ms=1)
        first_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=session._snd_seq.max,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=first_ack)

        self._advance(ms=session._rto_state.rto_ms + 1000)

        session.send(data=b"second")
        tx = self._advance(ms=1)

        self.assertEqual(
            len(tx),
            1,
            msg="The post-idle send() MUST transmit the data on the next tick.",
        )
        self.assertEqual(
            session._rto_state,
            initial_state(),
            msg=(
                "An idle longer than rto_ms MUST reset '_rto_state' to "
                f"initial_state() on the next send. Got {session._rto_state!r}."
            ),
        )

    def test__pump__send_after_idle_applies_restart_window(self) -> None:
        """
        Ensure a 'send()' after an idle period longer than the
        RTO applies the restart-window cwnd reduction to
        RW = min(IW, cwnd_pre_idle). Like the idle-reset, this
        runs in the per-segment send pipeline and only fires if
        the post-idle send is pumped out.

        Reference: RFC 5681 §4.1 (Restart Window after idle).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        mss = session._win.snd_mss

        session.send(data=b"prime")
        self._advance(ms=1)
        prime_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=session._snd_seq.max,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=prime_ack)

        session._cc.cwnd = 100 * mss
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        self._advance(ms=session._rto_state.rto_ms + 100)

        session.send(data=b"after-idle")
        self._advance(ms=1)

        expected_rw = min(initial_window(mss), 100 * mss)
        self.assertEqual(
            session._cc.cwnd,
            expected_rw,
            msg=(
                "After a >RTO idle, the next send() MUST reduce cwnd to "
                f"RW = min(IW, prior) = {expected_rw}. Got {session._cc.cwnd}."
            ),
        )
