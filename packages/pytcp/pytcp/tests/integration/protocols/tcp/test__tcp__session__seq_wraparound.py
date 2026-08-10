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
This module contains integration tests for 32-bit TCP sequence-
number wraparound in the 'TcpSession' state machine. Per RFC 9293
§3.4 sequence numbers are 32-bit unsigned integers that wrap
modulo 2**32. Production code in 'tcp__session.py' currently uses
plain Python integer arithmetic for sequence updates and plain
'>' / '<=' comparators for ACK acceptability checks; both fail
across the wrap boundary.

The fix is the deferred migration to 'pytcp.protocols.tcp.tcp__seq's modular
comparators ('lt32', 'le32', 'gt32', 'ge32', 'add32', 'sub32',
'in_range32') that already exist with full unit-test coverage.
This file is the forcing function for that migration.

Test classes (one TestCase per concern, per the project plan §6.12):

    * TestTcpSeqWraparound__Seq      - outbound seq wraps modularly.
    * TestTcpSeqWraparound__Ack      - ACK across wrap accepted /
                                        comparators wrap-aware.
    * TestTcpSeqWraparound__SeqAndAck - both directions wrap.

Reference RFCs:
    RFC 9293 §3.4    Sequence Numbers
    RFC 9293 §3.10.7.4   Synchronized state segment processing
                          (acceptability checks across the wrap)

pytcp/tests/integration/protocols/tcp/test__tcp__session__seq_wraparound.py

ver 3.0.10
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__constants import TCP__RTO__INITIAL_MS
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

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240
PEER__MSS: int = 1460

# 32-bit modular constants. These mirror what 'pytcp.protocols.tcp.tcp__seq'
# uses; pinning them here keeps the test arithmetic readable.
SEQ32__MAX: int = 0xFFFF_FFFF
SEQ32__MOD: int = 0x1_0000_0000


class TestTcpSeqWraparound__Seq(TcpTestCase):
    """
    Tests for outbound sequence-number wrap. Force ISS near the
    32-bit ceiling, drive data, and verify the on-the-wire seq
    numbers wrap modularly (i.e. 0xFFFF_FFFF + 1 == 0, not 2**32).
    """

    def test__seq_wraparound__outbound_data_seq_wraps_modularly(self) -> None:
        """
        Ensure that when SND.NXT crosses the 32-bit ceiling
        (0xFFFF_FFFF -> 0x0000_0000), subsequent outbound
        segments carry SEQ values reduced modulo 2**32.

        Reference: RFC 9293 §3.4 (sequence numbers are unsigned 32-bit modular).
        """

        session = self._drive_handshake_to_established(
            iss=0xFFFF_FFFE,
            peer_iss=0x0000_2000,
        )
        # Bypass slow-start so two back-to-back segments fire on
        # consecutive ticks.
        session._cc.snd_ewn = PEER__WIN

        self.assertEqual(
            session._snd_seq.nxt,
            0xFFFF_FFFF,
            msg=(
                "Setup precondition: post-handshake 'SND.NXT' must "
                "equal 'ISS + 1' = 0xFFFF_FFFF (just below the wrap)."
            ),
        )

        # Send #1: 4 bytes at seq 0xFFFF_FFFF. The segment fits the
        # 32-bit field; post-segment, 'SND.NXT' must wrap to 3.
        session.send(data=b"AAAA")
        seg1_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg1_tx),
            1,
            msg="Setup precondition: first send must produce one outbound segment.",
        )
        seg1_probe = self._parse_tx(seg1_tx[0])
        self._assert_segment(
            seg1_probe,
            seq=0xFFFF_FFFF,
            payload=b"AAAA",
        )

        # The spec encoding: post-segment-1 'SND.NXT' wraps modularly.
        self.assertEqual(
            session._snd_seq.nxt,
            (0xFFFF_FFFF + 4) % SEQ32__MOD,
            msg=(
                "After sending 4 bytes from seq=0xFFFF_FFFF, "
                "'SND.NXT' must wrap modulo 2**32 to "
                f"'{(0xFFFF_FFFF + 4) % SEQ32__MOD}' per RFC 9293 "
                "§3.4. Catching '0x1_0000_0003' here means the "
                "raw Python addition leaked past the 32-bit "
                "modular space; the next outbound segment will "
                "fail at 'struct.pack(\"!I\", ...)' on the "
                "non-32-bit value."
            ),
        )

        # Peer ACKs the first segment. This advances SND.UNA past
        # the wrap and clears the Minshall partial-in-flight gate
        # (RFC 1122 §4.2.3.4) so the second send's partial does
        # not get deferred. Without this ACK the post-migration
        # Minshall check would see '_snd_sml=3 > _snd_una=0xFFFF_FFFF'
        # modularly (correctly) and defer Send #2 - which is the
        # right Nagle behaviour but unrelated to the seq-wrap
        # contract this test is exercising.
        peer_ack_seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0x0000_0003,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_seg1)

        # Send #2: 4 more bytes. Per spec the segment carries
        # seq = 3 (the wrapped value).
        session.send(data=b"BBBB")
        try:
            seg2_tx = self._advance(ms=1)
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(
                f"Sending across the 32-bit seq wrap raised "
                f"'{type(exc).__name__}: {exc}'. RFC 9293 §3.4 "
                "requires sequence numbers to wrap modulo 2**32; "
                "the production code's raw integer arithmetic at "
                "'tcp__session.py:593' propagates a non-32-bit "
                "value into the assembler's 'struct.pack(\"!I\", "
                "...)' call, which rejects it. Fix: migrate "
                "'tcp__session.py' to use 'pytcp.protocols.tcp.tcp__seq's "
                "'add32' helper."
            )

        self.assertEqual(
            len(seg2_tx),
            1,
            msg="Second send must produce one outbound segment.",
        )
        seg2_probe = self._parse_tx(seg2_tx[0])
        self._assert_segment(
            seg2_probe,
            seq=3,
            payload=b"BBBB",
        )


class TestTcpSeqWraparound__Ack(TcpTestCase):
    """
    Tests for inbound ACK handling across the 32-bit wrap. The
    'TcpSession.tcp_fsm_established' branches use plain '<' / '<='
    comparators to validate 'SND.UNA <= SEG.ACK <= SND.MAX'; once
    the send-sequence range straddles the 32-bit wrap, those
    plain comparators no longer correctly identify which ACKs are
    in-window.
    """

    def test__seq_wraparound__inbound_ack_across_wrap_advances_snd_una(self) -> None:
        """
        Ensure that a peer ACK whose value is modularly
        inside [SND.UNA, SND.MAX] but numerically outside
        (because the range straddles the 32-bit wrap) is
        accepted as in-window and advances SND.UNA
        modularly to the ack value.

        Reference: RFC 9293 §3.4 (modular sequence-number comparison).
        """

        # Drive handshake at a tame ISS so FSM bootstrap is
        # ordinary. We then poke the send-sequence state directly
        # to straddle the wrap.
        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0x0000_2000,
        )

        # Pre-position SND.UNA/SND.NXT/SND.MAX to straddle the
        # wrap. The 18-byte in-flight range (0xFFFF_FFFE through
        # 0x10 modularly) is what makes ack = 0x05 a legal
        # in-window value the legacy '<=' check rejects.
        session._snd_seq.una = 0xFFFF_FFFE
        session._snd_seq.nxt = 0x0000_0010
        session._snd_seq.max = 0x0000_0010
        # Keep '_tx_buffer_una = max(_snd_una - _tx_buffer_seq_mod, 0)'
        # bounded to zero so the eventual buffer-purge inside
        # '_process_ack_packet' does not blow up on the modular
        # input.
        session._tx.seq_mod = 0xFFFF_FFFE

        # Peer sends an in-order ACK at the modularly-acceptable
        # ack = 0x05.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0x0000_0005,
            flags=("ACK",),
            win=PEER__WIN,
        )
        ack_inline = self._drive_rx(frame=peer_ack)

        # The spec encoding: SND.UNA advances modularly.
        self.assertEqual(
            session._snd_seq.una,
            0x0000_0005,
            msg=(
                "Peer's ACK at ack=0x05 with SND.UNA=0xFFFF_FFFE "
                "and SND.MAX=0x10 (range straddling the 32-bit "
                "wrap) MUST be accepted as in-window and SND.UNA "
                "MUST advance modularly to 0x05 per RFC 9293 §3.10.7.4. "
                "Current code's raw '<=' comparator rejects the "
                "ACK because 0xFFFF_FFFE <= 0x05 is numerically "
                "False; SND.UNA stays at 0xFFFF_FFFE and peer's "
                "in-flight data is silently unacknowledged. Fix: "
                "replace '<=' with 'le32' from "
                "'pytcp.protocols.tcp.tcp__seq'."
            ),
        )

        # Sanity: state still ESTABLISHED, no spurious empty-ACK
        # reply (which would fire if the ACK were classified as
        # 'unacceptable / past SND.MAX').
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED after a legal in-window ACK.",
        )
        self.assertEqual(
            ack_inline,
            [],
            msg=(
                "A legal in-window ACK must produce no outbound "
                "segment - it is processed by the data branch, "
                "not the 'unacceptable ACK' empty-reply path."
            ),
        )


class TestTcpSeqWraparound__SeqAndAck(TcpTestCase):
    """
    Tests for inbound RCV.NXT update across the 32-bit wrap. The
    canonical bidirectional-wrap case combines outbound seq wrap
    (covered by the '__Seq' class) with inbound rcv-side wrap (this
    class) - both directions independently break in the same way:
    raw integer arithmetic that escapes the 32-bit modular space.
    """

    def test__seq_wraparound__inbound_data_seq_wrap_advances_rcv_nxt_modularly(self) -> None:
        """
        Ensure that when peer's send-sequence range
        straddles the 32-bit wrap, the receive-side update
        of RCV.NXT wraps modularly: peer sends a data
        segment whose (seq + len) crosses the 32-bit
        ceiling, and RCV.NXT advances to the wrapped
        seg_end value.

        Reference: RFC 9293 §3.4 (modular sequence-number arithmetic).
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0xFFFF_FFFC,
        )

        self.assertEqual(
            session._rcv_seq.nxt,
            0xFFFF_FFFD,
            msg=("Setup precondition: post-handshake 'RCV.NXT' must " "equal 'peer_iss + 1' = 0xFFFF_FFFD."),
        )

        # Peer sends 8 bytes spanning the wrap: seq 0xFFFF_FFFD
        # through 0x04 modularly.
        peer_payload = b"peer-rcv"
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0xFFFF_FFFD,
            ack=0x0000_1001,
            flags=("ACK", "PSH"),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)

        # The spec encoding: RCV.NXT advances modularly.
        expected_rcv_nxt = (0xFFFF_FFFD + len(peer_payload)) % SEQ32__MOD
        self.assertEqual(
            session._rcv_seq.nxt,
            expected_rcv_nxt,
            msg=(
                "After peer's 8-byte data segment at "
                "seq=0xFFFF_FFFD, 'RCV.NXT' must advance "
                f"modularly to {expected_rcv_nxt:#x}."
            ),
        )

        # Sanity: data was enqueued.
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_payload,
            msg="Peer's payload must be delivered to '_rx_buffer'.",
        )


class TestTcpSeqWraparound__HalfCloseAck(TcpTestCase):
    """
    Tests for ACK acceptability across the 32-bit wrap in the
    half-close FSM states (CLOSE_WAIT, FIN_WAIT_1, FIN_WAIT_2,
    CLOSING, LAST_ACK). Each handler uses the chained Python
    comparator 'self._snd_seq.una <= ack <= self._snd_seq.max', which
    fails across the wrap exactly as the ESTABLISHED handler did
    before commit '91abbc4' migrated it. The migration was not
    extended to the half-close family; this test is the forcing
    function for that extension.
    """

    def test__seq_wraparound__close_wait_inbound_ack_across_wrap_advances_snd_una(self) -> None:
        """
        Ensure that a peer ACK whose value is modularly
        inside [SND.UNA, SND.MAX] but numerically outside
        is accepted as in-window in CLOSE_WAIT and advances
        SND.UNA to the ack value.

        Reference: RFC 9293 §3.4 (modular sequence-number comparison).
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0x0000_2000,
        )

        # Drive peer FIN to enter CLOSE_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0x0000_1001,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        assert session.state is FsmState.CLOSE_WAIT, f"Setup failed: expected CLOSE_WAIT, got {session.state!r}."

        # Pre-position send-sequence state to straddle the wrap.
        session._snd_seq.una = 0xFFFF_FFFE
        session._snd_seq.nxt = 0x0000_0010
        session._snd_seq.max = 0x0000_0010
        session._tx.seq_mod = 0xFFFF_FFFE

        # Peer sends the in-window ACK. Note seq advances past
        # peer's FIN to keep RCV.NXT consistent.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2002,
            ack=0x0000_0005,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._snd_seq.una,
            0x0000_0005,
            msg=(
                "Peer's in-window ACK at ack=0x05 with "
                "SND.UNA=0xFFFF_FFFE and SND.MAX=0x10 in CLOSE_WAIT "
                "MUST advance SND.UNA modularly to 0x05 per RFC "
                "9293 §3.10.7.4. Current code's chained '<=' "
                "rejects across the wrap. Fix: migrate "
                "'_tcp_fsm_close_wait' (and the other half-close "
                "handlers) to 'le32'."
            ),
        )


class TestTcpSeqWraparound__ReceiveWindow(TcpTestCase):
    """
    Tests for the receive-window acceptability check
    ('RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND') across the 32-bit
    wrap. The right-edge expression 'self._rcv_seq.nxt + self._rcv_wnd'
    is raw Python addition that overflows past 2**32 when
    'self._rcv_seq.nxt' is near the wrap; the resulting comparison
    rejects in-window segments whose seq numerically exceeds
    2**32 even though they are modularly inside the window.
    """

    def test__seq_wraparound__receive_window_right_edge_across_wrap_accepts_segment(self) -> None:
        """
        Ensure that a peer data segment whose seq lies
        modularly within the receive window
        '[RCV.NXT, RCV.NXT + RCV.WND)' is accepted even when
        the right edge straddles the 32-bit wrap.

        Reference: RFC 9293 §3.4 (modular receive-window arithmetic).
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0x0000_2000,
        )

        # Pre-position RCV.NXT near the 32-bit ceiling. We will
        # send peer data at exactly RCV.NXT so the segment is
        # in-order; its 'seg_end' wraps past the 32-bit ceiling,
        # which is what exercises the receive-window
        # acceptability check's modular right-edge computation.
        session._rcv_seq.nxt = 0xFFFF_FFE0
        session._rcv_seq.una = 0xFFFF_FFE0
        session._rcv_seq.ini = 0xFFFF_FFE0

        # Peer sends 50 bytes at seq=RCV.NXT (=0xFFFF_FFE0). The
        # segment's right edge wraps past 0xFFFF_FFFF to 0x12,
        # exercising 'add32' on the seg_end computation and
        # 'lt32 / gt32' on the receive-window acceptability test.
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0xFFFF_FFE0,
            ack=0x0000_1001,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)

        # Modularly 50 bytes past 0xFFFF_FFE0 is 0x12 (with 32
        # bytes consumed from 0xFFFF_FFE0 to 0xFFFF_FFFF + 1
        # phantom, then 18 bytes from 0x0 to 0x12).
        self.assertEqual(
            session._rcv_seq.nxt,
            0x0000_0012,
            msg=(
                "An in-order peer data segment whose "
                "seg_end wraps past the 32-bit ceiling MUST "
                "be accepted and advance RCV.NXT modularly. "
                "to 'add32' / 'lt32' / 'gt32'."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_payload,
            msg="In-window data must be delivered to '_rx_buffer'.",
        )


class TestTcpSeqWraparound__FinAck(TcpTestCase):
    """
    Tests for the FIN-ack '>=' check in the half-close states.
    'self._snd_seq.fin' is the seq number of the FIN segment we sent;
    the handler tests 'tcp__ack >= self._snd_seq.fin' to detect that
    peer has cumulatively acked our FIN. The raw '>=' fails
    across the wrap, so a wrap-spanning peer ACK that legitimately
    covers our FIN is treated as not-yet-cum-acked and the FSM
    fails to transition out of FIN_WAIT_1.
    """

    def test__seq_wraparound__fin_wait_1_fin_ack_across_wrap_transitions_to_fin_wait_2(self) -> None:
        """
        Ensure that when our FIN seq is near the 32-bit
        ceiling and peer's cumulative ACK has wrapped past
        it, the FIN_WAIT_1 handler recognises the FIN as
        ACKed and transitions to FIN_WAIT_2.

        Reference: RFC 9293 §3.4 (modular sequence-number comparison).
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0x0000_2000,
        )

        # Drive close() - we send FIN, transition to FIN_WAIT_1.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        assert session.state is FsmState.FIN_WAIT_1, f"Setup failed: expected FIN_WAIT_1, got {session.state!r}."

        # Pre-position state so SND.FIN straddles the wrap. The
        # FIN occupies 1 byte of seq space at SND.FIN; peer's
        # expected ACK is SND.FIN + 1.
        session._snd_seq.fin = 0xFFFF_FFFF
        session._snd_seq.una = 0xFFFF_FFFE
        session._snd_seq.nxt = 0x0000_0000
        session._snd_seq.max = 0x0000_0000
        session._tx.seq_mod = 0xFFFF_FFFE

        # Peer ACK covers our FIN (and one byte past, modularly
        # making the cum-ACK 0x01).
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0x0000_0000,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg=(
                "When peer's cum-ACK is modularly >= "
                "SND.FIN, the FIN_WAIT_1 handler MUST "
                "transition to FIN_WAIT_2."
            ),
        )


class TestTcpSeqWraparound__SynSentAck(TcpTestCase):
    """
    Tests for the SYN_SENT-state ACK acceptability check across
    the 32-bit wrap. RFC 9293 §3.10.7.3 step 1 mandates that any
    ACK-bearing segment in SYN_SENT whose 'SEG.ACK' falls outside
    '(SND.UNA, SND.MAX]' must elicit '<SEQ=SEG.ACK><CTL=RST>' and
    the segment be discarded. The check is implemented at
    'tcp__session.py' line 1706 with a chained Python comparator
    'self._snd_seq.una < ack <= self._snd_seq.max' that fails across the
    32-bit wrap. The site escaped the modular-arithmetic
    migration ('91abbc4' / '352199d'); this test is the forcing
    function for the spot fix.

    The bug fires only when the locally-chosen Initial Sequence
    Number is randomly drawn close to the 32-bit ceiling - rare
    in practice (~1-in-4-billion ISS draws) but a real
    interoperability failure when it does fire (peer sees a
    legitimate active-open's SYN+ACK rejected with RST).
    """

    def test__seq_wraparound__syn_sent_inbound_syn_ack_with_wrapped_ack_accepted(self) -> None:
        """
        Ensure that when the locally-chosen ISS lies on the
        32-bit ceiling and the peer's SYN+ACK carries 'ack =
        ISS + 1' which has wrapped past the ceiling to zero,
        the ACK acceptability check accepts the SYN+ACK as
        in-window and the session transitions to ESTABLISHED.

        Reference: RFC 9293 §3.10.7.3 (SYN_SENT ACK acceptability).
        """

        session = self._make_active_session(iss=SEQ32__MAX)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        # Tick to fire the outbound SYN.
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self.assertEqual(
            syn_probe.seq,
            SEQ32__MAX,
            msg="Setup precondition: outbound SYN must carry seq=ISS=0xFFFF_FFFF.",
        )
        self.assertEqual(
            session._snd_seq.max,
            0x0000_0000,
            msg=(
                "Setup precondition: post-SYN-emit 'SND.MAX' must be "
                "the wrapped value 0x0000_0000 (= ISS + 1 modularly)."
            ),
        )

        # Peer's SYN+ACK with ack = ISS + 1 = 0x0000_0000 (the
        # wrapped value). Per RFC 9293 §3.10.7.3 step 1 this is
        # acceptable - 'ack' falls inside '(SND.UNA, SND.MAX]'
        # modularly.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2000,  # peer's ISS
            ack=0x0000_0000,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        inline_tx = self._drive_rx(frame=peer_syn_ack)

        # No RST should fire - the SYN+ACK is acceptable.
        rst_frames = [frame for frame in inline_tx if self._parse_tx(frame).flags & {"RST"}]
        self.assertEqual(
            rst_frames,
            [],
            msg=(
                "An acceptable SYN+ACK whose ack value "
                "happens to have wrapped past the 32-bit "
                "ceiling MUST NOT elicit an RST."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=("The session MUST transition to ESTABLISHED " "after peer's acceptable SYN+ACK."),
        )


class TestTcpSeqWraparound__FinSentinel(TcpTestCase):
    """
    Tests the '_snd_fin = 0' sentinel collision in
    '_retransmit_packet_timeout's TX-buffer offset rewind. The
    rewind walks 'self._tx.seq_mod' back by one when
    'self._snd_seq.nxt in {self._snd_seq.ini, self._snd_seq.fin}', the
    rationale being that SYN and FIN consume one byte of seq
    space without a TX-buffer slot. But when no FIN has been
    sent, '_snd_fin' is the literal value 0 used as a sentinel;
    once 'SND.UNA' wraps modulo 2**32 to exactly 0 and an RTO
    fires, the rewind sets 'SND.NXT = 0', the set membership
    fires its FIN branch on the sentinel value, and the
    walk-back silently corrupts the offset translation.
    """

    def test__seq_wraparound__rto_after_snd_una_wraps_to_zero_does_not_corrupt_tx_buffer_offset(self) -> None:
        """
        Ensure that when 'SND.UNA' wraps modulo 2**32 to
        exactly 0 and an RTO fires before any FIN has been
        sent, the retransmit fires the queued data byte
        cleanly — the '_snd_fin = 0' sentinel value MUST NOT
        be confused for a real FIN seq matching 'SND.NXT == 0'.

        Reference: RFC 9293 §3.4 (modular sequence-number arithmetic).
        """

        session = self._drive_handshake_to_established(
            iss=0xFFFF_FFFE,
            peer_iss=0x0000_2000,
        )
        # Bypass slow-start so the 1-byte sends fire immediately.
        session._cc.snd_ewn = PEER__WIN

        # Step 3: send 1 byte at SND.NXT = 0xFFFF_FFFF.
        session.send(data=b"A")
        seg1_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg1_tx),
            1,
            msg="Setup precondition: first send must produce one outbound segment.",
        )
        self.assertEqual(
            session._snd_seq.nxt,
            0,
            msg=("Setup precondition: post-send-1 SND.NXT must wrap " "modulo 2**32 to 0."),
        )

        # Step 4: peer ACKs the byte. SND.UNA wraps to 0.
        peer_ack_seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_seg1)
        self.assertEqual(
            session._snd_seq.una,
            0,
            msg=(
                "Setup precondition: post-ACK SND.UNA must equal 0 - "
                "the wrap value that triggers the sentinel collision."
            ),
        )
        self.assertEqual(
            session._tx.seq_mod,
            0,
            msg=(
                "Setup precondition: '_tx_buffer_seq_mod' must "
                "have advanced to 0 after the cum-ACK purged the "
                "first byte."
            ),
        )

        # Step 5: send 1 byte at SND.NXT = 0. Peer does not ACK.
        session.send(data=b"B")
        seg2_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg2_tx),
            1,
            msg="Setup precondition: second send must produce one outbound segment.",
        )
        seg2_probe = self._parse_tx(seg2_tx[0])
        self._assert_segment(
            seg2_probe,
            seq=0,
            payload=b"B",
        )

        # Step 6: advance the virtual clock to fire the RTO.
        # 'TCP__RTO__INITIAL_MS' is the initial RTO (1000 ms).
        # Advance one extra ms past the timeout so the timer fires
        # cleanly on the boundary tick.
        retransmit_tx = self._advance(ms=TCP__RTO__INITIAL_MS + 1)

        # Pick out the retransmit segments from the advance window.
        # Multiple ticks fire while we advance; only the RTO tick
        # produces a TX. The fix produces exactly one retransmit
        # segment with the correct content; the bug produces zero.
        retransmit_segments = [self._parse_tx(frame) for frame in retransmit_tx]
        self.assertEqual(
            len(retransmit_segments),
            1,
            msg=(
                "After the RTO fires, exactly one retransmit segment "
                "MUST be emitted re-sending the unacked byte at "
                "seq=0. Today the rewind at "
                "'tcp__session.py:1335' walks '_tx_buffer_seq_mod' "
                "back by one because '_snd_fin == 0 == SND.NXT' "
                "fires the FIN branch on the sentinel value. The "
                "walk-back makes '_tx_buffer_nxt' overshoot by one, "
                "'remaining_data_len' compute as 0, and "
                "'_transmit_data' silently fail to emit the "
                "retransmit. The connection then cycles RTOs until "
                "R2 abort, with the queued byte never reaching the "
                "wire. Fix: replace the '_snd_fin = 0' sentinel "
                f"with a separate '_fin_sent: bool' flag. Got: {retransmit_segments!r}"
            ),
        )
        self._assert_segment(
            retransmit_segments[0],
            seq=0,
            payload=b"B",
        )

        # Belt-and-braces: '_tx_buffer_seq_mod' must NOT have been
        # decremented by the buggy rewind. The fix preserves the
        # value at 0; the bug subtracts 1 to 0xFFFF_FFFF.
        self.assertEqual(
            session._tx.seq_mod,
            0,
            msg=(
                "After the RTO, '_tx_buffer_seq_mod' MUST be "
                "unchanged at 0 - the rewind's FIN-walk-back must "
                "NOT fire when no FIN has been sent. Today the "
                "sentinel collision walks it back to 0xFFFF_FFFF, "
                "corrupting the seq-to-buffer-offset translation."
            ),
        )


class TestTcpSeqWraparound__PeerIsnSentinel(TcpTestCase):
    """
    Tests the 'self._rcv_seq.nxt > 0' sentinel collision in
    '_retransmit_packet_timeout's R2-abort RST emission. The
    abort path emits a RST to peer iff '_rcv_nxt > 0', the
    rationale being '_rcv_nxt' is initialised to 0 and becomes
    non-zero once peer's first segment is processed (via
    'add32(peer_isn, 1)' on peer's SYN). But when peer's ISN
    is exactly 0xFFFF_FFFF, 'add32(0xFFFF_FFFF, 1) == 0' so
    '_rcv_nxt' stays at the sentinel value despite peer having
    been contacted - the RST is silently suppressed.
    """

    def test__seq_wraparound__r2_abort_with_peer_isn_at_seq_max_emits_rst(self) -> None:
        """
        Ensure that when peer's ISN is exactly 0xFFFF_FFFF —
        making 'RCV.NXT == 0' after the handshake (the wrap
        of peer's ISN+1) — the R2 connection-abort path still
        emits a RST to peer.

        Reference: RFC 9293 §3.10.7.4 (R2 abort emits RST).
        Reference: RFC 1122 §4.2.3.5 (R2 ≥ 100 s retransmit abort).
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0xFFFF_FFFF,
        )
        # Sanity - the wrap precondition the bug hinges on.
        self.assertEqual(
            session._rcv_seq.nxt,
            0,
            msg=(
                "Setup precondition: post-handshake 'RCV.NXT' "
                "must equal 'add32(peer_isn=0xFFFF_FFFF, 1) == 0' "
                "- the post-wrap Seq32 value that the buggy gate "
                "wrongly treats as 'no peer contact'."
            ),
        )

        # Bypass slow-start so the first send fires immediately.
        session._cc.snd_ewn = PEER__WIN

        # Send a byte. Peer stays silent. RTO machinery starts.
        session.send(data=b"X")
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: initial send must produce one outbound segment.",
        )

        # Advance through the full RFC 6298 doubling cadence to
        # reach R2. Cumulative retransmit boundaries:
        #   t = 1   s   1st retransmit (counter -> 1)
        #   t = 3   s   2nd retransmit (counter -> 2)
        #   t = 7   s   3rd retransmit (counter -> 3)
        #   t = 15  s   4th retransmit (counter -> 4)
        #   t = 31  s   5th retransmit (counter -> 5)
        #   t = 63  s   6th retransmit (counter -> 6 == MAX)
        #   t = 127 s   R2 abort fires
        # Advance to just past 127 s (130 s) so the R2 boundary
        # falls inside the captured TX window.
        abort_tx = self._advance(ms=130_000)
        abort_segments = [self._parse_tx(frame) for frame in abort_tx]

        # The R2 abort emits exactly one RST+ACK if peer was
        # contacted. The data retransmits before the abort are
        # also in the captured TX list; pick out the RST frame.
        rst_segments = [seg for seg in abort_segments if "RST" in seg.flags]
        self.assertEqual(
            len(rst_segments),
            1,
            msg=(
                "On R2 abort with peer contacted (handshake "
                "completed), exactly one RST+ACK MUST be emitted "
                "at seq = SND.UNA per RFC 9293 §3.10.7.4 to "
                "signal peer that we are aborting the connection. "
                "Today the gate at 'tcp__session.py:1356' is the "
                "raw '_rcv_nxt > 0' comparison; with peer's ISN "
                "at 0xFFFF_FFFF, the post-handshake 'RCV.NXT' "
                "value is 0 (the sentinel) so the gate wrongly "
                "skips the RST emit. Peer is left in ESTABLISHED "
                "until their own R2 fires (~100 s+ later). Fix: "
                "replace '_rcv_nxt > 0' with a dedicated "
                f"'_peer_contacted: bool' flag. Got: {rst_segments!r}"
            ),
        )
        self._assert_segment(
            rst_segments[0],
            flags=frozenset({"RST", "ACK"}),
            seq=session._snd_seq.una,
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="On R2 abort, the session MUST transition to CLOSED.",
        )
