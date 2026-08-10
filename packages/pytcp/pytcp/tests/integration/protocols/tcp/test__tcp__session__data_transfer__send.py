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
This module contains integration tests for the TCP send-side data
transfer in the 'TcpSession' state machine, covering the application's
'send()' syscall path and the corresponding wire-level segment shape
prescribed by RFC 9293 §3.10.5 / RFC 1122 §4.2.2.2.

The tests in this file drive the session FSM directly: after taking
the session through the three-way handshake to ESTABLISHED via the
active-open path, each test invokes 'session.send(data=...)' and
asserts the wire-level shape of the segment(s) that follow on the
next virtual-clock tick. The full RX/TX path is exercised end to
end - outbound segments flow through the real
'PacketHandler._phtx_tcp -> _phtx_ip4 -> _phtx_ethernet' chain and
land in the mocked 'TxRing'.

Reference RFCs:
    RFC 9293 §3.10.5    SEND syscall semantics
    RFC 9293 §3.7.4     Generating data segments
    RFC 9293 §3.8.6     Window management
    RFC 9293 §3.8.6.1   Zero-window probing / persist timer
    RFC 6298 §2         Computing TCP's retransmission timer
    RFC 1122 §4.2.2.2   PSH bit on last segment of a write
    RFC 1122 §4.2.3.4   Nagle's algorithm

pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__send.py

ver 3.0.10
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing for log readability and reproducibility.
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


class TestTcpDataTransfer__Send(TcpTestCase):
    """
    Integration tests for the application-driven 'send()' path,
    covering segment shape, segmentation, window management, and
    flow-control behaviours.
    """

    def test__data_transfer_send__single_segment_fits_in_mss_emits_psh_ack(self) -> None:
        """
        Ensure that an application send() of a small payload
        (less than MSS) emits a single outbound TCP segment
        carrying the PSH and ACK flags, with SEQ tracking
        SND.NXT, ACK echoing RCV.NXT, and the payload equal
        to the bytes the application passed. SND.NXT
        advances by len(payload); state stays ESTABLISHED.

        Reference: RFC 1122 §4.2.2.2 (PSH on last segment of write).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        bytes_sent = session.send(data=payload)

        self.assertEqual(
            bytes_sent,
            len(payload),
            msg=(
                f"'send()' must return the number of bytes accepted "
                f"into the TX buffer. Got {bytes_sent}, expected "
                f"{len(payload)}."
            ),
        )

        # The actual transmit is gated on the next timer tick.
        tx_frames = self._advance(ms=1)
        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A single 'send()' of a payload smaller than MSS "
                "must produce exactly one outbound segment on the "
                f"next tick. Got {len(tx_frames)} TX frames."
            ),
        )

        probe = self._parse_tx(tx_frames[0])
        self._assert_segment(
            probe,
            flags=frozenset({"PSH", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=payload,
            win=65535,
            mss=None,
            wscale=None,
        )

        self.assertEqual(
            session._snd_seq.nxt,
            LOCAL__ISS + 1 + len(payload),
            msg=(
                "'_snd_nxt' must advance by len(payload) after "
                "transmitting the data segment - this consumes the "
                "outbound bytes from the send sequence space "
                "(RFC 9293 §3.4)."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg=(
                "'_snd_una' must be unchanged - the peer has not yet "
                "acknowledged our data; '_snd_una' only advances when "
                "the peer's ACK arrives."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Sending data must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_send__back_to_back_writes_respect_advertised_window(self) -> None:
        """
        Ensure that when the application sends more data
        than peer's advertised SND.WND can hold in flight,
        the sender respects the window: it transmits
        segments up to the window edge and then stops,
        leaving the remainder buffered until the peer
        acknowledges some of the in-flight bytes.

        Reference: RFC 9293 §3.8.4 (effective window = min(cwnd, snd_wnd)).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Restrict the effective and advertised send windows to 3 MSS,
        # bypassing slow-start so the window edge is the only constraint.
        snd_wnd_limit = 3 * 1460
        session._win.snd_wnd = snd_wnd_limit
        session._cc.snd_ewn = snd_wnd_limit

        payload = b"X" * 8000
        session.send(data=payload)

        # Tick 1: first MSS chunk goes out, no PSH (more buffered).
        tx_1 = self._advance(ms=1)
        self.assertEqual(
            len(tx_1),
            1,
            msg=f"Tick 1 must produce one segment. Got {len(tx_1)}.",
        )
        seg_1 = self._parse_tx(tx_1[0])
        self._assert_segment(
            seg_1,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=payload[0:1460],
            mss=None,
            wscale=None,
        )

        # Tick 2: second MSS chunk.
        tx_2 = self._advance(ms=1)
        self.assertEqual(
            len(tx_2),
            1,
            msg=f"Tick 2 must produce one segment. Got {len(tx_2)}.",
        )
        seg_2 = self._parse_tx(tx_2[0])
        self._assert_segment(
            seg_2,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 1460,
            ack=PEER__ISS + 1,
            payload=payload[1460:2920],
            mss=None,
            wscale=None,
        )

        # Tick 3: third MSS chunk - last that fits in the window.
        tx_3 = self._advance(ms=1)
        self.assertEqual(
            len(tx_3),
            1,
            msg=f"Tick 3 must produce one segment. Got {len(tx_3)}.",
        )
        seg_3 = self._parse_tx(tx_3[0])
        self._assert_segment(
            seg_3,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 2920,
            ack=PEER__ISS + 1,
            payload=payload[2920:4380],
            mss=None,
            wscale=None,
        )

        # Tick 4: window is full - no segment must be emitted even
        # though 3620 bytes remain buffered.
        tx_4 = self._advance(ms=1)
        self.assertEqual(
            tx_4,
            [],
            msg=(
                "Tick 4 must produce NO segment - the in-flight bytes "
                f"({3 * 1460}) equal the advertised window "
                f"({snd_wnd_limit}); RFC 9293 §3.8.6 forbids advancing "
                "SND.NXT past SND.UNA + SND.WND."
            ),
        )

        # Drive 100 more ms of virtual time (still well within the
        # retransmit timer, which fires at 1 s). The session must
        # remain quiescent - no spurious extra segments.
        tx_silent = self._advance(ms=100)
        self.assertEqual(
            tx_silent,
            [],
            msg=(
                "Without peer ACKs, the session must stay quiescent "
                "while the window is full - no spurious data segments "
                "may be emitted before the retransmit timer fires."
            ),
        )

        in_flight = session._snd_seq.nxt - session._snd_seq.una
        self.assertEqual(
            in_flight,
            snd_wnd_limit,
            msg=(
                f"In-flight bytes (SND.NXT - SND.UNA = {in_flight}) "
                f"must equal SND.WND = {snd_wnd_limit} after the window "
                "fills. Any larger value violates RFC 9293 §3.8.6."
            ),
        )
        self.assertEqual(
            session._snd_seq.nxt,
            LOCAL__ISS + 1 + snd_wnd_limit,
            msg="'_snd_nxt' must equal ISS + 1 + SND.WND after the window fills.",
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg="'_snd_una' must be unchanged - the peer has not ACKed any data.",
        )
        self.assertEqual(
            len(session._tx.buffer),
            len(payload),
            msg=("TX buffer must still contain all 8000 bytes - none " "have been ACKed and purged yet."),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Window-limited transmission must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_send__zero_window_triggers_persist_probe_at_rto(self) -> None:
        """
        Ensure that when the peer advertises a zero receive
        window and we have buffered data ready to send, the
        persist timer fires after the RTO interval and emits
        a 1-byte zero-window probe at SEQ = SND.UNA. The
        probe asks for a window update without draining the
        TX buffer.

        Reference: RFC 9293 §3.8.6.1 (zero-window probing).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Application send #1: 5 bytes.
        first_payload = b"hello"
        session.send(data=first_payload)
        first_tx = self._advance(ms=1)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first segment must fire on the next tick after send().",
        )

        # Peer ACKs the 5 bytes but slams the window shut.
        peer_ack_zero_window = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(first_payload),
            flags=("ACK",),
            win=0,
        )
        self._drive_rx(frame=peer_ack_zero_window)

        self.assertEqual(
            session._win.snd_wnd,
            0,
            msg="Setup precondition: peer's zero-window ACK must have set '_snd_wnd' to 0.",
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1 + len(first_payload),
            msg="Setup precondition: peer ACK'd the first 5 bytes - SND.UNA must have advanced.",
        )

        # Application send #2: 5 more bytes. These cannot go out
        # because the window is shut; they must wait for the persist
        # probe to elicit a window update from the peer.
        second_payload = b"world"
        session.send(data=second_payload)

        snd_una_before_probe = session._snd_seq.una
        snd_nxt_before_probe = session._snd_seq.nxt

        # Tick most of the way through the persist timeout. No
        # segment may fire yet - the RFC requires waiting at least
        # one RTO before the first probe.
        tx_during_wait = self._advance(ms=999)
        self.assertEqual(
            tx_during_wait,
            [],
            msg=(
                "No segment may be emitted during the persist countdown "
                "- the first zero-window probe must wait until at least "
                "one RTO (1000 ms) has elapsed (RFC 9293 §3.8.6.1)."
            ),
        )

        # Cross the persist timeout boundary. Exactly one probe must
        # fire.
        tx_at_probe = self._advance(ms=2)
        self.assertEqual(
            len(tx_at_probe),
            1,
            msg=(
                f"After 1000 ms in zero-window state with buffered data, "
                f"exactly one zero-window probe must fire (RFC 9293 "
                f"§3.8.6.1). Got {len(tx_at_probe)} TX frames."
            ),
        )

        probe = self._parse_tx(tx_at_probe[0])
        self._assert_segment(
            probe,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=snd_una_before_probe,
            ack=PEER__ISS + 1,
            payload=second_payload[:1],
            mss=None,
            wscale=None,
        )

        # The probe is exactly 1 byte and consumes 1 byte of seq
        # space. SND.UNA stays where it was - the peer has not yet
        # acknowledged the probe (and may not, if their window is
        # still genuinely zero).
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_before_probe + 1,
            msg="The persist probe consumes exactly one byte of sequence space.",
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before_probe,
            msg=(
                "SND.UNA must NOT advance during the probe - the probe "
                "is asking for a window update, not draining the buffer."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Zero-window probing must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_send__nagle_suppresses_small_write_with_unacked_data(self) -> None:
        """
        Ensure that when there is unacknowledged data in
        flight, a subsequent small send() is buffered rather
        than immediately transmitted. Nagle coalesces small
        writes until either all previously-sent data is
        ACKed or enough data has accumulated to fill a full
        MSS.

        Reference: RFC 9293 §3.7.4 (Nagle algorithm).
        Reference: RFC 1122 §4.2.3.4 (Nagle algorithm).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # First send: 1 byte. No outstanding data yet, so Nagle does
        # not gate this segment - it must fire on the next tick.
        session.send(data=b"a")
        first_tx = self._advance(ms=1)
        self.assertEqual(
            len(first_tx),
            1,
            msg=(
                "Setup precondition: with no outstanding data, the "
                "first 1-byte 'send()' must transmit immediately on "
                "the next tick (Nagle does not apply when "
                "SND.NXT == SND.UNA)."
            ),
        )
        first_seg = self._parse_tx(first_tx[0])
        self.assertEqual(
            first_seg.payload,
            b"a",
            msg="Setup precondition: first segment must carry the b'a' byte.",
        )

        # Snapshot state before the second send.
        snd_nxt_after_first = session._snd_seq.nxt
        snd_una_after_first = session._snd_seq.una
        self.assertGreater(
            snd_nxt_after_first,
            snd_una_after_first,
            msg=(
                "Setup precondition: SND.NXT must be greater than "
                "SND.UNA - i.e. there must be unacknowledged data in "
                "flight - for Nagle to apply on the next send."
            ),
        )

        # Second send: 1 byte. With outstanding data and a sub-MSS
        # buffered amount, Nagle MUST suppress immediate transmission.
        session.send(data=b"b")
        second_tx = self._advance(ms=1)

        self.assertEqual(
            second_tx,
            [],
            msg=(
                "RFC 1122 §4.2.3.4 (Nagle): with outstanding data "
                "(SND.NXT > SND.UNA) and a sub-MSS buffered amount "
                "(1 byte << MSS), 'send()' must be coalesced - the "
                "buffered byte must NOT be transmitted until either "
                "the outstanding data is ACKed or the buffer reaches "
                "a full MSS. Got "
                f"{len(second_tx)} TX frames (tinygram emission)."
            ),
        )

        # State invariants after the suppressed second send.
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_after_first,
            msg=(
                "'_snd_nxt' must NOT advance during the Nagle-suppressed "
                "tick - the b'b' byte is still buffered, not on the wire."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_after_first,
            msg="'_snd_una' must be unchanged - the peer has not ACKed anything.",
        )
        self.assertEqual(
            len(session._tx.buffer),
            2,
            msg=(
                "Both bytes must still be in the TX buffer - the b'a' "
                "byte is in flight (not yet ACKed and purged), and the "
                "b'b' byte is waiting for Nagle to release it."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Nagle suppression must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_send__tcp_nodelay_disables_nagle_partial_fires_immediately(self) -> None:
        """
        Ensure that with '_tcp_nodelay = True', a sub-MSS
        send() with outstanding unacked data fires the partial
        segment immediately on the next tick instead of being
        deferred by Nagle.

        Reference: RFC 1122 §4.2.3.4 (TCP_NODELAY disable).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._tcp_nodelay = True

        # First send: 1 byte. Fires immediately as in the Nagle
        # test (no outstanding data yet).
        session.send(data=b"a")
        first_tx = self._advance(ms=1)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first 1-byte send fires on next tick.",
        )

        snd_nxt_after_first = session._snd_seq.nxt
        self.assertGreater(
            snd_nxt_after_first,
            session._snd_seq.una,
            msg=("Setup precondition: SND.NXT > SND.UNA - " "outstanding data must be in flight for Nagle to apply."),
        )

        # Second send: 1 byte. With TCP_NODELAY set, the
        # sub-MSS partial MUST fire immediately on the next
        # tick - Nagle is disabled.
        session.send(data=b"b")
        second_tx = self._advance(ms=1)

        self.assertEqual(
            len(second_tx),
            1,
            msg=(
                "TCP_NODELAY: sub-MSS partial MUST fire "
                "immediately even with outstanding data; got "
                f"{len(second_tx)} TX frames."
            ),
        )
        second_seg = self._parse_tx(second_tx[0])
        self.assertEqual(
            second_seg.payload,
            b"b",
            msg="Second segment must carry the b'b' byte.",
        )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_after_first + 1,
            msg="SND.NXT must advance by 1 byte after the partial fires.",
        )

    def test__data_transfer_send__send_in_close_wait_is_allowed_and_transmits_data(self) -> None:
        """
        Ensure that an application can still send() data
        after the peer has closed its write half (CLOSE_WAIT)
        and that the data is actually transmitted on the wire
        with the FIN acknowledgement piggybacked. State stays
        CLOSE_WAIT.

        Reference: RFC 9293 §3.6 (CLOSE-WAIT, half-close semantics).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer half-closes by sending FIN+ACK with no data. Their
        # seq is peer_ISS+1 (the byte after their SYN); their ack
        # is LOCAL__ISS+1 (acknowledging our SYN, which they already
        # acked during the handshake's SYN+ACK).
        peer_fin_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin_ack)

        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: peer's FIN+ACK must transition us to CLOSE_WAIT.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 2,
            msg=(
                "Setup precondition: '_rcv_nxt' must equal "
                "peer_ISS + 2 after consuming peer's SYN and FIN seq "
                "bytes."
            ),
        )

        # Application send during CLOSE_WAIT must succeed.
        payload = b"after fin"
        bytes_sent = session.send(data=payload)
        self.assertEqual(
            bytes_sent,
            len(payload),
            msg=(
                f"'send()' must accept all {len(payload)} bytes into "
                f"the TX buffer in CLOSE_WAIT (RFC 9293 §3.10.4 - we "
                f"may still write until WE close). Got {bytes_sent}."
            ),
        )

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt

        tx_frames = self._advance(ms=1)
        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A 'send()' in CLOSE_WAIT must produce exactly one "
                "outbound data segment on the next tick. Got "
                f"{len(tx_frames)} TX frames."
            ),
        )

        seg = self._parse_tx(tx_frames[0])
        self._assert_segment(
            seg,
            flags=frozenset({"PSH", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 2,
            payload=payload,
            mss=None,
            wscale=None,
            win=65535,
        )

        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_before + len(payload),
            msg=("'_snd_nxt' must advance by len(payload) after " "transmitting the data segment in CLOSE_WAIT."),
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=("'_snd_una' must be unchanged - the peer has not yet " "ACK'd the new data."),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg=(
                "Sending data in CLOSE_WAIT must NOT transition the "
                "session - we only move to LAST_ACK when WE close, "
                "via 'session.close()'."
            ),
        )
        self.assertFalse(
            session._closing,
            msg=(
                "Sending data must not set the '_closing' flag - that "
                "flag is owned by 'close()' and gates the eventual "
                "FIN emission."
            ),
        )

    def test__data_transfer_send__send_after_close_raises_immediately(self) -> None:
        """
        Ensure any send() issued after the application has
        called close() is rejected with TcpSessionError —
        once close() has been invoked, the application has
        relinquished its right to write further data on the
        connection.

        Reference: RFC 9293 §3.10.4 (CLOSE call: subsequent SEND returns "connection closing").
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Positive control: 'send()' works in ESTABLISHED before close().
        bytes_sent = session.send(data=b"pre close")
        self.assertEqual(
            bytes_sent,
            len(b"pre close"),
            msg="Setup precondition: 'send()' must work normally in ESTABLISHED before close().",
        )

        # Application closes the connection.
        session.close()
        self.assertTrue(
            session._closing,
            msg="Setup precondition: 'close()' must set the '_closing' flag.",
        )

        # Any subsequent send() must be rejected with the
        # closing-error response.
        with self.assertRaises(TcpSessionError) as error_ctx:
            session.send(data=b"after close")

        self.assertIn(
            "closing",
            str(error_ctx.exception).lower(),
            msg=(
                "Post-close send() rejection must surface a "
                "'connection closing' error to the application. "
                f"Got: {error_ctx.exception!r}."
            ),
        )

    def test__data_transfer_send__multi_mss_payload_segments_with_psh_only_on_last(self) -> None:
        """
        Ensure that an application send() of a payload
        larger than MSS is segmented into MSS-sized chunks,
        each chunk emitted on a successive virtual-clock
        tick, with the PSH bit set only on the final segment
        of the write.

        Reference: RFC 1122 §4.2.2.2 (PSH on last segment of write).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Bypass slow-start so all three segments can fly without
        # waiting for peer ACKs - this test is about segmentation and
        # PSH placement, not congestion control.
        session._cc.snd_ewn = PEER__WIN

        payload = b"X" * 4000
        bytes_sent = session.send(data=payload)
        self.assertEqual(
            bytes_sent,
            len(payload),
            msg=f"'send()' must accept all {len(payload)} bytes into the TX buffer. Got {bytes_sent}.",
        )

        # Tick 1: first MSS-sized segment, no PSH.
        tx_tick_1 = self._advance(ms=1)
        self.assertEqual(
            len(tx_tick_1),
            1,
            msg="Tick 1 must produce exactly one outbound segment (the first MSS chunk).",
        )

        seg_1 = self._parse_tx(tx_tick_1[0])
        self._assert_segment(
            seg_1,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=payload[:1460],
            win=65535,
            mss=None,
            wscale=None,
        )

        # Tick 2: second MSS-sized segment, still no PSH (1080 bytes
        # remain in the buffer).
        tx_tick_2 = self._advance(ms=1)
        self.assertEqual(
            len(tx_tick_2),
            1,
            msg="Tick 2 must produce exactly one outbound segment (the second MSS chunk).",
        )

        seg_2 = self._parse_tx(tx_tick_2[0])
        self._assert_segment(
            seg_2,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 1460,
            ack=PEER__ISS + 1,
            payload=payload[1460:2920],
            win=65535,
            mss=None,
            wscale=None,
        )

        # Tick 3: final 1080-byte segment, PSH set (this drains the
        # TX buffer - per RFC 1122 §4.2.2.2 it is the LAST segment of
        # the write).
        tx_tick_3 = self._advance(ms=1)
        self.assertEqual(
            len(tx_tick_3),
            1,
            msg="Tick 3 must produce exactly one outbound segment (the final fragment).",
        )

        seg_3 = self._parse_tx(tx_tick_3[0])
        self._assert_segment(
            seg_3,
            flags=frozenset({"PSH", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 2920,
            ack=PEER__ISS + 1,
            payload=payload[2920:],
            win=65535,
            mss=None,
            wscale=None,
        )

        # Final state checks: SND.NXT covers the full 4000 bytes,
        # SND.UNA still at the post-handshake value (peer has not
        # ACKed yet), state stays ESTABLISHED.
        self.assertEqual(
            session._snd_seq.nxt,
            LOCAL__ISS + 1 + len(payload),
            msg=("After three segments totalling len(payload) bytes, " "'_snd_nxt' must equal ISS + 1 + len(payload)."),
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg=("'_snd_una' must be unchanged - the peer has not yet " "acknowledged any of the data we sent."),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Sending data must not transition the session out of ESTABLISHED.",
        )


class TestTcpDataTransfer__PersistCadence(TcpTestCase):
    """
    Integration tests for the RFC 9293 §3.8.6.1 zero-window
    persist-timer cadence:

        "The transmitting host SHOULD send the first zero-window
         probe when a zero window has existed for the
         retransmission timeout period (see Section 3.8.1), and
         SHOULD increase exponentially the interval between
         successive probes (MUST-58)."

    PyTCP's implementation (tcp__session.py:1589-1610):

        initial: TCP__RTO__INITIAL_MS (1000 ms)
        after each probe: persist_timeout = min(persist_timeout * 2,
                                                TCP__PERSIST__TIMEOUT_MAX_MS)
        cap: TCP__PERSIST__TIMEOUT_MAX_MS (60_000 ms)

    Cadence: 1 s -> 2 s -> 4 s -> 8 s -> 16 s -> 32 s -> 60 s
             -> 60 s -> ... (capped indefinitely until peer
             reopens window or R2 fires).

    The existing 'test__data_transfer_send__zero_window_triggers_persist_probe_at_rto'
    in this file pins the FIRST probe at t=1000 ms. These
    tests pin the doubling cadence and the 60-second cap.
    """

    def _drive_into_persist_with_data_pending(self, *, iss: int, peer_iss: int) -> TcpSession:
        """
        Drive the session into persist state with data pending:
        handshake, send some bytes, peer ACKs with win=0, send
        more bytes (cannot go out, persist arms).
        """

        session = self._drive_handshake_to_established(iss=iss, peer_iss=peer_iss)
        session.send(data=b"hello")
        self._advance(ms=1)
        peer_zero_window = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 1 + 5,
            flags=("ACK",),
            win=0,
        )
        self._drive_rx(frame=peer_zero_window)
        assert session._win.snd_wnd == 0, "Setup: peer must have shut the window."
        session.send(data=b"x" * 10)
        return session

    def test__persist__second_probe_fires_at_double_initial_timeout(self) -> None:
        """
        Ensure the second persist probe fires after 2*RTO
        (= 2000 ms), not after another 1*RTO. Pins the
        doubling cadence from probe #1 to probe #2.

        Reference: RFC 9293 §3.8.6.1 (zero-window probing exponential backoff).
        """

        self._drive_into_persist_with_data_pending(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        first_probe_tx = self._advance(ms=1001)
        first_probes = [self._parse_tx(f) for f in first_probe_tx]
        self.assertEqual(
            sum(1 for p in first_probes if p.payload),
            1,
            msg=f"Setup: exactly one probe must fire by t=1001 ms. Got {len(first_probes)}.",
        )

        too_early_tx = self._advance(ms=1000)
        early_probes = [self._parse_tx(f) for f in too_early_tx if self._parse_tx(f).payload]
        self.assertEqual(
            len(early_probes),
            0,
            msg=(
                "Persist doubling: probe #2 MUST NOT fire "
                "at t = probe#1 + 1000 ms. The persist interval "
                "after probe #1 is 2*RTO = 2000 ms, so the timer "
                "should still be counting down. Got "
                f"{len(early_probes)} probe(s) at t=2001 ms."
            ),
        )

        late_tx = self._advance(ms=1100)
        late_probes = [self._parse_tx(f) for f in late_tx if self._parse_tx(f).payload]
        self.assertEqual(
            len(late_probes),
            1,
            msg=(
                "Persist doubling: probe #2 MUST fire at "
                "t = probe#1 + 2*RTO = ~3000 ms. Got "
                f"{len(late_probes)} probe(s) in the [2001, 3101] ms "
                "window."
            ),
        )

    def test__persist__fourth_probe_fires_at_8x_initial_timeout(self) -> None:
        """
        Ensure cumulative doubling: probe #1 at 1 s, #2 at
        3 s (1+2), #3 at 7 s (1+2+4), #4 at 15 s (1+2+4+8).
        The intervals 1 / 2 / 4 / 8 s pin the geometric
        series through four probes.

        Reference: RFC 9293 §3.8.6.1 (zero-window probing exponential backoff).
        """

        self._drive_into_persist_with_data_pending(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        probe_arrival_times: list[int] = []
        clock_ms = 0
        while clock_ms < 16_000:
            tx = self._advance(ms=100)
            clock_ms += 100
            for frame in tx:
                probe = self._parse_tx(frame)
                if probe.payload:
                    probe_arrival_times.append(clock_ms)

        self.assertGreaterEqual(
            len(probe_arrival_times),
            4,
            msg=(
                "By t=16 s with peer's window shut, at least "
                "4 persist probes MUST have fired (at ~1, ~3, "
                f"~7, ~15 s). Got {len(probe_arrival_times)} "
                f"probe(s) at {probe_arrival_times}."
            ),
        )
        expected = [1000, 3000, 7000, 15000]
        actual = probe_arrival_times[:4]
        for i, (exp, act) in enumerate(zip(expected, actual)):
            self.assertLessEqual(
                abs(act - exp),
                150,
                msg=(
                    f"Persist doubling cadence: probe #{i + 1} "
                    f"expected at ~{exp} ms (cumulative of "
                    f"intervals "
                    f"{[2 ** k * 1000 for k in range(i + 1)]}), "
                    f"got {act} ms. Tolerance: 150 ms. All "
                    f"probe times: {probe_arrival_times}."
                ),
            )

    def test__persist__interval_caps_at_60_seconds(self) -> None:
        """
        Ensure that after enough probes that the doubled
        interval would exceed TCP__PERSIST__TIMEOUT_MAX_MS (60 s),
        the cap kicks in and subsequent probes fire on a
        fixed 60 s schedule.

        Reference: RFC 9293 §3.8.6.1 (zero-window probing interval cap).
        """

        from pytcp.protocols.tcp import tcp__constants

        session = self._drive_into_persist_with_data_pending(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Touch the persist machinery so it has been initialized.
        self._advance(ms=1001)
        # Pin '_persist_timeout' to the cap directly and re-arm
        # the timer at that interval. The next probe must fire
        # at exactly TCP__PERSIST__TIMEOUT_MAX_MS, NOT 2 * TCP__PERSIST__TIMEOUT_MAX_MS.
        session._persist.timeout = tcp__constants.TCP__PERSIST__TIMEOUT_MAX_MS
        session._arm_timer("persist", tcp__constants.TCP__PERSIST__TIMEOUT_MAX_MS)

        early_tx = self._advance(ms=tcp__constants.TCP__PERSIST__TIMEOUT_MAX_MS - 100)
        early_probes = [self._parse_tx(f) for f in early_tx if self._parse_tx(f).payload]
        self.assertEqual(
            len(early_probes),
            0,
            msg=(
                f"At t = cap - 100 ms, no probe should fire "
                f"(timer still counting). Got {len(early_probes)} "
                "probe(s)."
            ),
        )

        cap_tx = self._advance(ms=200)
        cap_probes = [self._parse_tx(f) for f in cap_tx if self._parse_tx(f).payload]
        self.assertEqual(
            len(cap_probes),
            1,
            msg=(
                f"Persist cap: probe MUST fire at t = "
                f"{tcp__constants.TCP__PERSIST__TIMEOUT_MAX_MS} ms after "
                f"the previous one (the cap'd interval). Got "
                f"{len(cap_probes)} probe(s)."
            ),
        )
        self.assertEqual(
            session._persist.timeout,
            tcp__constants.TCP__PERSIST__TIMEOUT_MAX_MS,
            msg=(
                "Persist cap: '_persist_timeout' MUST stay at "
                "TCP__PERSIST__TIMEOUT_MAX_MS after a post-cap probe. "
                f"Got _persist_timeout={session._persist.timeout} ms."
            ),
        )

    def test__persist__peer_window_reopen_resets_timeout_to_initial(self) -> None:
        """
        Ensure that when peer reopens the window, the
        persist timer is deactivated AND '_persist_timeout'
        is reset to the initial value
        (TCP__RTO__INITIAL_MS) so a future zero-window
        event starts fresh at 1 s, not at the previously-
        doubled value.

        Reference: RFC 9293 §3.8.6.1 (persist timer reset on window reopen).
        """

        from pytcp.protocols.tcp import tcp__constants

        session = self._drive_into_persist_with_data_pending(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Advance past several probes so '_persist_timeout' has
        # doubled multiple times.
        self._advance(ms=8000)
        self.assertGreater(
            session._persist.timeout,
            1000,
            msg=(
                "Setup invariant: after several probes, "
                "'_persist_timeout' MUST be > 1000 ms (doubled). "
                f"Got {session._persist.timeout} ms."
            ),
        )

        peer_window_update = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 5,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_window_update)

        self.assertFalse(
            session._persist.active,
            msg="Peer's window reopen MUST deactivate persist mode.",
        )
        self.assertEqual(
            session._persist.timeout,
            tcp__constants.TCP__RTO__INITIAL_MS,
            msg=(
                "RFC 9293 §3.8.6.1: peer's window reopen MUST reset "
                "'_persist_timeout' to TCP__RTO__INITIAL_MS "
                "(1000 ms) so a future zero-window event restarts "
                "the geometric series from the beginning, not from "
                "the previously-doubled value. Got "
                f"_persist_timeout={session._persist.timeout} ms."
            ),
        )


class TestTcpDataTransferRfc6691ReqB(TcpTestCase):
    """
    RFC 6691 §2 Req B: "the sender MUST reduce the TCP data
    length to account for any IP or TCP options that it is
    including in the packets that it sends." When a session
    has timestamps negotiated bilaterally, every outbound data
    segment carries 12 bytes of TSopt (10 + 2 NOP padding); a
    naive 'transmit_data_len = min(_snd_mss, ...)' produces an
    on-wire segment of fixed_headers + 12 (options) + _snd_mss
    (data) which exceeds the MTU by exactly options_len bytes
    and fragments at the IP layer.
    """

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=0x1234_5678,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._ts.send_ts
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__data_transfer__rfc6691_req_b__tsopt_segment_data_capped(self) -> None:
        """
        Ensure that with TSopt active, an outbound data segment
        carries at most '_snd_mss - options_overhead' bytes of
        payload so the on-wire packet stays within the link
        MTU. Per §2 Req B, the sender MUST reduce the data
        length when options consume option-block bytes.

        Reference: RFC 6691 §2 Req B (sender reduces data length for options).
        """

        session = self._drive_handshake_with_tsopt(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Send 2x MSS bytes; the first segment must be the
        # full options-aware MSS, not _snd_mss naively.
        session.send(data=b"X" * (2 * PEER__MSS))
        tx = self._advance(ms=1)
        self.assertGreaterEqual(
            len(tx),
            1,
            msg="Setup precondition: at least one segment fires.",
        )
        first = self._parse_tx(tx[0])
        # Per §2 Req B: data + TSopt (12 bytes) + fixed TCP header
        # (20 bytes) ≤ MTU - fixed IP header (20). With MSS
        # negotiated as 1460 (= 1500 - 20 - 20), the data length
        # must be ≤ 1460 - 12 = 1448 to stay under MTU.
        options_overhead = 12  # TSopt 10 bytes + 2 NOPs
        max_data_per_segment = PEER__MSS - options_overhead
        self.assertLessEqual(
            len(first.payload),
            max_data_per_segment,
            msg=(
                "RFC 6691 §2 Req B: with TSopt on every segment "
                "the sender MUST reduce data length by the "
                f"options overhead ({options_overhead} bytes). "
                f"Expected ≤ {max_data_per_segment}, got "
                f"{len(first.payload)} bytes."
            ),
        )
