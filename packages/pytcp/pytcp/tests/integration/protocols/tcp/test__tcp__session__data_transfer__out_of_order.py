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
This module contains integration tests for the TCP receive-side
out-of-order (OOO) segment handling in the 'TcpSession' state
machine, covering gap detection, OOO queue storage, fast-retransmit
duplicate-ACK emission, and gap-fill drain semantics per RFC 9293
§3.10.7.4 / §3.4.

The tests in this file drive a session through the active-open
handshake to ESTABLISHED and then feed segments out of order from
the peer, asserting both the receive buffer state and the outbound
ACK shapes that result.

Reference RFCs:
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 9293 §3.4        Sequence numbers
    RFC 9293 §3.8        Data Communication
    RFC 5681 §3.2        Fast retransmit / fast recovery
    RFC 1122 §4.2.2.20   General TCP requirements

pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__out_of_order.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__enums import FsmState
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


class TestTcpDataTransfer__OutOfOrder(TcpTestCase):
    """
    Integration tests for inbound out-of-order segment handling and
    the OOO queue / dup-ACK / gap-fill drain machinery.
    """

    def test__data_transfer_out_of_order__gap_buffers_segment_and_dup_ack_then_fill_drains(self) -> None:
        """
        Ensure the OOO machinery handles a one-segment gap:
        peer's segment #2 arrives before segment #1, the
        receiver buffers it and emits a duplicate ACK
        pointing at the still-expected RCV.NXT; when
        segment #1 arrives the receiver drains the OOO
        queue, advances RCV.NXT past both segments, and
        emits a cumulative ACK acknowledging both.

        Reference: RFC 5681 §4.2 (immediate ACK on out-of-order segment).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        seg1_payload = b"X" * 1460
        seg2_payload = b"Y" * 1460

        # Peer sends segment #2 FIRST (out of order). seq = peer_ISS+1
        # + 1460 = the byte AFTER segment #1's last byte.
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 1460,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=seg2_payload,
            win=PEER__WIN,
        )
        ooo_tx = self._drive_rx(frame=seg2)

        # The OOO arrival must trigger one fast-retransmit dup-ACK
        # pointing at the missing RCV.NXT.
        self.assertEqual(
            len(ooo_tx),
            1,
            msg=(
                "An OOO segment arriving with seq > RCV.NXT must "
                "trigger exactly one fast-retransmit dup-ACK pointing "
                f"at the missing RCV.NXT. Got {len(ooo_tx)} TX frames."
            ),
        )
        dup_ack = self._parse_tx(ooo_tx[0])
        self._assert_segment(
            dup_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=None,
            wscale=None,
            win=65535,
        )
        self.assertIn(
            PEER__ISS + 1 + 1460,
            session._ooo_packet_queue,
            msg=(
                "The OOO segment must be buffered in '_ooo_packet_queue' "
                "keyed by its arrival SEQ so the gap-fill drain can "
                "retrieve it later."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg=(
                "Out-of-order data must NOT be delivered to "
                "'_rx_buffer' - it stays in the OOO queue until the "
                "gap is filled."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1,
            msg=("RCV.NXT must NOT advance on an OOO arrival - the " "byte we are still expecting is unchanged."),
        )

        # Peer sends segment #1 - the gap-fill.
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=seg1_payload,
            win=PEER__WIN,
        )
        gap_fill_tx = self._drive_rx(frame=seg1)

        # The gap-fill arrival processes seg #1 then drains seg #2
        # from the OOO queue. The combined effect (two segments in
        # one drive) crosses the "ACK every other segment" threshold,
        # so a single inline cumulative ACK fires.
        self.assertEqual(
            len(gap_fill_tx),
            1,
            msg=(
                "The gap-fill segment must trigger exactly one inline "
                "cumulative ACK after the OOO drain (every-other-segment "
                f"threshold reached). Got {len(gap_fill_tx)} TX frames."
            ),
        )
        cumulative_ack = self._parse_tx(gap_fill_tx[0])
        self._assert_segment(
            cumulative_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1 + 2 * 1460,
            payload=b"",
            mss=None,
            wscale=None,
            # Advertised window reflects '_rx_buffer' occupancy per
            # RFC 9293 §3.8.6: 65535 max minus the 2 * 1460 bytes
            # delivered to the buffer after the gap-fill drain.
            win=65535 - 2 * 1460,
        )

        # Both payloads delivered in original order.
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload,
            msg=(
                "After the gap-fill drain, '_rx_buffer' must contain "
                "seg #1 followed by seg #2 in the order the application "
                "intended."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + 2 * 1460,
            msg=("RCV.NXT must advance past BOTH segments after the " "drain."),
        )
        self.assertEqual(
            session._rcv_seq.una,
            session._rcv_seq.nxt,
            msg=("RCV.UNA must equal RCV.NXT after the inline " "cumulative ACK fires."),
        )
        self.assertEqual(
            session._ooo_packet_queue,
            {},
            msg=("The OOO queue must be empty after the drain - segment " "#2 has been retrieved and processed."),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="OOO handling must not change the session state.",
        )

    def test__data_transfer_out_of_order__multi_gap_delivery_preserves_application_order(self) -> None:
        """
        Ensure the OOO machinery handles multiple non-
        contiguous gaps: four segments arriving in the order
        [seg2, seg4, seg1, seg3] are buffered with distinct
        OOO-queue keys; once seg1 and seg3 fill the gaps,
        the recursive drain delivers all four to '_rx_buffer'
        in application order.

        Reference: RFC 5681 §4.2 (immediate ACK on out-of-order segment).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        seg1_payload = b"A" * 1460
        seg2_payload = b"B" * 1460
        seg3_payload = b"C" * 1460
        seg4_payload = b"D" * 1460
        seg2_seq = PEER__ISS + 1 + 1460
        seg3_seq = PEER__ISS + 1 + 2 * 1460
        seg4_seq = PEER__ISS + 1 + 3 * 1460

        def _build(seq: int, payload: bytes) -> bytes:
            """Helper: build a peer data segment at the given seq."""
            return build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=seq,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                payload=payload,
                win=PEER__WIN,
            )

        # Stage A: seg2 arrives first (OOO).
        tx_a = self._drive_rx(frame=_build(seg2_seq, seg2_payload))
        self.assertEqual(len(tx_a), 1, msg="seg2 OOO arrival must trigger one dup-ACK.")
        self.assertEqual(
            self._parse_tx(tx_a[0]).ack,
            PEER__ISS + 1,
            msg="seg2 dup-ACK must point at still-missing RCV.NXT = peer_ISS + 1.",
        )
        self.assertIn(seg2_seq, session._ooo_packet_queue, msg="seg2 must be stored in OOO queue.")
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1,
            msg="RCV.NXT must NOT advance on the seg2 OOO arrival.",
        )

        # Stage B: seg4 arrives second (also OOO, distinct gap).
        tx_b = self._drive_rx(frame=_build(seg4_seq, seg4_payload))
        self.assertEqual(len(tx_b), 1, msg="seg4 OOO arrival must trigger one dup-ACK.")
        self.assertEqual(
            self._parse_tx(tx_b[0]).ack,
            PEER__ISS + 1,
            msg="seg4 dup-ACK must point at still-missing RCV.NXT = peer_ISS + 1.",
        )
        self.assertIn(seg2_seq, session._ooo_packet_queue, msg="seg2 must remain in OOO queue after seg4 arrives.")
        self.assertIn(seg4_seq, session._ooo_packet_queue, msg="seg4 must be stored in OOO queue.")
        self.assertEqual(
            len(session._ooo_packet_queue),
            2,
            msg=(
                "OOO queue must hold both seg2 and seg4 as distinct "
                "entries; their keys (peer_ISS+1+1460 vs "
                "peer_ISS+1+4380) must not collide."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg="rx_buffer must remain empty while there is a gap at RCV.NXT.",
        )

        # Stage C: seg1 arrives, fills first gap. seg2 drains. seg4
        # remains in OOO queue (RCV.NXT is now at peer_ISS+1+2*1460,
        # not peer_ISS+1+4380).
        tx_c = self._drive_rx(frame=_build(PEER__ISS + 1, seg1_payload))
        self.assertEqual(
            len(tx_c),
            1,
            msg=(
                "seg1 gap-fill drains seg2 too (2 segments processed); "
                "the every-other-segment threshold fires one cumulative "
                "ACK."
            ),
        )
        self.assertEqual(
            self._parse_tx(tx_c[0]).ack,
            PEER__ISS + 1 + 2 * 1460,
            msg="Cumulative ACK after seg1+seg2 drain must cover both.",
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload,
            msg="rx_buffer must hold seg1 followed by seg2 in send order.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + 2 * 1460,
            msg="RCV.NXT must equal peer_ISS + 1 + 2*MSS after the seg1+seg2 drain.",
        )
        self.assertNotIn(
            seg2_seq,
            session._ooo_packet_queue,
            msg="seg2 must have been removed from the OOO queue during the drain.",
        )
        self.assertIn(
            seg4_seq,
            session._ooo_packet_queue,
            msg=("seg4 must REMAIN in the OOO queue - the seg3 gap is " "still present so seg4 cannot drain yet."),
        )

        # Stage D: seg3 arrives, fills second gap. seg4 drains.
        tx_d = self._drive_rx(frame=_build(seg3_seq, seg3_payload))
        self.assertEqual(
            len(tx_d),
            1,
            msg=("seg3 gap-fill drains seg4 too; the every-other-segment " "threshold fires one cumulative ACK."),
        )
        self.assertEqual(
            self._parse_tx(tx_d[0]).ack,
            PEER__ISS + 1 + 4 * 1460,
            msg="Cumulative ACK after seg3+seg4 drain must cover everything received.",
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload + seg3_payload + seg4_payload,
            msg=(
                "rx_buffer must hold all four payloads in their original "
                "application order (A, B, C, D) regardless of the "
                "out-of-order arrival sequence on the wire."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + 4 * 1460,
            msg="RCV.NXT must equal peer_ISS + 1 + 4*MSS after all four segments drain.",
        )
        self.assertEqual(
            session._ooo_packet_queue,
            {},
            msg="OOO queue must be empty after the final drain.",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Multi-gap OOO handling must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_out_of_order__overlapping_segment_keeps_new_bytes_only(self) -> None:
        """
        Ensure a segment whose SEQ lies before RCV.NXT but
        whose tail extends past RCV.NXT is not rejected
        outright: the receiver discards the already-received
        prefix, accepts the new tail bytes, advances RCV.NXT
        accordingly, and acknowledges the new boundary.

        Reference: RFC 9293 §3.10.7.4 (receiver tolerance for overlap).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Stage 1: peer sends an in-order 5-byte segment.
        first_payload = b"hello"
        self._drive_rx(
            frame=build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                payload=first_payload,
                win=PEER__WIN,
            )
        )

        self.assertEqual(
            bytes(session._rx_buffer),
            first_payload,
            msg="Setup precondition: first 5 bytes must be in '_rx_buffer'.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + len(first_payload),
            msg="Setup precondition: RCV.NXT must advance past the first segment.",
        )

        # Stage 2: peer sends an OVERLAPPING segment. seq is back at
        # PEER__ISS+1 (covering the already-received b"hello") but
        # the payload extends past the previous tail by 6 new bytes.
        overlap_payload = b"hello world"
        new_bytes = overlap_payload[len(first_payload) :]
        self.assertEqual(new_bytes, b" world", msg="Test arithmetic: new tail bytes must be b' world'.")

        overlap_segment = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=overlap_payload,
            win=PEER__WIN,
        )
        inline_tx = self._drive_rx(frame=overlap_segment)

        # The receiver must accept the new tail bytes and emit
        # an inline ACK acknowledging the new boundary.
        self.assertEqual(
            len(inline_tx),
            1,
            msg=(
                "An overlapping segment whose tail extends past "
                "RCV.NXT must elicit exactly one inline ACK "
                f"acknowledging the new boundary. Got {len(inline_tx)} "
                "TX frames."
            ),
        )

        ack = self._parse_tx(inline_tx[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1 + len(overlap_payload),
            payload=b"",
            mss=None,
            wscale=None,
            # Advertised window reflects '_rx_buffer' occupancy per
            # RFC 9293 §3.8.6: 65535 max minus the 11 bytes of
            # 'b"hello world"' now in the buffer (the overlap
            # prefix is sliced away, not double-enqueued).
            win=65535 - len(overlap_payload),
        )

        # The receive buffer must contain exactly the original 5
        # bytes followed by the 6 new bytes - the overlap region
        # is discarded so no duplication of b"hello".
        self.assertEqual(
            bytes(session._rx_buffer),
            overlap_payload,
            msg=(
                "After the overlap, '_rx_buffer' must contain the "
                "11 bytes of b'hello world' exactly - the overlap "
                "region (the first 5 bytes that match what was "
                "already received) must be discarded, not "
                "double-enqueued."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + len(overlap_payload),
            msg=("RCV.NXT must advance to peer_ISS + 1 + 11 after " "consuming the overlap segment's new tail bytes."),
        )
        self.assertEqual(
            session._rcv_seq.una,
            session._rcv_seq.nxt,
            msg=(
                "RCV.UNA must equal RCV.NXT after the inline ACK fires "
                "- the every-other-segment threshold (count == 2 "
                "across the original segment + the overlap) forces "
                "the inline ACK."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Overlap handling must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_out_of_order__five_ooo_segments_emit_at_least_three_dup_acks(self) -> None:
        """
        Ensure that when the peer delivers a burst of OOO
        segments past a single gap, PyTCP-as-receiver emits
        at least three duplicate ACKs at the still-expected
        RCV.NXT — the threshold required to trigger peer's
        fast-retransmit.

        Reference: RFC 5681 §3.2 (fast retransmit on third dup-ACK).
        Reference: RFC 5681 §4.2 (immediate ACK on out-of-order segment).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Pin the count-based path: disable bilateral SACK so the SACK
        # byte-rule analysis is out of scope for this test. The same
        # cap-at-2 gate would inhibit SACK byte-rule recovery too, but
        # the count-rule is the cleaner failure to pin first.
        session._advertise.send_sack = False
        # Clear handshake-residual frames (our SYN, our third-leg ACK)
        # so 'self._frames_tx' below contains only the OOO-burst's
        # outbound dup-ACKs. The third-leg ACK has the same shape as
        # a dup-ACK ('ack == PEER__ISS + 1, seq == LOCAL__ISS + 1,
        # flags={"ACK"}'), so leaving it in would inflate the count.
        self._frames_tx.clear()

        # 5 OOO segments past a 1000-byte gap, each 100 bytes.
        # RCV.NXT stays at PEER__ISS + 1 throughout (the gap is at
        # the start of peer's stream).
        ooo_segment_count = 5
        gap_size = 1000
        ooo_payload_size = 100

        for i in range(ooo_segment_count):
            seg_seq = PEER__ISS + 1 + gap_size + i * ooo_payload_size
            ooo_seg = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=seg_seq,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                payload=b"X" * ooo_payload_size,
            )
            self._drive_rx(frame=ooo_seg)

        # Count outbound ACK frames at the still-expected RCV.NXT
        # (= PEER__ISS + 1). Each is a dup-ACK from peer's
        # perspective.
        dup_ack_count = 0
        for frame in self._frames_tx:
            probe = self._parse_tx(frame)
            if probe.ack == PEER__ISS + 1 and probe.seq == LOCAL__ISS + 1:
                self.assertEqual(
                    probe.flags,
                    frozenset({"ACK"}),
                    msg=(
                        "Each outbound dup-ACK during the gap MUST be "
                        "a bare ACK with no other flags set. "
                        f"Got: {probe.flags!r}"
                    ),
                )
                self.assertEqual(
                    probe.payload,
                    b"",
                    msg=(
                        "Each outbound dup-ACK during the gap MUST "
                        "carry no payload (it is a control segment). "
                        f"Got {len(probe.payload)} bytes."
                    ),
                )
                dup_ack_count += 1

        self.assertGreaterEqual(
            dup_ack_count,
            3,
            msg=(
                "The receiver MUST send an immediate duplicate "
                "ACK on every out-of-order segment arrival; "
                "the sender peer requires at least 3 duplicate "
                "ACKs to trigger fast-retransmit. With "
                f"{ooo_segment_count} OOO segments delivered past "
                "the gap, the receiver MUST emit at least 3 "
                "duplicate ACKs at the still-expected RCV.NXT. "
                f"Got dup-ACK count: {dup_ack_count}."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="OOO-burst handling must not transition the session out of ESTABLISHED.",
        )
