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
This module contains integration tests for the TCP receive-side data
transfer in the 'TcpSession' state machine, covering in-order data
delivery, the delayed-ACK mechanism, and out-of-window / unacceptable
segment rejection per RFC 9293 §3.10.7.4 and RFC 1122 §4.2.3.2.

The tests in this file drive a session through the active-open
handshake to ESTABLISHED and then feed data segments from the peer,
asserting both the delivery of bytes into '_rx_buffer' and the wire
shape of any acknowledgements the stack produces.

Reference RFCs:
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 9293 §3.4        Sequence numbers
    RFC 9293 §3.8        Data Communication
    RFC 1122 §4.2.3.2    When to Send an ACK Segment (delayed ACK,
                         "ACK every other segment", 500 ms ceiling)
    RFC 1122 §4.2.2.20   General TCP requirements

pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__recv.py

ver 3.0.10
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__constants import TCP__DELAYED_ACK__DELAY_MS
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


class TestTcpDataTransfer__Recv(TcpTestCase):
    """
    Integration tests for inbound data segments and the corresponding
    acknowledgement / receive-buffer behaviour.
    """

    def test__data_transfer_recv__in_order_data_delivered_with_delayed_ack(self) -> None:
        """
        Ensure in-order data arriving on an ESTABLISHED
        session is queued into '_rx_buffer' and acknowledged
        via the delayed-ACK mechanism: no inline ACK on
        arrival; the ACK fires within TCP__DELAYED_ACK__DELAY_MS ms
        carrying ack = RCV.NXT.

        Reference: RFC 1122 §4.2.3.2 (delayed ACK timer < 500 ms).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        rcv_una_before = session._rcv_seq.una
        snd_nxt_before = session._snd_seq.nxt

        # Peer sends 5 bytes of in-order data.
        payload = b"hello"
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=payload,
            win=PEER__WIN,
        )
        inline_tx = self._drive_rx(frame=peer_data)

        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "Receiving in-order data must not elicit an immediate "
                "inline ACK from '_tcp_fsm_established'; the ACK is "
                "delivered by the timer-driven delayed-ACK mechanism."
            ),
        )

        # Data is delivered, RCV.NXT advances, RCV.UNA unchanged.
        self.assertEqual(
            bytes(session._rx_buffer),
            payload,
            msg=(
                f"In-order data must be queued into '_rx_buffer'. Got "
                f"{bytes(session._rx_buffer)!r}, expected {payload!r}."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + len(payload),
            msg=("'_rcv_nxt' must advance by len(payload) after " "consuming the in-order data segment."),
        )
        self.assertEqual(
            session._rcv_seq.una,
            rcv_una_before,
            msg=("'_rcv_una' must be unchanged - we have not yet " "acknowledged the new data."),
        )

        # No ACK during the first half of the delayed-ACK interval.
        early_tx = self._advance(ms=TCP__DELAYED_ACK__DELAY_MS // 2)
        self.assertEqual(
            early_tx,
            [],
            msg=(
                f"Within {TCP__DELAYED_ACK__DELAY_MS // 2} ms of data receipt, "
                f"no ACK may fire - the delayed-ACK timer (interval "
                f"{TCP__DELAYED_ACK__DELAY_MS} ms) is still counting down per "
                "RFC 1122 §4.2.3.2."
            ),
        )

        # Within the delayed-ACK interval (plus a small grace for the
        # tick boundary), exactly one bare ACK must fire.
        ack_tx = self._advance(ms=TCP__DELAYED_ACK__DELAY_MS)
        self.assertEqual(
            len(ack_tx),
            1,
            msg=(
                f"Within {TCP__DELAYED_ACK__DELAY_MS} ms of the half-interval "
                "tick, exactly one delayed ACK must fire. Got "
                f"{len(ack_tx)} TX frames."
            ),
        )

        ack = self._parse_tx(ack_tx[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=snd_nxt_before,
            ack=PEER__ISS + 1 + len(payload),
            payload=b"",
            mss=None,
            wscale=None,
            # Advertised window reflects '_rx_buffer' occupancy per
            # RFC 9293 §3.8.6: 65535 max minus the bytes still
            # waiting to be drained by 'recv()'.
            win=65535 - len(payload),
        )

        # After the ACK fires, '_rcv_una' must catch up with '_rcv_nxt'.
        self.assertEqual(
            session._rcv_seq.una,
            session._rcv_seq.nxt,
            msg=(
                "After the delayed ACK fires, '_rcv_una' must equal "
                "'_rcv_nxt' - we have acknowledged everything we have "
                "received."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Receiving data must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_recv__back_to_back_full_segments_trigger_immediate_ack(self) -> None:
        """
        Ensure that when two back-to-back full-MSS data
        segments arrive on an ESTABLISHED session, the second
        segment triggers an immediate inline ACK covering
        both segments rather than both being deferred via the
        delayed-ACK timer.

        Reference: RFC 1122 §4.2.3.2 (ACK at least every second segment).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends two back-to-back full-MSS segments. Each segment
        # carries 1460 bytes of payload, exactly MSS = MTU(1500) -
        # IPv4(20) - TCP(20).
        seg1_payload = b"X" * 1460
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=seg1_payload,
            win=PEER__WIN,
        )
        seg2_payload = b"Y" * 1460
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 1460,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=seg2_payload,
            win=PEER__WIN,
        )

        # First segment: no inline ACK (subject to delayed-ACK timer).
        inline_tx_1 = self._drive_rx(frame=seg1)
        self.assertEqual(
            inline_tx_1,
            [],
            msg=(
                "The first full-MSS segment in a stream must NOT "
                "elicit an immediate ACK - it is subject to the "
                "delayed-ACK timer (RFC 1122 §4.2.3.2)."
            ),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + 1460,
            msg="After the first segment, '_rcv_nxt' must advance by MSS bytes.",
        )

        # Second segment: per the every-other-segment rule, the
        # receiver MUST emit an inline ACK now.
        inline_tx_2 = self._drive_rx(frame=seg2)
        self.assertEqual(
            len(inline_tx_2),
            1,
            msg=(
                "The second back-to-back full-MSS segment MUST "
                "trigger an immediate inline ACK per RFC 1122 "
                '§4.2.3.2 ("in a stream of full-sized segments '
                "there SHOULD be an ACK for at least every second "
                f'segment"). Got {len(inline_tx_2)} TX frames.'
            ),
        )

        ack = self._parse_tx(inline_tx_2[0])
        self._assert_segment(
            ack,
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
            # of back-to-back segments still in the buffer.
            win=65535 - 2 * 1460,
        )

        # Both payloads delivered in order.
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload,
            msg=("Both back-to-back segments must be delivered to " "'_rx_buffer' in the order they arrived."),
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + 2 * 1460,
            msg="'_rcv_nxt' must equal PEER__ISS + 1 + 2*MSS after both segments.",
        )
        self.assertEqual(
            session._rcv_seq.una,
            session._rcv_seq.nxt,
            msg=(
                "After the inline 'every other segment' ACK fires, "
                "'_rcv_una' must equal '_rcv_nxt' - we have just "
                "acknowledged everything we received."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Receiving back-to-back data must not change session state.",
        )

    def test__data_transfer_recv__bare_ack_with_no_data_does_not_trigger_ack_loop(self) -> None:
        """
        Ensure a bare ACK from the peer (no SYN, no FIN, no
        RST, no data) acknowledging an already-acknowledged
        byte is processed quietly: no inline TX, sequence
        variables unchanged, no ACK fires after the delayed-
        ACK interval — sending an ACK in response to a pure
        ACK would create an infinite loop on the wire.

        Reference: RFC 9293 §3.4 (cumulative-acknowledgement semantics).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt
        rcv_una_before = session._rcv_seq.una

        # Peer sends a bare ACK acknowledging our SYN once more.
        bare_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        inline_tx = self._drive_rx(frame=bare_ack)

        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "A bare ACK with no data must not elicit any inline "
                "outbound segment - sending an ACK in response to a "
                "pure ACK would create an infinite loop on the wire."
            ),
        )

        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg="A bare ACK carries no data; '_rx_buffer' must remain empty.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_before,
            msg=(
                "'_rcv_nxt' must NOT advance on a bare ACK with no " "data - there is no new sequence space to consume."
            ),
        )
        self.assertEqual(
            session._rcv_seq.una,
            rcv_una_before,
            msg="'_rcv_una' must be unchanged after a bare ACK that elicits no outbound ACK.",
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=(
                "'_snd_una' must be unchanged - the bare ACK "
                "re-acknowledges what was already acknowledged "
                "during the handshake."
            ),
        )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_before,
            msg="'_snd_nxt' must be unchanged - we have transmitted nothing since the handshake.",
        )

        # Drive past the delayed-ACK interval. Because 'rcv_nxt ==
        # rcv_una', the timer must NOT fire an ACK.
        late_tx = self._advance(ms=TCP__DELAYED_ACK__DELAY_MS * 2)
        self.assertEqual(
            late_tx,
            [],
            msg=(
                f"After {TCP__DELAYED_ACK__DELAY_MS * 2} ms of virtual time "
                "with no new data received, the delayed-ACK timer "
                "must not fire any ACK - 'rcv_nxt == rcv_una' so "
                "there is nothing to acknowledge."
            ),
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="A bare ACK must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_recv__ack_beyond_snd_max_triggers_empty_ack_reply(self) -> None:
        """
        Ensure a segment whose acknowledgement number is
        beyond SND.MAX (acknowledges data we have never
        sent) is rejected with an empty-ACK reply carrying
        our current SND.NXT / RCV.NXT; SND.UNA, SND.NXT,
        RCV.NXT are unchanged and state stays ESTABLISHED.

        Reference: RFC 9293 §3.10.7.4 (step 5 ACK acknowledging unsent data).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        # Peer sends a segment with an ACK that acknowledges data we
        # have never sent. Pick 0xDEAD as the offset so the bogus
        # ack value is visually unambiguous in failure output.
        bogus_ack_offset = 0xDEAD
        bogus_ack_segment = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + bogus_ack_offset,
            flags=("ACK",),
            win=PEER__WIN,
        )

        inline_tx = self._drive_rx(frame=bogus_ack_segment)

        self.assertEqual(
            len(inline_tx),
            1,
            msg=(
                "An incoming segment with ACK > SND.MAX must "
                "elicit exactly one inline empty-ACK reply. "
                f"Got {len(inline_tx)} TX frames."
            ),
        )

        ack_reply = self._parse_tx(inline_tx[0])
        self._assert_segment(
            ack_reply,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
            mss=None,
            wscale=None,
            win=65535,
        )

        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=("An ACK that exceeds SND.MAX must NOT advance " "'_snd_una' - it acknowledged data we never sent."),
        )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_before,
            msg="'_snd_nxt' must be unchanged - we have transmitted nothing new.",
        )
        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_before,
            msg=(
                "'_rcv_nxt' must be unchanged - the offending "
                "segment carried no data, and any data on an "
                "unacceptable segment is discarded."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="An unacceptable-ACK segment must not transition the session out of ESTABLISHED.",
        )
