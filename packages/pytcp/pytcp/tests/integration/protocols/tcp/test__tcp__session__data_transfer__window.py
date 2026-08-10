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
This module contains integration tests for the TCP window-management
machinery in the 'TcpSession' state machine, covering both the
receive-side advertisement of '_rcv_wnd' and the send-side handling
of the peer's advertised window (including the WSCALE-when-not-
advertised rule of RFC 7323 §2.2 and the mid-flight window-shrink
robustness rule of RFC 9293 §3.8.6).

Reference RFCs:
    RFC 9293 §3.8.6      Window management (advertised window
                         semantics, robustness against window shrink)
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 1122 §4.2.2.16   TCP MUST be robust against shrinking windows
    RFC 7323 §2.2        WSCALE option only when offered bilaterally

pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__window.py

ver 3.0.10
"""

from net_addr import Ip4Address
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

# Initial value 'TcpSession' assigns to '_rcv_wnd' (and thus the
# advertised window in our outbound segments before any data has
# been received).
LOCAL__INITIAL_RCV_WND: int = 65535


class TestTcpDataTransfer__Window(TcpTestCase):
    """
    Integration tests for the TCP window-management machinery, both
    the receive-side advertised window we put on outbound segments
    and the send-side interpretation of the peer's advertised window.
    """

    def test__window__advertised_rcv_wnd_shrinks_as_rx_buffer_fills(self) -> None:
        """
        Ensure the advertised receive window in our outbound
        segments shrinks as inbound data accumulates in
        '_rx_buffer' but is not yet consumed by recv().
        The advertised window must reflect remaining buffer
        capacity so the peer's flow-control loop has
        something to throttle against.

        Reference: RFC 9293 §3.8.4 (advertised window reflects available buffer).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Setup precondition: window starts at the constant initial
        # value, buffer is empty.
        self.assertEqual(
            session._rcv_wnd,
            LOCAL__INITIAL_RCV_WND,
            msg=(
                "Setup precondition: '_rcv_wnd' starts at the "
                f"initial value {LOCAL__INITIAL_RCV_WND} after the "
                "handshake completes."
            ),
        )
        self.assertEqual(
            len(session._rx_buffer),
            0,
            msg="Setup precondition: '_rx_buffer' is empty before any peer data arrives.",
        )

        # SEGMENT #1: 1460 bytes of 'X' at PEER__ISS + 1. Per the
        # delayed-ACK every-other-segment rule, this segment alone
        # only arms the timer - no inline ACK fires.
        seg1_payload = b"X" * 1460
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=seg1_payload,
        )
        seg1_inline = self._drive_rx(frame=seg1)
        self.assertEqual(
            seg1_inline,
            [],
            msg=(
                "Setup precondition: SEGMENT #1 must not produce an "
                "inline ACK - the delayed-ACK every-other-segment "
                "rule (RFC 1122 §4.2.3.2) arms the timer for the "
                "first pending segment and waits for the second."
            ),
        )

        # SEGMENT #2: 1460 bytes of 'Y' at PEER__ISS + 1 + 1460.
        # Two pending segments triggers the inline ACK.
        seg2_payload = b"Y" * 1460
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + len(seg1_payload),
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=seg2_payload,
        )
        seg2_inline = self._drive_rx(frame=seg2)
        self.assertEqual(
            len(seg2_inline),
            1,
            msg=(
                "Setup precondition: SEGMENT #2 must produce exactly "
                "one inline ACK per the delayed-ACK every-other-segment "
                "rule (RFC 1122 §4.2.3.2)."
            ),
        )

        ack = self._parse_tx(seg2_inline[0])

        # Sanity: the ACK acknowledges both segments cumulatively.
        self.assertEqual(
            ack.ack,
            PEER__ISS + 1 + len(seg1_payload) + len(seg2_payload),
            msg=(
                "The inline ACK must acknowledge both segments "
                "cumulatively, not just SEGMENT #2 alone - "
                "delayed-ACK accumulates and emits a single ACK "
                "covering all pending bytes."
            ),
        )

        # The spec encoding: advertised window reflects the 2920
        # bytes now sitting in '_rx_buffer'. RFC 9293 §3.8.6.
        expected_window = LOCAL__INITIAL_RCV_WND - (len(seg1_payload) + len(seg2_payload))
        self.assertEqual(
            ack.win,
            expected_window,
            msg=(
                f"Advertised receive window must shrink to "
                f"{expected_window} ({LOCAL__INITIAL_RCV_WND} - 2920 "
                "bytes in '_rx_buffer') per RFC 9293 §3.8.6 - the "
                "window indicates remaining capacity, and a "
                f"constant {LOCAL__INITIAL_RCV_WND} advertisement "
                "breaks the peer's flow-control loop. A slow "
                "application would never produce backpressure and "
                "the buffer would grow unbounded."
            ),
        )

        # State assertions: data made it into the buffer in order;
        # session still healthy.
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload,
            msg=(
                "'_rx_buffer' must hold both segments in arrival "
                "order - the delayed-ACK path enqueues bytes before "
                "deciding whether to emit the ACK."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED through the data-transfer.",
        )

    def test__window__peer_wscale_ignored_when_we_did_not_advertise(self) -> None:
        """
        Ensure a WSCALE option present on the peer's SYN+ACK
        is ignored when we did not offer WSCALE on our
        outbound SYN. '_snd_wsc' remains at 0 and peer's
        advertised window is applied raw (no shift) to
        '_snd_wnd'.

        Reference: RFC 7323 §2 (WSCALE bilateral negotiation).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        # PyTCP defaults to advertising WSCALE on outbound SYN
        # (RFC 7323 §2.2 / §2.3 throughput-friendly default).
        # This test deliberately exercises the asymmetric-non-offer
        # path, so opt out of advertising via the
        # '_advertise_wscale' flag before driving CONNECT.
        session._advertise.wscale = False
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Initial SYN fires on the first tick. Inspect it to confirm
        # we did NOT advertise WSCALE.
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self.assertIsNone(
            syn_probe.wscale,
            msg=(
                "Setup precondition: our outbound SYN must carry "
                "NO WSCALE option (RFC 7323 §2.2's 'did not offer' "
                "encoding). PyTCP's TX path emits the option only "
                "when 'tcp__wscale' is truthy "
                "(packet_handler__tcp__tx.py line 130), so passing "
                "'tcp__wscale=0' from '_transmit_packet' line 558 "
                "produces the option-absent wire form, and this "
                "test's bilateral-non-offer rule depends on it "
                "staying that way."
            ),
        )

        # Peer's SYN+ACK advertises WSCALE = 7 (a deliberate offer)
        # and a deliberately small raw window so the bug's effect
        # is observable.
        peer_raw_win = 1024
        peer_wscale = 7
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=peer_raw_win,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )

        # The spec encoding: peer's WSCALE was ignored; '_snd_wsc'
        # remains 0; '_snd_wnd' is the raw advertised window with
        # no left shift.
        self.assertEqual(
            session._win.snd_wsc,
            0,
            msg=(
                "Peer's WSCALE option (=7) on the SYN+ACK MUST be "
                "ignored because we did not offer WSCALE on our "
                "outbound SYN (RFC 7323 §2.2). '_snd_wsc' must "
                "remain at the no-scaling default of 0."
            ),
        )
        self.assertEqual(
            session._win.snd_wnd,
            peer_raw_win,
            msg=(
                f"'_snd_wnd' must equal the raw advertised window "
                f"({peer_raw_win}) with no left shift - the peer's "
                f"WSCALE = {peer_wscale} was ignored per RFC 7323 "
                f"§2.2 because the offer was unilateral. Applying "
                f"the shift would yield {peer_raw_win << peer_wscale}, "
                "wildly inflating the send window and permitting "
                "transmission past the peer's actual receive "
                "capacity."
            ),
        )

    def test__window__no_spurious_emissions_when_peer_shrink_makes_usable_window_negative(self) -> None:
        """
        Ensure that when the peer shrinks the advertised
        window mid-flight such that the usable window
        (SND.UNA + SND.WND - SND.NXT) goes negative, the
        session does not emit any spurious segments while
        waiting for the peer to reopen the window or for RTO
        to fire.

        Reference: RFC 1122 §4.2.2.16 (TCP MUST be robust against shrinking windows).
        """

        peer_initial_win = 4380  # 3 * MSS
        peer_shrunk_win = 1460  # 1 * MSS

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Override the handshake-installed send-window state so the
        # arithmetic for the shrink is deterministic and small enough
        # to assert against. The handshake set '_snd_wnd' from the
        # peer's SYN+ACK 'win' (= PEER__WIN = 64240) and '_snd_ewn'
        # to MSS; we want both at the 3-MSS pre-shrink value.
        session._win.snd_wnd = peer_initial_win
        session._cc.snd_ewn = peer_initial_win

        # Application sends 3 * MSS. All three segments fire on the
        # next tick. SND.NXT advances to LOCAL__ISS + 1 + 4380.
        payload_a = b"A" * 1460
        payload_b = b"B" * 1460
        payload_c = b"C" * 1460
        session.send(data=payload_a + payload_b + payload_c)

        # '_transmit_data' emits at most one segment per timer tick,
        # so we drain three MSS over three ticks.
        initial_tx = self._advance(ms=3)
        self.assertEqual(
            len(initial_tx),
            3,
            msg=(
                "Setup precondition: with '_snd_ewn = 4380' (3 MSS) "
                "and 4380 bytes queued, three full-MSS segments must "
                "fire across three timer ticks (one per tick)."
            ),
        )

        snd_nxt_pre_shrink = session._snd_seq.nxt
        self.assertEqual(
            snd_nxt_pre_shrink,
            LOCAL__ISS + 1 + 4380,
            msg=(
                "Setup precondition: 'SND.NXT' must have advanced past "
                "the three transmitted segments to LOCAL__ISS + 1 + 4380."
            ),
        )

        # Peer ACKs the FIRST segment AND shrinks the window to 1 MSS.
        # After processing this ACK, the right edge sits at
        # SND.UNA + SND.WND = LOCAL__ISS + 1 + 1460 + 1460 =
        # LOCAL__ISS + 1 + 2920, with two segments (B and C) entirely
        # past the new edge.
        peer_shrink_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload_a),
            flags=("ACK",),
            win=peer_shrunk_win,
        )
        self._drive_rx(frame=peer_shrink_ack)

        # Verify the shrink took effect on the session's send-side
        # state.
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1 + len(payload_a),
            msg="The shrink ACK must advance 'SND.UNA' past payload_a.",
        )
        self.assertEqual(
            session._win.snd_wnd,
            peer_shrunk_win,
            msg=(
                "The shrink ACK's 'win' field must update 'SND.WND' "
                f"to the new {peer_shrunk_win}-byte advertised value."
            ),
        )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_pre_shrink,
            msg=(
                "The shrink ACK is purely informational about peer's "
                "buffer; it must not move 'SND.NXT' (which still "
                "points at the original 3-segment frontier)."
            ),
        )

        # Application writes another MSS-worth of data after the
        # shrink. These bytes go into '_tx_buffer' but the new
        # SEQ would be LOCAL__ISS + 1 + 4380 - already 1460 bytes
        # past the new right edge.
        post_shrink_payload = b"D" * 1460
        session.send(data=post_shrink_payload)

        # Advance 10 ms. No timer should fire any segment in this
        # window (see scenario docstring for the per-timer breakdown);
        # spec-compliant behaviour is silence. Wrap in try / except so
        # the current code's invariant-assertion crash inside
        # '_transmit_data' surfaces as a clean unittest failure naming
        # the RFC clause rather than as an opaque traceback.
        try:
            silent_window_tx = self._advance(ms=10)
        except AssertionError as exc:  # pragma: no cover - bug path
            self.fail(
                f"Window-shrink robustness: '_transmit_data' crashed "
                f"with AssertionError({exc!s}) on the post-shrink "
                "tick. RFC 9293 §3.8.6 / RFC 1122 §4.2.2.16 require "
                "the sender to be robust against peer window "
                "shrinking, including the case where the new right "
                "edge falls below previously transmitted segments. "
                "The current invariant assertion at line 618 of "
                "tcp__session.py rejects this legal RFC scenario."
            )

        self.assertEqual(
            silent_window_tx,
            [],
            msg=(
                "After a window shrink that pushes the usable window "
                "negative and an application 'send()' that cannot fit, "
                "the wire MUST stay silent until either the peer "
                "reopens the window or RTO fires. RFC 9293 §3.8.6's "
                "robustness clause requires that a sender absorb the "
                "shrink without generating spurious traffic. Got "
                f"{len(silent_window_tx)} unexpected outbound frame(s) "
                "in the 10 ms post-shrink window - typically empty "
                "bare ACKs from '_transmit_data's negative-slice "
                "fall-through."
            ),
        )

        # Sanity: state and frontier unchanged.
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_pre_shrink,
            msg=(
                "'SND.NXT' must not advance during the silent post-shrink "
                "window - no new data can fit and no retransmits are due."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED through the shrink and silent window.",
        )

    def test__window__sub_mss_available_window_is_advertised_as_zero_per_rfc_1122_4_2_3_3(self) -> None:
        """
        Ensure that when the receiver-side available window
        drops below one MSS, we advertise a window of zero
        rather than a small positive value that would invite
        the peer to send a sub-MSS segment.

        Reference: RFC 1122 §4.2.3.3 (receiver SWS avoidance).
        """

        # Drive a custom handshake where peer offers WSCALE so the
        # bilateral negotiation completes and '_rcv_wsc' stays at
        # its default 7 (the file's '_drive_handshake_to_established'
        # does not include WSCALE on peer's SYN+ACK).
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=7,
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertIs(session.state, FsmState.ESTABLISHED)
        self.assertEqual(
            session._win.rcv_wsc,
            7,
            msg="Setup precondition: bilateral WSCALE must yield '_rcv_wsc = 7'.",
        )

        # Pre-fill '_rx_buffer' so the available window is sub-MSS.
        # '_rcv_wnd' is a property: 'max(0, _rcv_wnd_max - len(_rx_buffer))'.
        target_available = 535  # sub-MSS (< 1460)
        prefill_count = session._win.rcv_wnd_max - target_available
        with session._lock__rx_buffer:
            session._rx_buffer.extend(b"\x00" * prefill_count)
        self.assertEqual(
            session._rcv_wnd,
            target_available,
            msg=f"Setup precondition: '_rcv_wnd' must be {target_available} after pre-fill.",
        )

        # Peer sends 1 byte to arm a delayed-ACK. Drain past
        # 'TCP__DELAYED_ACK__DELAY_MS' so the timer-driven ACK fires.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X",
        )
        self._drive_rx(frame=peer_data)
        delayed_ack_tx = self._advance(ms=200)

        self.assertEqual(
            len(delayed_ack_tx),
            1,
            msg="Setup precondition: the delayed ACK must fire on the next tick after TCP__DELAYED_ACK__DELAY_MS.",
        )
        ack_probe = self._parse_tx(delayed_ack_tx[0])
        effective_window = ack_probe.win << session._win.rcv_wsc
        self.assertTrue(
            effective_window == 0 or effective_window >= session._win.rcv_mss,
            msg=(
                f"RFC 1122 §4.2.3.3 receiver SWS avoidance: "
                f"the advertised window's effective byte count "
                f"({effective_window} = {ack_probe.win} << {session._win.rcv_wsc}) "
                f"MUST be either 0 or >= MSS ({session._win.rcv_mss}). "
                f"Today PyTCP advertises a small positive window "
                f"({ack_probe.win}) representing {effective_window} "
                f"effective bytes - sub-MSS."
            ),
        )

    def test__window__peer_window_update_via_dup_ack_shape_updates_snd_wnd(self) -> None:
        """
        Ensure that a peer ACK whose wire shape matches the
        dup-ACK pattern (seq == RCV.NXT, ack == SND.UNA, no
        data) but carries a different window value than
        peer's previously-advertised window is treated as a
        window-update segment, not a duplicate ACK. SND.WND
        is updated to the new value and the dup-ACK counter
        does not advance.

        Reference: RFC 9293 §3.10.7.4 (window update on SND.UNA <= SEG.ACK <= SND.NXT).
        Reference: RFC 5681 §2 (dup-ACK definition excludes wnd-update segments).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self.assertEqual(
            session._win.snd_wnd,
            PEER__WIN,
            msg="Setup precondition: post-handshake SND.WND must equal peer's SYN+ACK win.",
        )

        new_win = 20000
        # Sanity: new_win must differ from PEER__WIN, otherwise the
        # test would be vacuous.
        self.assertNotEqual(
            new_win,
            PEER__WIN,
            msg="Test fixture must use a NEW window value distinct from peer's SYN+ACK win.",
        )

        peer_wnd_update = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=new_win,
        )
        self._drive_rx(frame=peer_wnd_update)

        self.assertEqual(
            session._win.snd_wnd,
            new_win,
            msg=(
                "An ACK whose wire shape matches the dup-ACK "
                "pattern but carries a NEW window value MUST "
                f"update SND.WND. Got '_snd_wnd' = "
                f"{session._win.snd_wnd}, expected {new_win}."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="A wnd-update must not transition the session out of ESTABLISHED.",
        )

    def test__window__three_wnd_updates_must_not_trigger_spurious_fast_retransmit(self) -> None:
        """
        Ensure that three consecutive ACKs with the dup-ACK wire
        shape ('seq == RCV.NXT, ack == SND.UNA, no data') but
        each carrying a DIFFERENT window value do not
        trigger fast-retransmit. Window-changing segments
        are not duplicates per the dup-ACK definition; they
        do not contribute to the fast-retransmit threshold.

        Reference: RFC 5681 §3.2 (fast retransmit on third dup-ACK).
        Reference: RFC 5681 §2 (dup-ACK definition excludes wnd-update segments).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Bypass slow-start so the data segment fires immediately
        # and SND.MAX advances past SND.UNA - giving fast-retransmit
        # something to fire on.
        session._cc.snd_ewn = PEER__WIN

        session.send(data=b"X" * 1460)
        self._advance(ms=1)
        self.assertEqual(
            session._snd_seq.max,
            LOCAL__ISS + 1 + 1460,
            msg=("Setup precondition: SND.MAX must have advanced past SND.UNA " "after the initial data send."),
        )
        # Clear handshake + initial-data residue so 'self._frames_tx'
        # below contains only any spurious retransmits.
        self._frames_tx.clear()

        # Peer sends three wnd-update ACKs at the same ack value
        # (= SND.UNA, since peer hasn't ACKed our data yet) but with
        # DIFFERENT window values - per RFC 5681 §2(e) these are NOT
        # duplicates.
        for new_win in (10000, 20000, 30000):
            wnd_update = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=new_win,
            )
            self._drive_rx(frame=wnd_update)

        # Advance a timer tick so any pending fast-retransmit
        # ('_retransmit_packet_request' rewinds SND.NXT but the
        # actual transmission happens on the next '_transmit_data'
        # call, which fires from the timer branch) emits.
        self._advance(ms=1)

        retransmits = [self._parse_tx(frame) for frame in self._frames_tx if len(self._parse_tx(frame).payload) > 0]
        self.assertEqual(
            retransmits,
            [],
            msg=(
                "Three peer ACKs with the dup-ACK wire shape "
                "but DIFFERENT window values are wnd-updates, "
                "not duplicates. They MUST NOT trigger fast-"
                f"retransmit. Got {len(retransmits)} spurious "
                "retransmit(s)."
            ),
        )
        self.assertEqual(
            session._cc.recovery_point,
            0,
            msg=(
                "Three peer wnd-update ACKs MUST NOT enter "
                "fast-retransmit recovery. Got "
                f"'_recovery_point' = {session._cc.recovery_point:#x}."
            ),
        )


class TestTcpDataTransfer__ReceiverSWS(TcpTestCase):
    """
    Integration tests for RFC 9293 §3.8.6.2 + RFC 1122
    §4.2.2.16 receiver-side Silly Window Syndrome avoidance:

      * The advertised right edge ('rcv_nxt + rcv_wnd') is
        non-decreasing across successive ACKs (modulo the
        zero-window case where the floor temporarily collapses
        the right edge to 'rcv_nxt'; peer treats that as the
        special persist-probe trigger).

      * When the receive buffer drains across the SWS-floor
        (1 MSS), the window REOPENS by advertising the FULL
        post-drain availability in a single step, not by
        small per-byte advances.

    Existing tests pin the basic shrink behavior
    ('advertised_rcv_wnd_shrinks_as_rx_buffer_fills') and the
    sub-MSS-floor ('sub_mss_available_window_is_advertised_as_zero
    _per_rfc_1122_4_2_3_3'). These tests cover the multi-ACK
    invariants those don't.
    """

    def test__sws__right_edge_non_decreasing_across_successive_acks(self) -> None:
        """
        Ensure the advertised right edge (RCV.NXT + RCV.WND)
        in our outbound ACKs is non-decreasing across
        successive segments arriving without app reads. As
        RCV.NXT advances by N bytes, RCV.WND shrinks by
        exactly N so the right edge stays constant.

        Reference: RFC 1122 §4.2.2.16 (TCP MUST be robust against shrinking windows).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Initial right edge: rcv_nxt + _rcv_wnd_max.
        initial_right_edge = session._rcv_seq.nxt + session._win.rcv_wnd_max

        # Drive 8 back-to-back full-MSS segments with no app reads.
        # Each pair of segments fires one inline cumulative ACK
        # via the every-other-segment rule.
        right_edges: list[int] = [initial_right_edge]
        for i in range(4):
            seq_a = PEER__ISS + 1 + (i * 2) * PEER__MSS
            seq_b = seq_a + PEER__MSS
            seg_a = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=seq_a,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                payload=b"X" * PEER__MSS,
            )
            seg_b = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=seq_b,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                payload=b"Y" * PEER__MSS,
            )
            self._drive_rx(frame=seg_a)
            tx_after_b = self._drive_rx(frame=seg_b)
            for frame in tx_after_b:
                probe = self._parse_tx(frame)
                if "ACK" in probe.flags and not probe.payload:
                    right_edges.append(probe.ack + (probe.win << session._win.rcv_wsc))

        for i in range(1, len(right_edges)):
            self.assertGreaterEqual(
                right_edges[i],
                right_edges[i - 1],
                msg=(
                    "Advertised right edge MUST be non-decreasing "
                    "across successive ACKs. Got "
                    f"right_edges={right_edges}; element {i} "
                    f"({right_edges[i]:#x}) is less than element "
                    f"{i - 1} ({right_edges[i - 1]:#x})."
                ),
            )

    def test__sws__window_reopens_at_full_size_after_drain_across_floor(self) -> None:
        """
        Ensure that when the buffer drains from sub-MSS
        (advertised window = 0) to above-MSS, the next
        outbound ACK advertises the full current available
        space, not a small fraction.

        Reference: RFC 1122 §4.2.3.3 (receiver SWS avoidance).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Fill buffer to within < 1 MSS of capacity so the SWS
        # floor advertises 0.
        prefill_count = session._win.rcv_wnd_max - 100  # leaves 100 bytes free, < MSS
        session._rx_buffer.extend(b"P" * prefill_count)
        # Manually advance rcv_nxt so the rx buffer occupancy
        # is consistent (peer's seq view).
        session._rcv_seq.nxt = (PEER__ISS + 1 + prefill_count) & 0xFFFF_FFFF

        # Trigger an outbound ACK to observe the floor.
        seg = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_seq.nxt,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"Z" * 50,  # small-enough to fit in the 100-byte free
        )
        # Drive a second small segment to elicit an inline ACK
        # via every-other-segment.
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_seq.nxt + 50,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"Z" * 50,
        )
        self._drive_rx(frame=seg)
        floor_tx = self._drive_rx(frame=seg2)
        floor_acks = [self._parse_tx(f) for f in floor_tx if not self._parse_tx(f).payload]
        self.assertGreaterEqual(
            len(floor_acks),
            1,
            msg="Setup invariant: every-other-segment must elicit an inline ACK.",
        )
        floor_ack = floor_acks[0]
        self.assertEqual(
            floor_ack.win,
            0,
            msg=(
                f"Setup invariant: with free buffer < MSS, the SWS "
                f"floor MUST advertise win=0. Got win={floor_ack.win}."
            ),
        )

        # Drain the buffer well past one MSS via recv() so the
        # window can reopen.
        drained = session._rx_buffer[: 2 * PEER__MSS]
        del session._rx_buffer[: 2 * PEER__MSS]
        assert len(drained) == 2 * PEER__MSS

        # Force a fresh outbound ACK by driving another peer
        # segment so we observe the reopened window.
        seg3 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_seq.nxt + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"W" * 1,
        )
        seg4 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_seq.nxt + 101,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"W" * 1,
        )
        self._drive_rx(frame=seg3)
        reopen_tx = self._drive_rx(frame=seg4)
        reopen_acks = [self._parse_tx(f) for f in reopen_tx if not self._parse_tx(f).payload]
        self.assertGreaterEqual(
            len(reopen_acks),
            1,
            msg="Setup invariant: every-other-segment after drain must elicit an ACK.",
        )
        reopen_ack = reopen_acks[0]

        # The reopened window should reflect roughly 2*MSS of
        # drain (minus the ~100 bytes of new data we drove), so
        # the wire-level 'win' value should be meaningfully
        # above zero AND above one MSS (not a tiny advance).
        self.assertGreaterEqual(
            reopen_ack.win << session._win.rcv_wsc,
            PEER__MSS,
            msg=(
                f"RFC 9293 §3.8.6.2: when the buffer drains across "
                f"the SWS floor, the reopened window MUST be at "
                f"least one MSS ({PEER__MSS}). Got win="
                f"{reopen_ack.win} (post-shift "
                f"{reopen_ack.win << session._win.rcv_wsc})."
            ),
        )
