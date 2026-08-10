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
This module contains integration tests for the TCP fast-retransmit
machinery in the 'TcpSession' state machine, covering the duplicate-
ACK trigger threshold prescribed by RFC 5681 §3.2.

The tests in this file drive the session through the active-open
handshake to ESTABLISHED, transmit a single full-MSS data segment,
then feed the peer's duplicate ACKs one at a time through the real
RX path. Assertions cover both the count threshold ("third duplicate
ACK is the trigger") and the wire-level shape of the resulting fast
retransmit (same seq, same payload as the original, no peer ACK
required).

Reference RFCs:
    RFC 5681 §3.2        Fast Retransmit / Fast Recovery
    RFC 9293 §3.7.6      Loss recovery using duplicate ACK feedback
    RFC 6675             Conservative loss recovery (informational
                         backdrop; not asserted here)

pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__retransmit_dupack.py

ver 3.0.10
"""

from net_addr import Ip4Address
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


class TestTcpDataTransfer__RetransmitDupack(TcpTestCase):
    """
    Integration tests for the dup-ACK-triggered fast-retransmit
    threshold and the wire-level shape of the retransmit it produces.
    """

    def test__dupack__third_duplicate_ack_triggers_fast_retransmit(self) -> None:
        """
        Ensure the fast-retransmit algorithm fires only on
        the third duplicate ACK from the peer, not earlier,
        and the resulting retransmit reuses the original
        SEQ and payload byte-for-byte.

        Reference: RFC 5681 §3.2 (fast retransmit on third dup-ACK).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Original transmission on the next tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: the original data segment must fire on the first tick.",
        )
        initial_seg = self._parse_tx(initial_tx[0])
        self.assertEqual(
            initial_seg.seq,
            LOCAL__ISS + 1,
            msg="Setup precondition: the original segment must carry SEQ = ISS + 1.",
        )
        self.assertEqual(
            initial_seg.payload,
            payload,
            msg="Setup precondition: the original segment must carry the application's payload byte-for-byte.",
        )

        # Helper: build one dup-ACK frame (same shape every time).
        def dupack_frame() -> bytes:
            return build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )

        # DUP-ACK #1: counter = 1. Below the RFC threshold.
        dupack_1_inline = self._drive_rx(frame=dupack_frame())
        self.assertEqual(
            dupack_1_inline,
            [],
            msg=(
                "DUP-ACK #1 must not produce any inline TX - the "
                "fast-retransmit handler only sets internal state, "
                "the actual retransmit is timer-driven."
            ),
        )
        dupack_1_tick = self._advance(ms=1)
        self.assertEqual(
            dupack_1_tick,
            [],
            msg=(
                "After DUP-ACK #1 and one tick, NO retransmit may "
                "fire - we are at one dup-ACK out of the three RFC "
                "5681 §3.2 mandates as the trigger."
            ),
        )

        # DUP-ACK #2: counter = 2. Still below the RFC threshold.
        dupack_2_inline = self._drive_rx(frame=dupack_frame())
        self.assertEqual(
            dupack_2_inline,
            [],
            msg="DUP-ACK #2 must not produce any inline TX.",
        )
        dupack_2_tick = self._advance(ms=1)
        self.assertEqual(
            dupack_2_tick,
            [],
            msg=(
                "After DUP-ACK #2 and one tick, NO retransmit may "
                "fire - RFC 5681 §3.2 names the THIRD duplicate ACK "
                "as the trigger, not the second. A retransmit here "
                "indicates the dup-ACK counter threshold is set "
                "below the RFC value (current code uses '> 1' where "
                "'> 2' is required)."
            ),
        )

        # DUP-ACK #3: counter = 3. RFC trigger; one retransmit
        # MUST fire on the next tick.
        dupack_3_inline = self._drive_rx(frame=dupack_frame())
        self.assertEqual(
            dupack_3_inline,
            [],
            msg=(
                "DUP-ACK #3 must not produce inline TX - the handler "
                "resets SND.NXT to SND.UNA but the actual retransmit "
                "is emitted by the next timer-driven '_transmit_data' "
                "pass."
            ),
        )
        dupack_3_tick = self._advance(ms=1)
        self.assertEqual(
            len(dupack_3_tick),
            1,
            msg=(
                "After DUP-ACK #3 and one tick, exactly ONE "
                "retransmit must fire (RFC 5681 §3.2 fast retransmit) "
                "- the lost segment that the peer's three duplicate "
                "ACKs are signalling as missing."
            ),
        )
        retransmit_seg = self._parse_tx(dupack_3_tick[0])
        self.assertEqual(
            retransmit_seg.seq,
            LOCAL__ISS + 1,
            msg=(
                "The fast retransmit must reuse the original SEQ "
                f"({LOCAL__ISS + 1:#x}) per RFC 5681 §3.2 - it is "
                "the missing segment, not a fresh one."
            ),
        )
        self.assertEqual(
            retransmit_seg.payload,
            payload,
            msg=(
                "The fast retransmit must reuse the original payload "
                "byte-for-byte. A different payload would indicate "
                "either TX-buffer corruption or a post-original "
                "send() call leaking into the retransmit."
            ),
        )
        self.assertEqual(
            retransmit_seg.flags,
            frozenset({"PSH", "ACK"}),
            msg=(
                "The fast retransmit must carry the same flag set as "
                "the original segment: PSH (RFC 1122 §4.2.2.2 - last "
                "segment of the write) plus the always-on ACK "
                "piggyback."
            ),
        )

        # State assertions: peer never advanced our ack, session
        # remains alive throughout the dup-ACK sequence.
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg=(
                "'SND.UNA' must be unchanged - dup-ACKs by definition "
                "carry 'SEG.ACK == SND.UNA' and so do not advance "
                "the send sequence space."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="The session must remain ESTABLISHED through the full dup-ACK sequence.",
        )

    def test__dupack__data_bearing_same_ack_does_not_count_toward_threshold(self) -> None:
        """
        Ensure a peer segment carrying SEG.ACK == SND.UNA
        but also delivering new data does NOT count as a
        duplicate ACK for the fast-retransmit threshold;
        such segments are bidirectional traffic, not loss
        signals.

        Reference: RFC 5681 §3.2 (dup-ACK definition excludes data-bearing segments).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Original transmission on the next tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: the original data segment must fire on the first tick.",
        )

        # Three data-bearing segments at ack == SND.UNA, each
        # delivering 100 bytes of fresh in-order data.
        peer_data_chunk = b"Y" * 100
        for index in range(3):
            seg = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1 + index * len(peer_data_chunk),
                ack=LOCAL__ISS + 1,
                flags=("ACK", "PSH"),
                win=PEER__WIN,
                payload=peer_data_chunk,
            )
            inline = self._drive_rx(frame=seg)
            for frame in inline:
                probe = self._parse_tx(frame)
                self.assertNotEqual(
                    probe.payload,
                    payload,
                    msg=(
                        f"After data-bearing segment #{index + 1} at "
                        f"ack == SND.UNA, no retransmit of the original "
                        "data segment is permitted - the segment "
                        "carries data and so cannot count as a "
                        "duplicate ACK per RFC 5681 §3.2 footnote 4(b)."
                    ),
                )

        # The dup-ACK counter must NEVER have been touched.
        self.assertNotIn(
            LOCAL__ISS + 1,
            session._tx.retransmit_request_counter,
            msg=(
                "'_tx_retransmit_request_counter' must contain no "
                "entry for SND.UNA after three data-bearing same-ACK "
                "segments - the dup-ACK predicate excludes "
                "data-bearing segments per RFC 5681 §3.2."
            ),
        )

        # Post-tick: still no retransmit. The buggy '> 1' threshold
        # would only fire if the counter had been incremented; the
        # data-bearing exclusion prevents that, so the post-tick
        # clock is silent.
        post_tick_tx = self._advance(ms=1)
        for frame in post_tick_tx:
            probe = self._parse_tx(frame)
            self.assertNotEqual(
                probe.payload,
                payload,
                msg=(
                    "After three data-bearing segments and one tick, "
                    "no fast retransmit of the original data may fire - "
                    "data-bearing segments do not count toward the "
                    "RFC 5681 §3.2 threshold, so the dup-ACK counter "
                    "stayed at zero and there is nothing to retrigger."
                ),
            )

        # Receive-side state advanced by exactly 3 * 100 bytes.
        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + 3 * len(peer_data_chunk),
            msg=(
                "'RCV.NXT' must advance by the cumulative length of "
                "the three in-order data chunks - the segments were "
                "processed as normal receive, not silently dropped."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_data_chunk * 3,
            msg=(
                "'_rx_buffer' must hold the three data chunks in "
                "arrival order - the data-handling branch of the FSM "
                "queued them rather than the dup-ACK branch dropping "
                "them."
            ),
        )

        # Send-side state and FSM unchanged.
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg=(
                "'SND.UNA' must be unchanged - the peer's ACK never "
                "advanced and our outstanding data is still in flight."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED through the bidirectional exchange.",
        )

    def test__dupack__fast_retransmit_is_one_shot_per_loss_event(self) -> None:
        """
        Ensure the fast-retransmit algorithm fires exactly
        once per loss event: additional duplicate ACKs after
        the third do not cause the lost segment to be
        retransmitted again. Per-tick observation across 5
        dup-ACKs: 0, 0, 1, 0, 0 retransmits.

        Reference: RFC 5681 §3.2 (fast retransmit one-shot, dup-ACKs after threshold inflate cwnd).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Original transmission on the next tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: the original data segment must fire on the first tick.",
        )

        def dupack_frame() -> bytes:
            return build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )

        def count_retransmits(frames: list[bytes]) -> int:
            """
            Count outbound segments that look like a retransmit of
            our original data: SEQ = LOCAL__ISS + 1, payload equals
            the original. Anything else (delayed-ACK piggyback,
            etc.) is ignored.
            """

            count = 0
            for frame in frames:
                probe = self._parse_tx(frame)
                if probe.seq == LOCAL__ISS + 1 and probe.payload == payload:
                    count += 1
            return count

        # Per-tick expected retransmit counts. Index N corresponds
        # to "after dup-ACK #(N+1) and one tick".
        expected_per_tick = [0, 0, 1, 0, 0]
        observed_per_tick: list[int] = []

        for index in range(5):
            self._drive_rx(frame=dupack_frame())
            tick_tx = self._advance(ms=1)
            observed_per_tick.append(count_retransmits(tick_tx))

        # Per-tick assertions, surfaced one at a time so the failure
        # message points to exactly which dup-ACK observation
        # diverged from the RFC.
        for index, (expected, observed) in enumerate(zip(expected_per_tick, observed_per_tick), start=1):
            self.assertEqual(
                observed,
                expected,
                msg=(
                    f"After dup-ACK #{index} and one tick, expected "
                    f"{expected} retransmit(s) of the original payload "
                    f"but observed {observed}. RFC 5681 §3.2 mandates "
                    "the trigger on dup-ACK #3 only, with no "
                    "re-firing on subsequent dup-ACKs."
                ),
            )

        # Total across the full 5-dup-ACK sequence: exactly one
        # retransmit (the one-shot rule encoded as a single
        # cumulative invariant).
        self.assertEqual(
            sum(observed_per_tick),
            1,
            msg=(
                "Across the full 5-dup-ACK sequence, exactly ONE "
                "fast retransmit of the lost segment is permitted "
                f"(RFC 5681 §3.2 step 3). Observed "
                f"{sum(observed_per_tick)} retransmits at SEQ = "
                f"{LOCAL__ISS + 1:#x}."
            ),
        )

        # Send-side state and FSM unchanged across the sequence.
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg=(
                "'SND.UNA' must be unchanged - dup-ACKs by definition "
                "do not advance SND.UNA, so the send sequence space "
                "remains frozen at LOCAL__ISS + 1."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Session must remain ESTABLISHED across the full "
                "dup-ACK sequence - fast retransmit is a recovery "
                "mechanism within ESTABLISHED, not a state-changing "
                "event."
            ),
        )

    def test__dupack__rto_during_fast_retransmit_recovery_clears_recovery_point(self) -> None:
        """
        Ensure that when an RTO fires while inside a fast-
        retransmit recovery episode, the '_recovery_point'
        marker is cleared so subsequent dup-ACKs can re-enter
        recovery on a fresh loss event. RTO collapses cwnd to
        one SMSS and rewinds SND.NXT — the stale RecoveryPoint
        becomes meaningless.

        Reference: RFC 5681 §3.1 (RTO collapses cwnd, slow-start re-entry).
        Reference: RFC 6675 §5 (RecoveryPoint lifecycle).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        # Send 1 MSS and drain so the original segment is on the
        # wire and its RTO timer is armed.
        payload = b"X" * 1460
        session.send(data=payload)
        self._advance(ms=1)

        # Three dup-ACKs back-to-back. The third triggers fast-
        # retransmit.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        self.assertNotEqual(
            session._cc.recovery_point,
            0,
            msg=(
                "Setup precondition: the third dup-ACK MUST trigger "
                "fast-retransmit and set '_recovery_point' to a "
                "non-zero marker (the SND.MAX at recovery entry). "
                "Without this precondition the rest of the test is "
                "vacuous."
            ),
        )

        # Drain the fast-retransmit segment.
        self._advance(ms=1)

        # Wait long enough for the RTO timer on the retransmit to
        # fire. The retransmit re-armed the timer at 2000ms (one
        # back-off doubling); 3 seconds is comfortably past that.
        self._advance(ms=3000)

        self.assertEqual(
            session._cc.recovery_point,
            0,
            msg=(
                "After RTO fires, '_recovery_point' MUST be cleared "
                "to zero - RTO is a hard reset per RFC 5681 §3.1 and "
                "the old recovery marker (SND.MAX at fast-retransmit "
                "entry) is meaningless once SND.NXT has been rewound "
                "to SND.UNA. Today PyTCP leaves '_recovery_point' "
                "set; the next dup-ACK skips fast-retransmit via the "
                "one-shot guard at the top of "
                "'_retransmit_packet_request'. Fix: clear "
                "'self._cc.recovery_point = 0' inside "
                "'_retransmit_packet_timeout'."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Sanity: after one RTO retry the connection must "
                "still be in ESTABLISHED - TCP__RETRANSMIT__MAX_COUNT "
                "is 6, we have only used 2 retries (initial + fast-"
                "retransmit + 1 RTO)."
            ),
        )
        self.assertEqual(
            session._cc.snd_ewn,
            session._win.snd_mss,
            msg=(
                "Sanity: RTO MUST collapse '_snd_ewn' to one SMSS "
                "per RFC 5681 §3.1 (slow-start re-entry). If this "
                "assertion fails the RTO did not actually fire, "
                "and the '_recovery_point' assertion above is "
                "vacuous."
            ),
        )

    def test__dupack__peer_fin_during_fast_retransmit_recovery_clears_recovery_point(self) -> None:
        """
        Ensure that when peer's FIN arrives mid-recovery and
        the FSM transitions ESTABLISHED -> CLOSE_WAIT without
        the cumulative ACK advancing past the existing
        '_recovery_point' marker, the marker is cleared as
        part of leaving ESTABLISHED so post-FIN sends can
        re-enter recovery on a fresh loss.

        Reference: RFC 6675 §5 (RecoveryPoint lifecycle on state transition).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN
        mss = session._win.snd_mss

        # Send 4 MSS and drain so SND.MAX is well past SND.UNA.
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)
        self.assertEqual(
            session._snd_seq.max,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: all 4 MSS segments must drain.",
        )

        # Three dup-ACKs back-to-back. Third triggers fast-retransmit.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        self.assertNotEqual(
            session._cc.recovery_point,
            0,
            msg=(
                "Setup precondition: the third dup-ACK MUST trigger "
                "fast-retransmit and set '_recovery_point' to a "
                "non-zero marker."
            ),
        )
        recovery_point_at_entry = session._cc.recovery_point

        # Drain the fast-retransmit segment.
        self._advance(ms=1)

        # Peer sends FIN+ACK with the SAME cum-ACK = LOCAL__ISS+1
        # (no forward progress). State transitions to CLOSE_WAIT
        # WITHOUT SND.UNA advancing past '_recovery_point' - so
        # the natural 'le32(_recovery_point, _snd_una)' clearing
        # path inside '_process_ack_packet' does NOT fire.
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
            msg="Setup precondition: peer's FIN must transition session to CLOSE_WAIT.",
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg=(
                "Setup precondition: peer's FIN had cum-ACK = "
                "LOCAL__ISS + 1, so SND.UNA must NOT have advanced "
                "past '_recovery_point'. If this assertion fails "
                "the natural in-'_process_ack_packet' clearing "
                "fired and the test below is vacuous."
            ),
        )
        self.assertEqual(
            session._cc.recovery_point,
            0,
            msg=(
                "Leaving ESTABLISHED MUST clear '_recovery_point' "
                "to zero - the RFC 6675 §5 marker is meaningful "
                "only inside the ESTABLISHED loss-recovery loop. "
                f"Today the marker stays at {recovery_point_at_entry} "
                "(the stale SND.MAX from fast-retransmit entry); "
                "the next dup-ACK in CLOSE_WAIT or any state "
                "transitioned to from here would skip fast-"
                "retransmit via the one-shot guard. Fix: clear "
                "'self._cc.recovery_point = 0' in '_change_state' "
                "when leaving ESTABLISHED, or equivalently in the "
                "ESTABLISHED handlers' transitions out."
            ),
        )

    def test__dupack__limited_transmit_sends_new_segment_on_first_dup_ack(self) -> None:
        """
        Ensure the Limited Transmit behaviour: on the FIRST
        duplicate ACK (before fast-retransmit fires at the
        third), the sender MUST emit one previously-unsent
        segment from the TX buffer if the receiver window
        allows. Limited Transmit injects new segments into
        the pipe so a small-window flow (where there might
        not be three in-flight segments to generate three
        dup-ACKs) can still trigger fast retransmit on real
        loss.

        The Limited Transmit budget is 'cwnd + 2*SMSS' -
        two extra segments beyond cwnd, one per each of
        the first two dup-ACKs. After fast-retransmit
        fires (third dup-ACK), the regular fast-recovery
        path takes over.

        Reference: RFC 3042 §3 (Limited Transmit on first two dup-ACKs).
        Reference: RFC 5681 §3.2 (fast-recovery on third dup-ACK).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Pin cwnd to a small value so the queued data
        # exceeds it. With cwnd=4*SMSS we'll send 4
        # segments and have 4 more queued in '_tx_buffer'
        # for Limited Transmit to inject.
        session._cc.cwnd = 4 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)
        # Queue 8 segments worth of data; only 4 will fit
        # in cwnd.
        session.send(data=b"x" * (8 * PEER__MSS))
        for _ in range(4):
            self._advance(ms=1)
        snd_max_pre_dup = session._snd_seq.max
        self.assertEqual(
            (snd_max_pre_dup - LOCAL__ISS - 1) & 0xFFFF_FFFF,
            4 * PEER__MSS,
            msg="Setup precondition: 4 segments must be in flight before any dup-ACK.",
        )

        # First dup-ACK at SND.UNA. Limited Transmit should
        # fire one new segment from the queued tail of the
        # TX buffer.
        first_dup_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        first_lt_tx = self._drive_rx(frame=first_dup_ack)

        # Find a NEW segment whose seq starts at the
        # previous SND.MAX (the next-unsent byte before the
        # dup-ACK).
        new_segment = None
        for frame in first_lt_tx:
            probe = self._parse_tx(frame)
            if probe.seq == snd_max_pre_dup and len(probe.payload) > 0:
                new_segment = probe
                break

        self.assertIsNotNone(
            new_segment,
            msg=(
                "RFC 3042 §3: the first duplicate ACK MUST "
                "trigger a new segment transmission from the "
                "TX buffer (Limited Transmit). Today PyTCP's "
                "'_retransmit_packet_request' increments the "
                "dup-ACK counter and returns without sending "
                f"any new data. Got {len(first_lt_tx)} TX "
                "frames; none carrying a new segment at "
                f"seq={snd_max_pre_dup}."
            ),
        )
