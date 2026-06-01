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
This module contains integration tests for the TCP retransmit-on-
timeout (RTO) machinery in the 'TcpSession' state machine, covering
exponential back-off cadence per RFC 6298 §2 and the connection-
abort timeout per RFC 1122 §4.2.3.5 R2 / RFC 9293 §3.8.3.

The tests in this file drive a session through the active-open
handshake to ESTABLISHED, send a full-MSS data segment, then keep
the peer silent so the retransmit timer can drive its full cadence
of probes. Assertions cover both the wire shape of each retransmit
(same seq, same payload, ACK-only flags) and the count / timing of
transmissions across the full RTO window.

Reference RFCs:
    RFC 6298 §2          Computing TCP's Retransmission Timer
    RFC 9293 §3.8.3      User Timeout / connection abort
    RFC 1122 §4.2.3.5    R1 / R2 retransmission limits

pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__retransmit_timeout.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.session import TcpSession
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

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460


class TestTcpDataTransfer__RetransmitTimeout(TcpTestCase):
    """
    Integration tests for the RTO retransmit machinery: cadence,
    payload preservation, and connection-abort timing.
    """

    def test__retransmit_timeout__silent_peer_retransmits_per_rfc6298_cadence(self) -> None:
        """
        Ensure that when an in-flight data segment goes
        unacknowledged the retransmit timer fires with
        exponential back-off (initial RTO = 1 s, doubled per
        retry) and the connection stays alive past the R2
        floor of 100 s. By t = 60 s of peer silence the wire
        shows at least five retransmits, each reusing the
        original seq and payload byte-for-byte; state stays
        ESTABLISHED.

        Reference: RFC 6298 §2.1 (initial RTO = 1 second).
        Reference: RFC 6298 §5.5 (binary backoff).
        Reference: RFC 1122 §4.2.3.5 (R2 >= 100 s before connection abort).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Initial transmission on the next tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: initial data segment must fire on the first tick.",
        )
        initial_seg = self._parse_tx(initial_tx[0])
        self.assertEqual(
            initial_seg.payload,
            payload,
            msg="Initial segment payload must equal what 'send()' was called with.",
        )
        self.assertEqual(
            initial_seg.seq,
            LOCAL__ISS + 1,
            msg="Initial segment seq must equal SND.NXT post-handshake.",
        )

        # Drive 60 seconds of virtual time with the peer silent. The
        # captured TX list will hold the initial-plus-retransmits
        # cadence.
        retransmits = self._advance(ms=60_000)

        # Doubling cadence (1, 3, 7, 15, 31 s within 60 s);
        # the retransmit count must be at least 5.
        self.assertGreaterEqual(
            len(retransmits),
            5,
            msg=(
                f"Within 60 s of peer silence, the RFC 6298 doubling "
                f"cadence (1, 3, 7, 15, 31 s) must produce at least 5 "
                f"retransmits. Got {len(retransmits)} - check the "
                "exponential-back-off arithmetic and "
                "TCP__RETRANSMIT__MAX_COUNT."
            ),
        )

        # Each retransmit reuses the original SEQ and payload.
        for index, frame in enumerate(retransmits, start=1):
            probe = self._parse_tx(frame)
            self.assertEqual(
                probe.seq,
                initial_seg.seq,
                msg=(
                    f"Retransmit #{index} must reuse the original SEQ "
                    f"= 0x{initial_seg.seq:08x} per RFC 6298 §2 (same "
                    f"segment, not a fresh one). Got "
                    f"0x{probe.seq:08x}."
                ),
            )
            self.assertEqual(
                probe.payload,
                payload,
                msg=(
                    f"Retransmit #{index} must reuse the original "
                    f"payload byte-for-byte. Got "
                    f"{len(probe.payload)} bytes vs expected "
                    f"{len(payload)}."
                ),
            )
            self.assertEqual(
                probe.flags,
                frozenset({"PSH", "ACK"}),
                msg=(
                    f"Retransmit #{index} must carry the same flag set "
                    "as the original segment (PSH on the last segment "
                    "of the write, ACK piggyback)."
                ),
            )

        # Session remains alive past the R2 floor of 100 s. Within
        # the 60 s observation window, no abort is permissible.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "After 60 s of silence, the session must still be in "
                "ESTABLISHED - RFC 1122 §4.2.3.5 R2 requires the abort "
                "timeout to be at least 100 s, well past the 60 s "
                "observation window."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg=(
                "'_snd_una' must be unchanged - the peer has not ACK'd "
                "any of our data so the send sequence space remains "
                "frozen at the initial SND.NXT."
            ),
        )

    def test__retransmit_timeout__peer_ack_mid_back_off_clears_counters_and_grows_window(self) -> None:
        """
        Ensure that when a peer ACK arrives in the middle of
        the retransmit back-off window, the sender-side
        bookkeeping unwinds cleanly: the session-level
        retransmit timer is unregistered, SND.UNA advances,
        '_retransmit_count' resets to 0, '_snd_ewn' grows,
        and no spurious retransmits fire on subsequent ticks.

        Reference: RFC 6298 §5.2 (turn off retransmission timer when all data is acked).
        Reference: RFC 6298 §5.3 (restart timer on cum-ACK that advances SND.UNA).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Initial transmission.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: initial data segment must fire on the first tick.",
        )

        # Advance past the first retransmit boundary (RTO = 1 s after
        # initial). Within this window the first retransmit fires and
        # '_snd_ewn' collapses back to one MSS.
        retransmit_window_tx = self._advance(ms=1500)
        self.assertGreaterEqual(
            len(retransmit_window_tx),
            1,
            msg=(
                "Setup precondition: the first retransmit must fire "
                "within 1500 ms of the initial transmission "
                "(RTO = 1 s + tick latency)."
            ),
        )

        # Snapshot pre-ACK state.
        self.assertEqual(
            session._retransmit_count,
            1,
            msg=(
                "Pre-ACK precondition: '_retransmit_count' must be 1 "
                "after exactly one retransmit-timeout fire (the first "
                "RTO at 1 s after the initial transmission)."
            ),
        )
        self.assertIn(
            f"{session}-retransmit",
            self._pending_session_timers(session),
            msg=(
                "Pre-ACK precondition: the session-level retransmit "
                "timer must be re-armed (via 'back_off') after the "
                "first retransmit fired."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1,
            msg="Pre-ACK precondition: SND.UNA must still be at the initial ISS+1.",
        )
        snd_ewn_before_ack = session._cc.snd_ewn
        self.assertEqual(
            snd_ewn_before_ack,
            session._win.snd_mss,
            msg=(
                "Pre-ACK precondition: '_snd_ewn' must be back at one "
                "MSS after the retransmit-timeout reset collapsed it."
            ),
        )

        # Peer ACKs the data, covering both the initial transmit and
        # any retransmits.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertNotIn(
            f"{session}-retransmit",
            self._pending_session_timers(session),
            msg=(
                "RFC 6298 §5.2: a cum-ACK that drains all in-flight "
                "bytes MUST turn off the session-level retransmit "
                "timer."
            ),
        )
        self.assertEqual(
            session._retransmit_count,
            0,
            msg=(
                "Peer's progress ACK must reset the R2 abort counter - "
                "fresh evidence of liveness restores the connection's "
                "retransmit budget."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1 + len(payload),
            msg=("'SND.UNA' must advance past the acknowledged data " "after the peer ACK is processed."),
        )
        self.assertGreater(
            session._cc.snd_ewn,
            snd_ewn_before_ack,
            msg=(
                "'_snd_ewn' must grow on a successful ACK "
                "(slow-start-style doubling per "
                "'_process_ack_packet') - the retransmit-timeout "
                "reset had collapsed it back to one MSS."
            ),
        )
        self.assertEqual(
            len(session._tx.buffer),
            0,
            msg=("The TX buffer must be empty after the peer ACKs all " "outstanding data."),
        )

        # Advance an additional 10 s of virtual time. With the
        # session-level timer turned off and the TX buffer empty,
        # no spurious retransmit may fire.
        silent_window_tx = self._advance(ms=10_000)
        self.assertEqual(
            silent_window_tx,
            [],
            msg=(
                "After the peer ACK turns off the retransmit timer, "
                "NO further TX may fire on subsequent ticks - the TX "
                "buffer is empty and the timer is unregistered."
            ),
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="The peer ACK must leave the session in ESTABLISHED.",
        )

    def test__retransmit_timeout__fin_wait_1_timer_retransmits_fin_not_data(self) -> None:
        """
        Ensure that once a session has transitioned to
        FIN_WAIT_1, subsequent retransmit-timer expirations
        retransmit only the FIN segment — they do not
        re-send any data segments at sequence numbers that
        have already been acknowledged or that lie past the
        FIN.

        Reference: RFC 9293 §3.6 (FIN-WAIT-1 awaits ACK of our FIN).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Initial transmit.
        self._advance(ms=1)

        # Peer ACKs the data.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1 + len(payload),
            msg="Setup precondition: peer's ACK must have advanced SND.UNA past the data.",
        )
        self.assertEqual(
            len(session._tx.buffer),
            0,
            msg="Setup precondition: TX buffer must be empty after the data is acknowledged.",
        )

        # Application closes the connection.
        session.close()
        self.assertTrue(
            session._closing,
            msg="Setup precondition: 'close()' must set the '_closing' flag.",
        )

        # First tick after 'close()': state transitions to FIN_WAIT_1
        # because the TX buffer is empty. No segment fires on this tick.
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg=(
                "The ESTABLISHED -> FIN_WAIT_1 transition tick must "
                "not emit any segment (the FIN fires on the next tick "
                "via the FIN_WAIT_1 timer handler)."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "After the transition tick, state must be FIN_WAIT_1 "
                "('_closing AND not _tx_buffer' triggers the "
                "transition)."
            ),
        )

        # Second tick: FIN_WAIT_1's timer handler emits the FIN.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg=(
                "The first FIN_WAIT_1 timer tick must emit exactly one "
                "outbound FIN segment via '_transmit_data's "
                "FIN-retransmit block."
            ),
        )
        fin_seg = self._parse_tx(fin_tx[0])
        self.assertIn(
            "FIN",
            fin_seg.flags,
            msg="The first outbound segment in FIN_WAIT_1 must carry the FIN flag.",
        )
        self.assertEqual(
            fin_seg.payload,
            b"",
            msg="The FIN must carry no application payload.",
        )
        fin_seq = fin_seg.seq

        # Drive 60 s of virtual time with the peer silent. The FIN's
        # retransmit timer cycles through RFC 6298 doubling. Capture
        # all retransmits and verify each is a FIN, not data.
        retransmits = self._advance(ms=60_000)

        self.assertGreaterEqual(
            len(retransmits),
            4,
            msg=(
                "Within 60 s of peer silence, the RFC 6298 doubling "
                "cadence (1, 3, 7, 15, 31 s after the initial FIN) "
                f"must produce at least 4 FIN retransmits. Got "
                f"{len(retransmits)}."
            ),
        )

        for index, frame in enumerate(retransmits, start=1):
            probe = self._parse_tx(frame)
            self.assertIn(
                "FIN",
                probe.flags,
                msg=(
                    f"Retransmit #{index} in FIN_WAIT_1 must carry FIN "
                    "flag - retransmitting a data segment here would "
                    "reuse already-acknowledged SEQ space and violate "
                    "RFC 9293 §3.10.4."
                ),
            )
            self.assertEqual(
                probe.payload,
                b"",
                msg=(
                    f"Retransmit #{index} in FIN_WAIT_1 must carry no "
                    "payload - the FIN is a control segment, and any "
                    "data byte would risk re-sending data the peer "
                    "has already acknowledged."
                ),
            )
            self.assertEqual(
                probe.seq,
                fin_seq,
                msg=(
                    f"Retransmit #{index} in FIN_WAIT_1 must reuse the "
                    f"original FIN's SEQ ({fin_seq:#x}). A different "
                    "SEQ would indicate either data leakage from the "
                    "ESTABLISHED-state transmit block or post-FIN "
                    "sequence drift."
                ),
            )

        # Session must still be in FIN_WAIT_1 after 60 s - well
        # within the R2 floor.
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=("After 60 s of silent retransmits, the session must " "still be in FIN_WAIT_1 (R2 = 100 s minimum)."),
        )

    def test__retransmit_timeout__sub_mss_partial_segment_retransmits_despite_nagle(self) -> None:
        """
        Ensure that when an in-flight sub-MSS partial
        segment goes unacknowledged the RTO retransmits it
        on the timer boundary, despite Nagle's Minshall
        variant ordinarily deferring fresh partials while a
        previous partial is in flight. The retransmit
        machinery re-sends the earliest unacked segment
        regardless of segment size or Nagle state.

        Reference: RFC 6298 §5 (RTO-driven retransmission).
        Reference: RFC 1122 §4.2.3.4 (Nagle applies to fresh transmits, not retransmits).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Bypass slow-start so the partial fires on the first tick.
        session._cc.snd_ewn = PEER__WIN

        # Step 2: send a 100-byte sub-MSS partial.
        partial_payload = b"X" * 100
        session.send(data=partial_payload)
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: initial send must produce exactly one outbound segment.",
        )
        initial_probe = self._parse_tx(initial_tx[0])
        self._assert_segment(
            initial_probe,
            seq=LOCAL__ISS + 1,
            payload=partial_payload,
        )

        # Step 3: peer stays silent. Advance past the initial RTO.
        # 'TCP__RTO__INITIAL_MS' is 1000 ms (the initial
        # RTO); +1 ms past the boundary so the timer fires on
        # the boundary tick.
        retransmit_tx = self._advance(ms=TCP__RTO__INITIAL_MS + 1)
        retransmit_segments = [self._parse_tx(frame) for frame in retransmit_tx]

        # Step 4: the RTO MUST fire one retransmit. Today the
        # Nagle gate defers and zero retransmits emit.
        self.assertEqual(
            len(retransmit_segments),
            1,
            msg=(
                "After the RTO timer expires on a sub-MSS partial "
                "in flight, exactly one retransmit segment MUST be "
                "emitted carrying the same seq and payload as the "
                "original. Today '_transmit_data's Nagle gate "
                "(RFC 1122 §4.2.3.4 Minshall variant) treats the "
                "RTO retransmit identically to a fresh partial "
                "transmit, observes 'prev_partial_in_flight=True' "
                "(the partial we are retransmitting IS still in "
                "flight), and defers indefinitely. The retransmit "
                "counter never increments, R2 is never reached, "
                "and the connection is silently stuck. Affects "
                "every interactive workload that drops a sub-MSS "
                f"segment. Got: {retransmit_segments!r}"
            ),
        )
        self._assert_segment(
            retransmit_segments[0],
            seq=LOCAL__ISS + 1,
            payload=partial_payload,
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Session must remain ESTABLISHED through the RTO retransmit.",
        )

    def test__retransmit_timeout__rto_with_peer_zero_window_respects_flow_control(self) -> None:
        """
        Ensure that when an RTO fires while peer has
        advertised a 0-window, the retransmit path respects
        peer's flow-control: '_snd_ewn' collapses to 0
        (clamped to '_snd_wnd'); no MSS-sized data segment
        hits the wire. The persist machinery probes while the
        window is closed.

        Reference: RFC 9293 §3.8.6.1 (zero-window probing).
        Reference: RFC 1122 §4.2.2.16 (sender robust against shrinking windows).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Bypass slow-start so the initial send fires at full MSS.
        session._cc.snd_ewn = PEER__WIN

        # Step 2: send 100 bytes. One segment fires.
        payload = b"X" * 100
        session.send(data=payload)
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: initial send must produce one outbound segment.",
        )

        # Step 3: simulate peer's 0-window state. State-direct
        # because the ACK-only "ack==SND.UNA + win=0" frame would
        # be intercepted by ESTABLISHED's dup-ACK branch which
        # doesn't update '_snd_wnd'. This is equivalent to peer
        # having processed a fresh ACK that advances SND.UNA AND
        # advertises win=0.
        session._win.snd_wnd = 0
        session._cc.snd_ewn = 0

        # Step 4: advance past TCP__RTO__INITIAL_MS so the
        # RTO timer for the unacked segment fires.
        rto_tx = self._advance(ms=TCP__RTO__INITIAL_MS + 1)

        # Spec: post-RTO '_snd_ewn' must reflect peer's 0-window.
        self.assertEqual(
            session._cc.snd_ewn,
            0,
            msg=(
                "After RTO with peer's 0-window, '_snd_ewn' MUST "
                "be 0 (clamped to '_snd_wnd'). Today "
                "'_retransmit_packet_timeout' sets '_snd_ewn = "
                "self._win.snd_mss' unconditionally, ignoring peer's "
                "advertised window. Fix: clamp via "
                "'_snd_ewn = min(self._win.snd_mss, self._win.snd_wnd)'."
            ),
        )

        # Spec: no data-bearing segment fires; persist machinery
        # handles probing once the window is closed. (Persist
        # probes are 1-byte and may or may not fire depending on
        # exact timing; we assert no MSS-class data segment.)
        rto_segments = [self._parse_tx(frame) for frame in rto_tx]
        data_segments = [seg for seg in rto_segments if len(seg.payload) > 1]
        self.assertEqual(
            data_segments,
            [],
            msg=(
                "After RTO with peer's 0-window, NO data-bearing "
                "segment larger than 1 byte may be emitted; peer's "
                "advertised window forbids it. Got: "
                f"{data_segments!r}"
            ),
        )

    def test__retransmit_timeout__fin_retransmit_does_not_drift_tx_buffer_seq_mod(self) -> None:
        """
        Ensure that retransmitting the FIN segment after RTO
        leaves '_tx_buffer_seq_mod' unchanged across the
        entire retransmit cycle. The FIN consumes one byte
        of sequence space but no slot in the TX buffer; the
        retransmit walk-back must compensate for the phantom
        byte each cycle so the anchor remains aligned.

        Reference: RFC 9293 §3.4 (sequence-number arithmetic and TX-buffer alignment).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Empty TX buffer; close immediately.
        session.close()
        # First tick: ESTABLISHED -> FIN_WAIT_1 (no segment emitted).
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: empty-buffer close transitions to FIN_WAIT_1 on the first tick.",
        )
        # Second tick: FIN emitted by the FIN_WAIT_1 timer branch.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: the FIN_WAIT_1 timer tick after close() must emit exactly one FIN.",
        )
        original_fin = self._parse_tx(fin_tx[0])
        self.assertIn(
            "FIN",
            original_fin.flags,
            msg="Setup precondition: the segment emitted in step 2 must carry the FIN flag.",
        )

        # Snapshot the post-original-FIN anchor. This is the value
        # every subsequent retransmit MUST preserve.
        baseline_seq_mod = session._tx.seq_mod

        # Drive three RTO cycles with the peer silent. Cumulative
        # delays: 1 s, 1+2=3 s, 1+2+4=7 s. We advance a small
        # margin past each boundary so the timer fires.
        for cycle, cumulative_ms in enumerate((1_000, 3_000, 7_000), start=1):
            already_advanced_ms = (0, 1_000, 3_000)[cycle - 1]
            delta_ms = cumulative_ms - already_advanced_ms + 1
            retransmits = self._advance(ms=delta_ms)
            self.assertEqual(
                len(retransmits),
                1,
                msg=(
                    f"RTO cycle #{cycle}: the FIN_WAIT_1 retransmit "
                    f"machinery MUST emit exactly one FIN retransmit "
                    f"per cycle. Got {len(retransmits)}."
                ),
            )
            probe = self._parse_tx(retransmits[0])
            self.assertEqual(
                probe.seq,
                original_fin.seq,
                msg=(
                    f"RTO cycle #{cycle}: the FIN retransmit MUST "
                    f"reuse the original FIN's seq "
                    f"(0x{original_fin.seq:08x}). A different seq "
                    f"would indicate post-FIN sequence drift. "
                    f"Got 0x{probe.seq:08x}."
                ),
            )
            self.assertEqual(
                session._tx.seq_mod,
                baseline_seq_mod,
                msg=(
                    f"RTO cycle #{cycle}: '_tx_buffer_seq_mod' "
                    f"MUST equal its post-original-FIN value "
                    f"(0x{baseline_seq_mod:08x}). Got "
                    f"0x{session._tx.seq_mod:08x} (drift "
                    f"+{(session._tx.seq_mod - baseline_seq_mod) & 0xFFFFFFFF})."
                ),
            )


class TestTcpRfc6582Recover(TcpTestCase):
    """
    RFC 6582 §3.2 step 4 'recover' marker: post-RTO, the highest
    SND.MAX transmitted is recorded into '_recover_seq' so the
    subsequent post-RTO retransmit storm's dup-ACK echoes cannot
    spuriously re-trigger fast retransmit before the cum-ACK
    advances past the marker.
    """

    def _drive_to_established(self, *, iss: int, peer_iss: int) -> TcpSession:
        """Drive active-open handshake."""

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
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__rfc6582__recover_seq_initialised_zero(self) -> None:
        """
        Ensure '_recover_seq' starts at the 0 sentinel so a fresh
        connection's first dup-ACK-driven loss event can enter
        fast retransmit without an artificial gate.

        Reference: RFC 6582 §3.2 step 4 (recover variable).
        """

        session = self._drive_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self.assertEqual(
            session._cc.recover_seq,
            0,
            msg=(
                "RFC 6582 §3.2 step 4 sentinel: _recover_seq MUST "
                "initialise to 0 so the first loss event is not "
                f"gated. Got _recover_seq={session._cc.recover_seq}."
            ),
        )

    def test__rfc6582__rto_records_snd_max_into_recover_seq(self) -> None:
        """
        Ensure that the RTO path records the highest SND.MAX
        transmitted into '_recover_seq' per §3.2 step 4 so the
        post-RTO fast-retransmit gate has a marker to compare
        SND.UNA against.

        Reference: RFC 6582 §3.2 step 4 (record SND.MAX on RTO).
        """

        session = self._drive_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.send(data=b"X" * 100)
        self._advance(ms=1)
        snd_max_at_rto = session._snd_seq.max
        # Force RTO firing by advancing past current RTO.
        self._advance(ms=session._rto_state.rto_ms + 10)

        self.assertEqual(
            session._cc.recover_seq,
            snd_max_at_rto,
            msg=(
                "RFC 6582 §3.2 step 4: post-RTO _recover_seq MUST "
                f"equal the pre-RTO SND.MAX ({snd_max_at_rto}). "
                f"Got _recover_seq={session._cc.recover_seq}."
            ),
        )

    def test__rfc6582__recover_seq_clears_when_cum_ack_passes_marker(self) -> None:
        """
        Ensure that '_recover_seq' decays back to the 0 sentinel
        once SND.UNA has advanced strictly past the recorded
        marker, re-enabling normal fast retransmit on subsequent
        loss events.

        Reference: RFC 6582 §3.2 step 4 (recover marker decay).
        """

        session = self._drive_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.send(data=b"X" * 100)
        self._advance(ms=1)
        snd_max_at_rto = session._snd_seq.max
        self._advance(ms=session._rto_state.rto_ms + 10)
        assert session._cc.recover_seq == snd_max_at_rto

        # Peer ACKs all bytes up to (and including) the marker
        # (snd_max_at_rto is one past the last data byte sent;
        # cum-ACK = snd_max_at_rto fully ACKs the burst, and
        # _recover_seq clears once SND.UNA reaches the marker).
        peer_full_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=snd_max_at_rto,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_full_ack)

        self.assertEqual(
            session._cc.recover_seq,
            0,
            msg=(
                "RFC 6582 §3.2 step 4 decay: _recover_seq MUST "
                "clear once SND.UNA passes the marker. Got "
                f"_recover_seq={session._cc.recover_seq}."
            ),
        )


class TestTcpRfc6675SackRetainedOnRto(TcpTestCase):
    """
    RFC 6675 §5.1: "A SACK TCP sender SHOULD utilize all SACK
    information made available during the loss recovery
    following an RTO." This is the modern interpretation that
    supersedes RFC 2018 §5's older "turn off SACKed bits"
    guidance. PyTCP retains the SACK scoreboard across the RTO.
    """

    def _drive_to_established(self, *, iss: int, peer_iss: int) -> TcpSession:
        """Drive active-open handshake."""

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
            sackperm=True,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._advertise.send_sack
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__rfc6675__rto_retains_sack_scoreboard(self) -> None:
        """
        Ensure that the RTO retransmit handler retains the
        '_sack_scoreboard' so the post-RTO recovery can use the
        prior SACK reports to skip already-delivered ranges.
        The modern interpretation supersedes the older "turn
        off SACKed bits" guidance.

        Reference: RFC 6675 §5.1 (utilize all SACK info on RTO).
        Reference: RFC 2018 §5 (legacy "turn off SACKed bits", now superseded).
        """

        session = self._drive_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Inject a SACK block manually so the scoreboard is
        # non-empty pre-RTO.
        session._sack_scoreboard.add_block(LOCAL__ISS + 100, LOCAL__ISS + 200)
        assert len(session._sack_scoreboard.blocks()) == 1

        session.send(data=b"X" * 100)
        self._advance(ms=1)
        self._advance(ms=session._rto_state.rto_ms + 10)

        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [(LOCAL__ISS + 100, LOCAL__ISS + 200)],
            msg=(
                "RFC 6675 §5.1: post-RTO the SACK scoreboard "
                "MUST retain prior SACK info. Got "
                f"{session._sack_scoreboard.blocks()!r}."
            ),
        )
