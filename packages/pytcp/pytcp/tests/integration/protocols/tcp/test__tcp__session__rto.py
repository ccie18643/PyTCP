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
This module contains integration tests for the RFC 6298 RTO sample
collection. See 'docs/rfc/tcp/rfc6298__rto_computation/adherence.md'
for the per-clause spec audit.

RFC 6298 §4 specifies how the RTT estimator MUST collect samples
from outbound segments and the corresponding ACKs:

    "TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
     That is, RTT samples MUST NOT be made using segments that were
     retransmitted (and thus for which it is ambiguous whether the
     reply was for the first instance of the packet or a later
     instance)."

    "Traditionally, TCP implementations use coarse grain clocks to
     measure the RTT and trigger the RTO, ... [section 4 paragraph
     describes single-sample-per-RTT cadence]."

The Phase 2 work installs a single-pending-sample tracker on
'TcpSession':

    _rto_state: RtoState                    # initial_state() in __init__
    _rtt_sample_seq: Seq32 | None = None    # seq we're sampling
    _rtt_sample_send_time_ms: int | None    # virtual clock at send
    _rtt_sample_retransmitted: bool = False # Karn's flag

with three hook points:

    _transmit_packet  - records a fresh sample iff none is pending.
    _process_ack_packet - harvests on ACK passing sample seq, runs
                          'update' iff Karn's flag is False, then
                          clears the tracker.
    _retransmit_packet_timeout - sets Karn's flag on the in-flight
                                 sample so the eventual ACK does
                                 not poison the smoothed estimate.

The retransmit-timer logic itself is unchanged in Phase 2:
'_rto_state.rto_ms' is observed but the per-seq backoff machinery
('_tx_retransmit_timeout_counter') still drives the wire cadence.
Phase 3 (a follow-up commit set) replaces the per-seq machinery
with the session-level RTO timer.

The tests below exercise the six invariants of Phase 2 and are
expected to FAIL today against a session that does not yet expose
'_rto_state' / '_rtt_sample_seq' / '_rtt_sample_send_time_ms' /
'_rtt_sample_retransmitted'. The fix commit adds the fields and
the three hook points; this test file flips green at that point.

Reference RFCs:
    RFC 6298 §2     RTO computation
    RFC 6298 §3     Karn's algorithm
    RFC 6298 §4     Single-sample-per-RTT cadence
    RFC 9293 §3.8.4 references RFC 6298 by inclusion

pytcp/tests/integration/protocols/tcp/test__tcp__session__rto.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__rto import (
    INITIAL_RTO_MS,
    RtoState,
    initial_state,
    update,
)
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__socket import TcpSocket
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

# Initial sequence numbers, well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply (1500 - 20 - 20 IPv4).
PEER__MSS: int = 1460


class TestTcpRtoSampling(TcpTestCase):
    """
    Integration tests for the RFC 6298 RTO sample-collection
    machinery: pending-sample tracker, single-sample-per-RTT
    cadence, harvest-on-ACK, Karn-tainted-on-retransmit.
    """

    def test__rto__outbound_data_segment_records_pending_sample(self) -> None:
        """
        Ensure that an outbound data segment in ESTABLISHED
        records a pending RTT sample on TcpSession with
        sample_seq, sample_send_time_ms, and the Karn taint
        flag cleared.

        Reference: RFC 6298 §2.2 (RTT sampling first segment).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Post-handshake the SYN sample has been harvested.
        self.assertIsNone(
            session._rtt.seq,
            msg=(
                "Post-handshake the SYN sample MUST have "
                "been harvested by peer's SYN+ACK; "
                "'_rtt_sample_seq' should be 'None'."
            ),
        )

        payload = b"hello, world!"
        session.send(data=payload)
        send_tick_now_ms = self._timer.now_ms + 1
        self._advance(ms=1)

        self.assertEqual(
            session._rtt.seq,
            LOCAL__ISS + 1,
            msg=(
                "An outbound data segment in"
                "ESTABLISHED MUST record a pending RTT sample "
                "with sample_seq equal to the segment's seq."
            ),
        )
        self.assertEqual(
            session._rtt.send_time_ms,
            send_tick_now_ms,
            msg=("The recorded send-time MUST equal the " "virtual clock at the moment " "'_transmit_packet' fired."),
        )
        self.assertFalse(
            session._rtt.retransmitted,
            msg=(
                "A fresh outbound segment MUST mark the "
                "pending sample as not-retransmitted; Karn's "
                "flag is set only on retransmit."
            ),
        )

    def test__rto__ack_covering_pending_sample_harvests_and_updates_rto_state(self) -> None:
        """
        Ensure that an ACK whose ack-field passes the
        pending sample seq harvests the sample, advances
        '_rto_state' via 'update(prior, observed_rtt_ms)',
        and clears the sample tracker.

        Reference: RFC 6298 §2.2 (first-sample formula).
        Reference: RFC 6298 §2.3 (EWMA update).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        pre_ack_state = session._rto_state

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)
        sample_send_time = session._rtt.send_time_ms

        self._advance(ms=9)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        observed_rtt_ms = self._timer.now_ms - (sample_send_time or 0)
        expected_state = update(pre_ack_state, observed_rtt_ms)

        self.assertEqual(
            session._rto_state,
            expected_state,
            msg=(
                "ACK harvesting the pending sample MUST fold "
                f"'observed_rtt_ms={observed_rtt_ms}' into "
                "the prior state via 'update'. Expected "
                f"{expected_state!r}, got {session._rto_state!r}."
            ),
        )
        self.assertIsNone(
            session._rtt.seq,
            msg=(
                "After harvest the sample tracker MUST be "
                "cleared so the next outbound segment can "
                "start a fresh sample."
            ),
        )

    def test__rto__additional_data_while_sample_pending_does_not_overwrite(self) -> None:
        """
        Ensure single-sample-per-RTT cadence: additional
        outbound segments fired while a previous sample is
        still pending do not overwrite the pending sample.

        Reference: RFC 6298 §2.2 (single sample per RTT).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"x" * (2 * PEER__MSS)
        session.send(data=payload)

        first_tx = self._advance(ms=1)
        self.assertEqual(
            len(first_tx),
            1,
            msg=(f"Setup invariant: first tick must produce exactly " f"one segment. Got {len(first_tx)}."),
        )
        first_sample_seq = session._rtt.seq

        second_tx = self._advance(ms=1)
        self.assertEqual(
            len(second_tx),
            1,
            msg=(f"Setup invariant: second tick must produce the " f"second segment. Got {len(second_tx)}."),
        )

        self.assertEqual(
            session._rtt.seq,
            first_sample_seq,
            msg=(
                "While a sample is pending, subsequent "
                "outbound segments MUST NOT overwrite "
                "'_rtt_sample_seq'. Single-sample-per-RTT cadence."
            ),
        )
        self.assertEqual(
            first_sample_seq,
            LOCAL__ISS + 1,
            msg=("Setup invariant: first sample seq must equal the " "first segment's seq."),
        )

    def test__rto__post_harvest_next_outbound_starts_fresh_sample(self) -> None:
        """
        Ensure that once the pending sample has been
        harvested by a covering ACK, the next outbound data
        segment starts a fresh sample.

        Reference: RFC 6298 §2.2 (single sample per RTT, fresh after harvest).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        first_payload = b"hello"
        session.send(data=first_payload)
        self._advance(ms=1)

        first_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(first_payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=first_ack)
        self.assertIsNone(
            session._rtt.seq,
            msg=(
                "Setup invariant: the first sample must have been "
                "harvested by the first ACK before the second "
                "segment fires."
            ),
        )

        second_payload = b"world"
        session.send(data=second_payload)
        second_send_now_ms = self._timer.now_ms + 1
        self._advance(ms=1)

        self.assertEqual(
            session._rtt.seq,
            LOCAL__ISS + 1 + len(first_payload),
            msg=(
                "After a sample is harvested, the "
                "next outbound segment MUST start a fresh sample "
                "with sample_seq equal to the new segment's seq."
            ),
        )
        self.assertEqual(
            session._rtt.send_time_ms,
            second_send_now_ms,
            msg=("The fresh sample's send-time MUST " "equal the virtual clock at the second-segment " "send."),
        )
        self.assertFalse(
            session._rtt.retransmitted,
            msg=("A fresh post-harvest sample is not " "Karn-tainted; '_rtt_sample_retransmitted' MUST " "be False."),
        )

    def test__rto__retransmit_marks_pending_sample_as_karn_tainted(self) -> None:
        """
        Ensure that when a segment with a pending sample is
        retransmitted via the timeout path, the sample is
        marked tainted (Karn's algorithm) so the eventual
        ACK does not produce an RTT sample.

        Reference: RFC 6298 §3 (Karn's algorithm).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)
        original_sample_seq = session._rtt.seq

        # Advance past the per-seq retransmit timeout (1000 ms)
        # so '_retransmit_packet_timeout' fires.
        self._advance(ms=1001)

        self.assertTrue(
            session._rtt.retransmitted,
            msg=(
                "Karn: retransmit of the sampled "
                "segment MUST set '_rtt_sample_retransmitted' so "
                "the eventual ACK does not poison the smoothed "
                "estimate."
            ),
        )
        self.assertEqual(
            session._rtt.seq,
            original_sample_seq,
            msg=(
                "Karn's algorithm taints the sample "
                "but does NOT clear it - 'sample_seq' must remain "
                "set so the harvest path can recognise the "
                "covering ACK and skip 'update'."
            ),
        )

    def test__rto__ack_of_karn_tainted_sample_clears_but_does_not_update_state(self) -> None:
        """
        Ensure an ACK that harvests a Karn-tainted sample
        clears the sample tracker without folding the
        observed RTT into '_rto_state' — the smoothed
        estimator stays stale until a fresh non-retransmitted
        sample arrives.

        Reference: RFC 6298 §3 (Karn's algorithm).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)

        # Taint the sample via retransmit timeout fire.
        self._advance(ms=1001)
        assert session._rtt.retransmitted, (
            "Setup invariant: the retransmit timeout must have "
            "fired and tainted the pending sample before the "
            "covering ACK arrives."
        )
        pre_ack_rto_state = session._rto_state

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertIsNone(
            session._rtt.seq,
            msg=(
                "Harvest of a Karn-tainted sample MUST "
                "clear the sample tracker even though the "
                "smoothed estimate is not updated."
            ),
        )
        self.assertEqual(
            session._rto_state,
            pre_ack_rto_state,
            msg=(
                "Karn: the tainted sample's RTT MUST NOT be "
                "folded into '_rto_state'. Expected the "
                f"unchanged pre-ACK state "
                f"{pre_ack_rto_state!r}, got "
                f"{session._rto_state!r}."
            ),
        )


class TestTcpRtoInitialization(TcpTestCase):
    """
    Construction-time invariants for the RFC 6298 RTO state on a
    fresh 'TcpSession'.
    """

    def test__rto__fresh_session_initializes_rto_state_to_initial(self) -> None:
        """
        Ensure a freshly-constructed TcpSession starts with
        '_rto_state == initial_state()' (SRTT and RTTVAR
        uninitialised, RTO at INITIAL_RTO_MS) and an empty
        sample tracker.

        Reference: RFC 6298 §2.1 (initial RTO = 1 second).
        """

        self._force_iss(LOCAL__ISS)

        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = PEER__IP
        sock._remote_port = PEER__PORT

        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=PEER__IP,
            remote_port=PEER__PORT,
            socket=sock,
        )

        self.assertEqual(
            session._rto_state,
            initial_state(),
            msg=(
                "A fresh session MUST initialise "
                "'_rto_state' to 'initial_state()' "
                "(srtt_ms=None, rttvar_ms=None, "
                f"rto_ms={INITIAL_RTO_MS})."
            ),
        )
        self.assertIsNone(
            session._rtt.seq,
            msg="A fresh session has no pending sample.",
        )
        self.assertIsNone(
            session._rtt.send_time_ms,
            msg="A fresh session has no pending sample.",
        )
        self.assertFalse(
            session._rtt.retransmitted,
            msg="A fresh session's sample tracker is not Karn-tainted.",
        )

        self.assertIsInstance(
            session._rto_state,
            RtoState,
            msg=("'_rto_state' must be the typed 'RtoState' " "dataclass from 'pytcp.protocols.tcp.tcp__rto'."),
        )


class TestTcpRtoRetransmitTimer(TcpTestCase):
    """
    Integration tests for the RFC 6298 §5 session-level retransmit
    timer machinery.

    The session-level timer replaced an earlier per-seq retransmit-
    timer family
    ('f"{session}-retransmit_seq-{seq}"' keyed by '_tx_retransmit_timeout_counter')
    with a single session-level timer 'f"{session}-retransmit"' driven
    by '_rto_state.rto_ms'. The five RFC 6298 §5 invariants the new
    machinery must satisfy:

        §5.1  Every time a packet containing data is sent (including
              a retransmission), if the timer is not running, start
              it running so that it will expire after RTO seconds.
        §5.2  When all outstanding data has been acknowledged, turn
              off the retransmission timer.
        §5.3  When an ACK is received that acknowledges new data,
              restart the retransmission timer so that it will
              expire after RTO seconds.
        §5.4  Retransmit the earliest segment that has not been
              acknowledged.
        §5.5  Set RTO = RTO * 2 ('back off the timer'), capped at
              the upper bound (MAX_RTO_MS).

    The tests below exercise §5.1 / §5.2 / §5.5 directly. §5.3 and
    §5.4 are covered transitively by the existing
    'data_transfer__retransmit_timeout' integration suite (whose
    cadence assertions stay green via the 'MIN_RTO_MS' clamp).
    """

    def test__rto__data_transmit_arms_session_level_retransmit_timer(self) -> None:
        """
        Ensure that when a data segment is sent and no
        retransmit timer is currently running, the session
        arms a single 'f"{session}-retransmit"' timer with
        timeout equal to '_rto_state.rto_ms'.

        Reference: RFC 6298 §5.1 (start retransmission timer on data send).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)

        session_retransmit_timer = f"{session}-retransmit"
        self.assertIn(
            session_retransmit_timer,
            self._pending_session_timers(session),
            msg=(
                "A data send while no retransmit timer is "
                f"running MUST arm '{session_retransmit_timer}'. "
                f"Got pending timers: "
                f"{sorted(self._pending_session_timers(session))!r}."
            ),
        )
        self.assertEqual(
            self._pending_session_timers(session)[session_retransmit_timer],
            session._rto_state.rto_ms,
            msg=(
                "The session-level retransmit timer MUST be "
                "armed with '_rto_state.rto_ms' "
                f"(= {session._rto_state.rto_ms} ms "
                f"post-handshake)."
            ),
        )

        legacy_per_seq_keys = [
            k for k in self._pending_session_timers(session) if k.startswith(f"{session}-retransmit_seq-")
        ]
        self.assertEqual(
            legacy_per_seq_keys,
            [],
            msg=(
                "Phase 3 retires the per-seq retransmit-timer family. "
                "No 'f\"{session}-retransmit_seq-X\"' keys may survive "
                f"after a fresh data send. Got: {legacy_per_seq_keys!r}."
            ),
        )

    def test__rto__cumulative_ack_draining_in_flight_stops_retransmit_timer(self) -> None:
        """
        Ensure that when a cumulative ACK fully drains the
        in-flight bytes (all sent data is acknowledged),
        the retransmit timer is turned off.

        Reference: RFC 6298 §5.2 (turn off retransmission timer when all data is acked).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        retransmit_keys = [k for k in self._pending_session_timers(session) if "retransmit" in k]
        self.assertEqual(
            retransmit_keys,
            [],
            msg=(
                "A cum-ACK that drains all in-flight bytes "
                "MUST turn off the retransmission timer. Got "
                f"surviving keys: {retransmit_keys!r}."
            ),
        )

    def test__rto__retransmit_timeout_backs_off_rto_state(self) -> None:
        """
        Ensure that when the retransmit timer expires,
        '_rto_state.rto_ms' is doubled via 'back_off'
        (capped at MAX_RTO_MS), SRTT / RTTVAR are unchanged,
        and the timer is re-armed with the new rto_ms.

        Reference: RFC 6298 §5.5 (binary backoff).
        Reference: RFC 6298 §5.6 (re-arm timer with new RTO).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        pre_backoff_state = session._rto_state

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)

        # Advance to exactly the per-handshake-clamped RTO
        # boundary. With the MIN_RTO_MS clamp the timer is armed
        # at 1000 ms; the last tick of this advance is the one
        # that drops the timer to 0 AND fires
        # '_retransmit_packet_timeout' (FakeTimer ticks _timers
        # before _tasks, so the post-backoff re-arm sees the new
        # 'rto_ms' decremented zero further times by 'advance'
        # before the assertion sees it).
        self._advance(ms=1000)

        self.assertEqual(
            session._rto_state.rto_ms,
            pre_backoff_state.rto_ms * 2,
            msg=(
                "Retransmit timeout MUST double "
                "'_rto_state.rto_ms' via 'back_off'. Pre-"
                f"backoff rto_ms={pre_backoff_state.rto_ms}; "
                f"expected {pre_backoff_state.rto_ms * 2} "
                f"post-backoff; got "
                f"{session._rto_state.rto_ms}."
            ),
        )
        self.assertEqual(
            session._rto_state.srtt_ms,
            pre_backoff_state.srtt_ms,
            msg=(
                "'back_off' MUST NOT touch SRTT - Karn's "
                "algorithm separates sample-driven updates "
                "from timeout-driven backoffs."
            ),
        )
        self.assertEqual(
            session._rto_state.rttvar_ms,
            pre_backoff_state.rttvar_ms,
            msg=(
                "'back_off' MUST NOT touch RTTVAR - Karn's "
                "algorithm separates sample-driven updates "
                "from timeout-driven backoffs."
            ),
        )

        session_retransmit_timer = f"{session}-retransmit"
        self.assertIn(
            session_retransmit_timer,
            self._pending_session_timers(session),
            msg=(
                "After back_off, the retransmit timer MUST "
                "be re-armed with the new rto_ms. Got "
                "pending timers: "
                f"{sorted(self._pending_session_timers(session))!r}."
            ),
        )
        self.assertEqual(
            self._pending_session_timers(session)[session_retransmit_timer],
            session._rto_state.rto_ms,
            msg=(
                "The re-armed timer's timeout MUST equal "
                "the post-backoff "
                f"'_rto_state.rto_ms = {session._rto_state.rto_ms}'."
            ),
        )


class TestTcpRtoRestartAfterIdle(TcpTestCase):
    """
    Integration tests for the RFC 6298 §5.7 restart-after-idle
    behaviour.

    When a session has been silent for longer than the in-flight
    'rto_ms' the smoothed RTT estimator may be stale - the
    network conditions that produced the current SRTT/RTTVAR may
    no longer hold. Phase 4 hooks '_transmit_packet' so the next
    outbound segment after a long idle resets '_rto_state' to
    'initial_state()' and the §4 sample-collection hook then
    re-establishes the estimator from scratch on the next
    covering ACK.

    The reset is gated on:

        '_last_send_time_ms is not None'
        AND 'now_ms - _last_send_time_ms > _rto_state.rto_ms'
        AND segment carries a data/SYN/FIN byte (i.e. it
            consumes sequence space the peer can ACK back)

    so a fresh session never spuriously resets, and a quiescent
    burst spaced under 'rto_ms' preserves the smoothed estimate
    that drives subsequent retransmit timing.
    """

    def _send_one_payload_and_ack(self, *, session: TcpSession, seq_offset: int, payload: bytes) -> None:
        """
        Send 'payload', drive the data segment out on the next
        tick, then drive a peer ACK that fully covers it. Used
        to put the session into the post-handshake quiescent
        state where the retransmit timer is off (§5.2 satisfied)
        and a subsequent idle period can be observed cleanly.
        """

        session.send(data=payload)
        self._advance(ms=1)
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + seq_offset + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

    def test__rto__idle_longer_than_rto_resets_state_to_initial(self) -> None:
        """
        Ensure that a session quiescent for longer than the
        in-flight 'rto_ms' resets '_rto_state' to
        'initial_state()' on the next outbound segment, so
        a stale smoothed estimator does not drive spurious
        retransmits with a now-too-short RTO.

        Reference: RFC 6298 §5.7 (restart-after-idle).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Step 1: send + ACK first payload so the session
        # reaches a quiescent state (timer off, all in-flight
        # acked).
        first_payload = b"hello"
        self._send_one_payload_and_ack(
            session=session,
            seq_offset=0,
            payload=first_payload,
        )
        first_send_time = session._rtt.last_send_time_ms
        self.assertIsNotNone(
            first_send_time,
            msg="Setup invariant: '_last_send_time_ms' must be recorded after the first send.",
        )

        # Step 2: idle longer than rto_ms (= 1000 ms post-clamp).
        self._advance(ms=2000)

        # Step 3: send second payload.
        second_payload = b"world"
        session.send(data=second_payload)
        self._advance(ms=1)

        self.assertEqual(
            session._rto_state,
            initial_state(),
            msg=(
                "Idle for "
                f"{self._timer.now_ms - (first_send_time or 0)}"
                f" ms > rto_ms={1000}; '_rto_state' MUST "
                "reset to 'initial_state()' on the next data "
                f"send. Got {session._rto_state!r}."
            ),
        )
        self.assertEqual(
            session._rtt.seq,
            LOCAL__ISS + 1 + len(first_payload),
            msg=(
                "The §5.7 reset must not interfere with "
                "sample collection - the new outbound segment "
                "still records its sample seq."
            ),
        )

    def test__rto__idle_shorter_than_rto_preserves_state(self) -> None:
        """
        Ensure the §5.7 reset is gated on the idle period
        exceeding 'rto_ms'. A burst of writes spaced shorter
        than the smoothed RTO preserves the smoothed
        estimator.

        Reference: RFC 6298 §5.7 (restart-after-idle gated on idle > RTO).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        first_payload = b"hello"
        self._send_one_payload_and_ack(
            session=session,
            seq_offset=0,
            payload=first_payload,
        )
        pre_idle_state = session._rto_state
        self.assertIsNotNone(
            session._rtt.last_send_time_ms,
            msg="Setup invariant: '_last_send_time_ms' must be recorded after the first send.",
        )

        # Short idle, well under rto_ms = 1000 ms.
        self._advance(ms=500)

        second_payload = b"world"
        session.send(data=second_payload)
        self._advance(ms=1)

        self.assertEqual(
            session._rto_state,
            pre_idle_state,
            msg=(
                "The idle-reset is gated on the idle period "
                "exceeding 'rto_ms'. A 500 ms idle with "
                "rto_ms=1000 must not trigger the reset; "
                f"'_rto_state' must remain at "
                f"{pre_idle_state!r}. Got {session._rto_state!r}."
            ),
        )

    def test__rto__transmit_updates_last_send_time(self) -> None:
        """
        Ensure that '_transmit_packet' records the virtual
        clock at every outbound segment that consumes
        sequence space (data / SYN / FIN), so the §5.7 idle
        check has an accurate baseline.

        Reference: RFC 6298 §5.7 (last-send-time tracking for idle reset).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # SYN consumed sequence space at t=0; handshake helper
        # advances 1 ms before delivering SYN+ACK, so the
        # post-handshake '_last_send_time_ms' is the SYN send
        # time (= 0 ms on FakeTimer's virtual clock).
        self.assertIsNotNone(
            session._rtt.last_send_time_ms,
            msg=(
                "Baseline: '_last_send_time_ms' MUST be "
                "recorded by the SYN send during handshake. "
                "Otherwise the first post-handshake data "
                "send sees 'None' and skips the idle-reset "
                "check entirely."
            ),
        )

        payload = b"hello, world!"
        session.send(data=payload)
        send_tick_now_ms = self._timer.now_ms + 1
        self._advance(ms=1)

        self.assertEqual(
            session._rtt.last_send_time_ms,
            send_tick_now_ms,
            msg=(
                "'_last_send_time_ms' MUST equal the "
                "virtual clock at the moment "
                "'_transmit_packet' fired the data segment."
            ),
        )


class TestTcpRtoSynFloor(TcpTestCase):
    """
    Integration tests for the RFC 6298 §5.7 SECOND clause: the
    SYN-RTO 3-second floor.

    RFC 6298 §5.7 second sentence:

        "If the timer expires awaiting the ACK of a SYN segment
         and the TCP implementation is using an RTO less than
         3 seconds, the RTO MUST be re-initialized to 3 seconds
         when data transmission begins (i.e., after the three-
         way handshake completes)."

    The floor protects against pathologically aggressive RTOs
    in environments where the SYN's RTT measurement (clamped to
    MIN_RTO_MS = 1000 ms by the RFC 6298 §2.4 lower bound) is
    optimistic relative to the path's actual RTT. By forcing
    rto_ms >= 3000 ms after a SYN retransmit, the first
    post-handshake data send is given a more conservative
    timeout while the connection re-acquires fresh RTT samples.

    The floor applies ONLY when the SYN was retransmitted at
    least once (i.e., '_retransmit_count > 0' at handshake
    completion). If the peer's SYN+ACK arrives before any SYN
    retransmit fires, no floor applies - the canonical RTT
    measurement (typically clamped to MIN_RTO_MS) stands.
    """

    def test__rto__post_syn_retransmit_handshake_floors_rto_at_3000ms(self) -> None:
        """
        Ensure that when the SYN was retransmitted at least
        once (peer's SYN+ACK arrives only after the SYN
        retransmit fired), the post-handshake
        '_rto_state.rto_ms' is >= 3000 ms when data
        transmission begins.

        Reference: RFC 6298 §5.7 (SYN-RTO 3-second floor after retransmit).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Initial SYN goes out on the first tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup invariant: connect must emit one SYN frame on the first tick.",
        )

        # Advance past the initial RTO so the SYN's retransmit
        # timer fires at least once.
        self._advance(ms=1500)
        self.assertGreaterEqual(
            session._retransmit_count,
            1,
            msg=(
                "Setup invariant: after 1.5 s of peer silence, the SYN's "
                "retransmit timer (RTO=1000 ms) MUST have fired at least "
                f"once. Got _retransmit_count={session._retransmit_count}."
            ),
        )

        # Peer's SYN+ACK arrives; handshake completes.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: handshake MUST complete on peer SYN+ACK.",
        )
        self.assertGreaterEqual(
            session._rto_state.rto_ms,
            3000,
            msg=(
                "When the SYN was retransmitted at least "
                "once before the handshake completed, "
                "'_rto_state.rto_ms' MUST be re-initialized "
                "to >= 3000 ms when data transmission "
                "begins. Got _rto_state.rto_ms="
                f"{session._rto_state.rto_ms} ms."
            ),
        )

    def test__rto__post_clean_handshake_no_syn_retransmit_skips_3000ms_floor(self) -> None:
        """
        Ensure that when the SYN was not retransmitted
        (peer's SYN+ACK arrives before any SYN-RTO timer
        fires), the SYN-RTO 3-second floor does not apply
        and '_rto_state.rto_ms' takes whatever value the
        canonical SRTT / RTTVAR estimator yields.

        Reference: RFC 6298 §5.7 (SYN-RTO floor only applies on retransmit).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # Peer's SYN+ACK arrives within the initial RTO window;
        # no SYN retransmit fires.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: clean handshake reaches ESTABLISHED.",
        )
        self.assertEqual(
            session._retransmit_count,
            0,
            msg=(
                "Setup invariant: no SYN retransmit fired before peer's "
                f"SYN+ACK; _retransmit_count must be 0. Got "
                f"{session._retransmit_count}."
            ),
        )
        self.assertLess(
            session._rto_state.rto_ms,
            3000,
            msg=(
                "The 3-second floor applies ONLY when the "
                "SYN was retransmitted. A clean handshake's "
                "post-handshake '_rto_state.rto_ms' MUST be "
                "the canonical estimator output, NOT 3000 ms. "
                f"Got _rto_state.rto_ms="
                f"{session._rto_state.rto_ms} ms."
            ),
        )

    def _make_listen_session(self, *, iss: int) -> tuple[TcpSocket, TcpSession]:
        """
        Build a wildcard-listen 'TcpSocket' / 'TcpSession' pair
        ready to accept inbound SYNs. Mirrors the harness used
        in 'handshake__passive.py'.
        """

        from net_addr import Ip4Address as _Ip4Address

        self._force_iss(iss)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = _Ip4Address()
        sock._remote_port = 0
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=_Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.LISTEN)
        return sock, session

    def test__rto__passive_open_with_syn_ack_retransmit_floors_rto_at_3000ms(self) -> None:
        """
        Ensure that the SYN-RTO 3-second floor applies on
        the passive-open path: if our SYN+ACK was
        retransmitted before peer's third-leg ACK arrived,
        post-handshake '_rto_state.rto_ms' is >= 3000 ms.

        Reference: RFC 6298 §5.7 (SYN-RTO 3-second floor, applied to passive-open SYN+ACK).
        """

        listen_sock, _ = self._make_listen_session(iss=LOCAL__ISS)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        # First tick fires the SYN+ACK from the freshly-spawned
        # child in SYN_RCVD.
        first_tx = self._advance(ms=1)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup invariant: SYN_RCVD must emit exactly one SYN+ACK on the first tick.",
        )

        # The original listening session has been mutated into
        # the child bound to peer's 4-tuple. Resolve it via the
        # child socket id.
        from pytcp.socket import SocketType
        from pytcp.socket.socket_id import SocketId

        child_socket_id = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=STACK__IP,
            local_port=STACK__PORT,
            remote_address=PEER__IP,
            remote_port=PEER__PORT,
        )
        child_sock = stack.sockets[child_socket_id]
        assert isinstance(child_sock, TcpSocket)
        child_session = child_sock._tcp_session
        assert child_session is not None

        # Advance past the SYN+ACK's retransmit RTO (1000 ms)
        # so the retransmit timer fires once.
        self._advance(ms=1500)
        self.assertGreaterEqual(
            child_session._retransmit_count,
            1,
            msg=(
                "Setup invariant: after 1.5 s of peer silence, "
                "the SYN+ACK's retransmit timer (RTO=1000 ms) "
                "MUST have fired at least once. Got "
                f"_retransmit_count={child_session._retransmit_count}."
            ),
        )

        # Peer's third-leg ACK finally arrives; handshake
        # completes.
        third_leg_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=third_leg_ack)

        self.assertIs(
            child_session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: third-leg ACK must complete the handshake.",
        )
        self.assertGreaterEqual(
            child_session._rto_state.rto_ms,
            3000,
            msg=(
                "When our SYN+ACK was retransmitted at "
                "least once before peer's third-leg ACK "
                "arrived, '_rto_state.rto_ms' MUST be re-"
                "initialized to >= 3000 ms when data "
                f"transmission begins. Got _rto_state.rto_ms="
                f"{child_session._rto_state.rto_ms} ms."
            ),
        )

        # Cleanup: drop spawned child socket so other tests in
        # the class are not contaminated.
        for sid in list(stack.sockets):
            if sid != listen_sock.socket_id:
                del stack.sockets[sid]

    def test__rto__passive_open_clean_handshake_skips_3000ms_floor(self) -> None:
        """
        Ensure that a clean passive open (third-leg ACK
        arrives within the initial RTO, no SYN+ACK
        retransmit) does not apply the SYN-RTO 3-second
        floor.

        Reference: RFC 6298 §5.7 (SYN-RTO floor only on retransmit, passive-open shape).
        """

        listen_sock, _ = self._make_listen_session(iss=LOCAL__ISS)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self._advance(ms=1)

        from pytcp.socket import SocketType
        from pytcp.socket.socket_id import SocketId

        child_socket_id = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=STACK__IP,
            local_port=STACK__PORT,
            remote_address=PEER__IP,
            remote_port=PEER__PORT,
        )
        child_sock = stack.sockets[child_socket_id]
        assert isinstance(child_sock, TcpSocket)
        child_session = child_sock._tcp_session
        assert child_session is not None

        # Peer's third-leg ACK arrives within the initial RTO
        # window; no SYN+ACK retransmit fires.
        third_leg_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=third_leg_ack)

        self.assertIs(
            child_session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: clean passive-open reaches ESTABLISHED.",
        )
        self.assertEqual(
            child_session._retransmit_count,
            0,
            msg=(
                "Setup invariant: no SYN+ACK retransmit fired before "
                "peer's third-leg ACK; _retransmit_count must be 0. "
                f"Got {child_session._retransmit_count}."
            ),
        )
        self.assertLess(
            child_session._rto_state.rto_ms,
            3000,
            msg=(
                "The floor applies ONLY when our SYN+ACK "
                "was retransmitted. A clean passive open's "
                "post-handshake '_rto_state.rto_ms' MUST be "
                "the canonical estimator output, NOT 3000 ms. "
                f"Got _rto_state.rto_ms="
                f"{child_session._rto_state.rto_ms} ms."
            ),
        )

        for sid in list(stack.sockets):
            if sid != listen_sock.socket_id:
                del stack.sockets[sid]

    def test__rto__syn_retransmit_count_survives_process_ack_packet_reset(self) -> None:
        """
        Ensure that '_syn_retransmit_count' accumulates
        SYN / SYN+ACK retransmit-timer fires while in
        {SYN_SENT, SYN_RCVD} and is NOT reset by
        '_process_ack_packet' on the SND.UNA-advancing
        handshake-completing ACK, so the SYN-RTO floor
        check is order-independent.

        Reference: RFC 6298 §5.7 (SYN-RTO floor relies on persistent retransmit count).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        self._advance(ms=1500)

        self.assertTrue(
            hasattr(session, "_syn_retransmit_count"),
            msg=(
                "TcpSession MUST expose a "
                "'_syn_retransmit_count' field decoupled "
                "from the general-purpose '_retransmit_count'."
            ),
        )
        self.assertGreaterEqual(
            getattr(session, "_syn_retransmit_count", -1),
            1,
            msg=(
                "'_syn_retransmit_count' MUST increment on "
                "each SYN-RTO timer fire while in SYN_SENT. Got "
                f"{getattr(session, '_syn_retransmit_count', None)}."
            ),
        )

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: handshake completes on peer SYN+ACK.",
        )
        self.assertGreaterEqual(
            getattr(session, "_syn_retransmit_count", -1),
            1,
            msg=("'_syn_retransmit_count' MUST survive " "'_process_ack_packet's reset of " "'_retransmit_count'."),
        )
