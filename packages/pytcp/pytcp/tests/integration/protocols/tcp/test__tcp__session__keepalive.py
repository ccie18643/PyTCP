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
This module contains integration tests for the TCP keep-alive
mechanism per RFC 1122 §4.2.3.6.

RFC 1122 §4.2.3.6 mandates four behavioural invariants:
    1. The keep-alive mechanism MUST default to OFF.
    2. The application MUST be able to enable / disable keep-alive
       per-connection (in PyTCP, via 'TcpSession._keepalive_enabled').
    3. The keep-alive idle timer MUST default to no less than 2 h
       (the constant 'TCP__KEEPALIVE__IDLE_TIME_MS = 7_200_000' satisfies this
       at the implementation level; tests patch it to small values).
    4. After the idle timer expires, the implementation emits a
       probe ('ACK' with 'SEG.SEQ = SND.NXT - 1' so peer's TCP
       responds with an ACK at the current SND.NXT without
       delivering any segment text to peer's application). On
       probe-ack the idle timer is rearmed; on lack of response the
       probe is retransmitted every 'TCP__KEEPALIVE__PROBE_INTERVAL_MS', and
       after 'TCP__KEEPALIVE__PROBE_MAX_COUNT' unanswered probes the
       connection is declared dead.

Reference RFCs:
    RFC 1122 §4.2.3.6   TCP keep-alive
    RFC 9293 §3.8.4     references and defers to RFC 1122

pytcp/tests/integration/protocols/tcp/test__tcp__session__keepalive.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__constants import TCP__DELAYED_ACK__DELAY_MS
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.socket import SO_KEEPALIVE, SOL_SOCKET, AddressFamily
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

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460

# Test-tunable keep-alive parameters. The production defaults
# (7200 s / 75 s / 9) are too coarse for unit-style integration
# tests; we patch them to small values so a full probe / tear-
# down cycle completes in a few hundred milliseconds of virtual
# time. The patched values are the SAME RFC-compliant shape -
# only the magnitudes change.
TEST__KEEPALIVE_IDLE_TIME_MS: int = 100
TEST__KEEPALIVE_PROBE_INTERVAL_MS: int = 50
TEST__KEEPALIVE_PROBE_MAX_COUNT: int = 3


class TestTcpKeepalive(TcpTestCase):
    """
    Integration tests for the RFC 1122 §4.2.3.6 keep-alive
    mechanism: opt-in semantics, idle-timer arming, probe wire
    shape, probe-ack reset, exhaustion tear-down.
    """

    def _patch_keepalive_constants(self) -> None:
        """
        Patch the production keep-alive constants to small test
        values so a full probe / tear-down cycle completes in a
        few hundred milliseconds of virtual time.
        """

        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__KEEPALIVE__IDLE_TIME_MS",
            TEST__KEEPALIVE_IDLE_TIME_MS,
        )
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__KEEPALIVE__PROBE_INTERVAL_MS",
            TEST__KEEPALIVE_PROBE_INTERVAL_MS,
        )
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__KEEPALIVE__PROBE_MAX_COUNT",
            TEST__KEEPALIVE_PROBE_MAX_COUNT,
        )

    def test__keepalive__disabled_by_default_no_probe_ever_fires(self) -> None:
        """
        Ensure that a session that has not been opted in via
        '_keepalive_enabled = True' does not emit any
        keep-alive probe regardless of how long the
        connection sits idle.

        Reference: RFC 1122 §4.2.3.6 (keep-alive defaults off).
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertFalse(
            session._keepalive.enabled,
            msg="RFC 1122 §4.2.3.6: '_keepalive_enabled' MUST default to False.",
        )

        idle_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS * 5)

        self.assertEqual(
            idle_tx,
            [],
            msg=(
                "RFC 1122 §4.2.3.6: a session with keep-alive disabled "
                "(default) MUST NOT emit any probe regardless of idle time."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="An idle keep-alive-disabled session must remain ESTABLISHED.",
        )

    def test__keepalive__enabled_idle_session_emits_probe_after_idle_time(self) -> None:
        """
        Ensure that when '_keepalive_enabled = True' and the
        connection has been idle (no inbound or outbound
        data) for 'TCP__KEEPALIVE__IDLE_TIME_MS', the session emits
        exactly one keep-alive probe.

        Reference: RFC 1122 §4.2.3.6 (idle-timer probe emission).
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive.enabled = True

        # Pre-boundary advance: the idle timer should NOT yet fire.
        pre_boundary_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS - 1)
        self.assertEqual(
            pre_boundary_tx,
            [],
            msg=(
                f"RFC 1122 §4.2.3.6: in the {TEST__KEEPALIVE_IDLE_TIME_MS - 1} ms "
                "before the idle timer expires, no keep-alive probe must be emitted."
            ),
        )

        # Boundary advance: idle timer expires, probe must fire.
        boundary_tx = self._advance(ms=2)
        self.assertEqual(
            len(boundary_tx),
            1,
            msg=(
                f"RFC 1122 §4.2.3.6: after {TEST__KEEPALIVE_IDLE_TIME_MS} ms of "
                "idle time, a keep-alive probe MUST be emitted (got "
                f"{len(boundary_tx)} TX frames)."
            ),
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="A keep-alive probe must not change the session state.",
        )

    def test__keepalive__probe_wire_shape_is_ack_with_seq_snd_nxt_minus_one(self) -> None:
        """
        Ensure the keep-alive probe wire shape is an ACK with
        'SEG.SEQ = SND.NXT - 1' and no payload.

        Reference: RFC 1122 §4.2.3.6 (probe SEG.SEQ = SND.NXT - 1).
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive.enabled = True

        snd_nxt_before = session._snd_seq.nxt
        rcv_nxt_before = session._rcv_seq.nxt

        boundary_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS + 1)
        self.assertEqual(
            len(boundary_tx),
            1,
            msg="Setup precondition: keep-alive probe must fire on idle expiry.",
        )

        probe = self._parse_tx(boundary_tx[0])

        self.assertEqual(
            probe.flags,
            frozenset({"ACK"}),
            msg=("RFC 1122 §4.2.3.6: keep-alive probe must carry ONLY the ACK " f"flag. Got flags={probe.flags!r}."),
        )
        self.assertEqual(
            probe.seq,
            (snd_nxt_before - 1) & 0xFFFF_FFFF,
            msg=(
                "RFC 1122 §4.2.3.6: keep-alive probe SEG.SEQ must equal "
                f"SND.NXT - 1 = {(snd_nxt_before - 1) & 0xFFFF_FFFF}; "
                f"got {probe.seq}."
            ),
        )
        self.assertEqual(
            probe.ack,
            rcv_nxt_before,
            msg=("Keep-alive probe SEG.ACK must reflect the current RCV.NXT " f"({rcv_nxt_before}); got {probe.ack}."),
        )
        self.assertEqual(
            probe.payload,
            b"",
            msg="RFC 1122 §4.2.3.6: keep-alive probe must carry no payload.",
        )

    def test__keepalive__peer_ack_of_probe_rearms_idle_timer(self) -> None:
        """
        Ensure that when peer responds to a keep-alive probe
        with an ACK at SND.NXT, the implementation treats it
        as a probe-ack and re-arms the idle timer for another
        full TCP__KEEPALIVE__IDLE_TIME_MS interval.

        Reference: RFC 1122 §4.2.3.6 (probe-ack rearms idle timer).
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive.enabled = True

        # First probe.
        first_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS + 1)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first keep-alive probe must fire on idle expiry.",
        )

        # Peer's probe-ack: ACK at our current SND.NXT, no data.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_seq.nxt,
            ack=session._snd_seq.nxt,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # Just before the next idle boundary, no probe yet.
        pre_boundary_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS - 1)
        self.assertEqual(
            pre_boundary_tx,
            [],
            msg=(
                "After a probe-ack, the idle timer must be re-armed for the full "
                f"{TEST__KEEPALIVE_IDLE_TIME_MS} ms - no further probes within that window."
            ),
        )

        # Past the next boundary, the second probe fires.
        second_boundary_tx = self._advance(ms=2)
        self.assertEqual(
            len(second_boundary_tx),
            1,
            msg=(
                "After the re-armed idle timer expires, a SECOND keep-alive probe "
                "MUST fire. Got "
                f"{len(second_boundary_tx)} TX frames (probe-ack did not re-arm)."
            ),
        )

    def test__keepalive__unanswered_probes_tear_down_connection_after_threshold(
        self,
    ) -> None:
        """
        Ensure that when peer is silent and
        'TCP__KEEPALIVE__PROBE_MAX_COUNT' consecutive probes go
        unanswered, the connection is torn down (state ->
        CLOSED).

        Reference: RFC 1122 §4.2.3.6 (probe-count tear-down).
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive.enabled = True

        # Run the full idle + probe-retransmit window. Total virtual
        # time: TCP__KEEPALIVE__IDLE_TIME_MS (initial wait) +
        # (TCP__KEEPALIVE__PROBE_MAX_COUNT + 1) * TCP__KEEPALIVE__PROBE_INTERVAL_MS
        # for safety past the tear-down boundary.
        total_ms = (
            TEST__KEEPALIVE_IDLE_TIME_MS + (TEST__KEEPALIVE_PROBE_MAX_COUNT + 1) * TEST__KEEPALIVE_PROBE_INTERVAL_MS
        )
        all_tx = self._advance(ms=total_ms)

        probe_count = len(all_tx)
        self.assertGreaterEqual(
            probe_count,
            TEST__KEEPALIVE_PROBE_MAX_COUNT,
            msg=(
                "RFC 1122 §4.2.3.6: at least TCP__KEEPALIVE__PROBE_MAX_COUNT="
                f"{TEST__KEEPALIVE_PROBE_MAX_COUNT} probes must be emitted before "
                f"the connection is declared dead. Got {probe_count} probes."
            ),
        )
        self.assertIsNot(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "RFC 1122 §4.2.3.6: after TCP__KEEPALIVE__PROBE_MAX_COUNT unanswered "
                "probes, the connection must be torn down (state must transition "
                "out of ESTABLISHED). State is still ESTABLISHED, indicating no "
                "tear-down occurred."
            ),
        )

    def test__keepalive__data_activity_resets_idle_timer(self) -> None:
        """
        Ensure that data-bearing peer activity resets the
        keep-alive idle timer; after a reset the timer
        re-arms to fire one full TCP__KEEPALIVE__IDLE_TIME_MS later.

        Reference: RFC 1122 §4.2.3.6 (idle timer counts time since last segment).
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive.enabled = True

        margin_ms = 30
        # Advance to just before the original idle boundary.
        pre_data_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS - margin_ms)
        self.assertEqual(
            pre_data_tx,
            [],
            msg="Setup: no probe must fire before the idle boundary.",
        )

        # Peer sends one byte. The session inline-ACKs at the
        # post-data RCV.NXT (so seq=SND.NXT, distinguishable from
        # a probe at seq=SND.NXT-1).
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_seq.nxt,
            ack=session._snd_seq.nxt,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X",
        )
        ack_tx = self._drive_rx(frame=peer_data)
        snd_nxt_after_data = session._snd_seq.nxt

        def _is_probe(frame: bytes) -> bool:
            """A probe is the ACK with seq=SND.NXT-1; data-ACKs use seq=SND.NXT."""
            return self._parse_tx(frame).seq != snd_nxt_after_data

        # Advance through the ORIGINAL boundary (now at
        # IDLE_TIME + margin total since handshake) and just past
        # it. If the timer was NOT reset, a probe would have fired
        # somewhere in this window.
        through_old_boundary_tx = self._advance(ms=2 * margin_ms)
        probes_before_new_boundary = sum(1 for frame in (ack_tx + through_old_boundary_tx) if _is_probe(frame))
        self.assertEqual(
            probes_before_new_boundary,
            0,
            msg=(
                "RFC 1122 §4.2.3.6: data activity must reset the idle timer; "
                f"no keep-alive probe must fire within {2 * margin_ms} ms after a "
                f"peer data segment (i.e., past the ORIGINAL idle boundary). "
                f"Got {probes_before_new_boundary} probe(s)."
            ),
        )

        # Advance to one tick past the EFFECTIVE new boundary.
        # Peer data triggers the RFC 1122 §4.2.3.2 delayed-ACK
        # timer (TCP__DELAYED_ACK__DELAY_MS ms). When that timer fires,
        # the session emits its inline ACK to peer's data; that
        # outbound ACK itself counts as activity for keep-alive
        # purposes and resets the idle timer to TCP__KEEPALIVE__IDLE_TIME_MS.
        # The keep-alive probe therefore fires at
        # 'data_arrival + TCP__DELAYED_ACK__DELAY_MS + TCP__KEEPALIVE__IDLE_TIME_MS'.
        # We are currently '2 * margin_ms' past data arrival, so
        # the remaining advance is the difference.
        new_boundary_offset = TCP__DELAYED_ACK__DELAY_MS + TEST__KEEPALIVE_IDLE_TIME_MS
        remaining_to_new_boundary = new_boundary_offset - 2 * margin_ms + 1
        new_boundary_tx = self._advance(ms=remaining_to_new_boundary)
        probes_at_new_boundary = sum(1 for frame in new_boundary_tx if _is_probe(frame))
        self.assertEqual(
            probes_at_new_boundary,
            1,
            msg=(
                "RFC 1122 §4.2.3.6: after data activity resets the idle timer, "
                "the timer must re-arm and fire ONE probe at the new effective "
                f"boundary ({new_boundary_offset} ms after data arrival, "
                "accounting for the §4.2.3.2 delayed-ACK that the session sends "
                f"in response to peer's data). Got {probes_at_new_boundary} "
                "probe(s) - the timer either disarmed entirely or never fired."
            ),
        )


class TestTcpKeepaliveOverrides(TcpTestCase):
    """
    Integration tests for the per-connection keep-alive
    overrides (TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT).
    Verifies the override fields on TcpSession actually change
    the timer behaviour at runtime - the helpers must read
    'override or constant', not just the constant.
    """

    def _patch_keepalive_constants(self) -> None:
        """
        Patch the global defaults to small test values so we can
        prove the override takes precedence over them. The
        override values used in each test are DIFFERENT from these
        patched defaults so a regression that ignored the override
        would surface as a wrong-timing failure.
        """

        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__KEEPALIVE__IDLE_TIME_MS",
            TEST__KEEPALIVE_IDLE_TIME_MS,
        )
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__KEEPALIVE__PROBE_INTERVAL_MS",
            TEST__KEEPALIVE_PROBE_INTERVAL_MS,
        )
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__KEEPALIVE__PROBE_MAX_COUNT",
            TEST__KEEPALIVE_PROBE_MAX_COUNT,
        )

    def test__keepalive_overrides__idle_override_takes_precedence_over_constant(
        self,
    ) -> None:
        """
        Ensure '_keepalive_idle_override' makes
        '_keepalive_arm_idle' use the per-connection value
        instead of 'tcp__constants.TCP__KEEPALIVE__IDLE_TIME_MS'.

        Reference: RFC 1122 §4.2.3.6 (per-connection keep-alive timing).
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive.enabled = True
        # Override: half the patched default, so probe should fire
        # at 50 ms (override) NOT 100 ms (constant).
        override_ms = TEST__KEEPALIVE_IDLE_TIME_MS // 2
        session._keepalive.idle_override = override_ms

        # Pre-boundary advance: no probe yet.
        pre_boundary_tx = self._advance(ms=override_ms - 1)
        self.assertEqual(
            pre_boundary_tx,
            [],
            msg=(f"Setup precondition: no probe within {override_ms - 1} ms " f"of the override boundary."),
        )

        # Past the override boundary: exactly one probe.
        boundary_tx = self._advance(ms=2)
        self.assertEqual(
            len(boundary_tx),
            1,
            msg=(
                f"Override TCP_KEEPIDLE={override_ms} ms must take precedence "
                "over the patched TCP__KEEPALIVE__IDLE_TIME_MS constant. Probe must fire "
                f"at the override boundary; got {len(boundary_tx)} probe(s) "
                f"after {override_ms + 1} ms of idle."
            ),
        )


class TestTcpKeepaliveListenerForkInheritance(TcpTestCase):
    """
    Integration test for the listener-fork keep-alive inheritance
    path: a listening socket that has set 'SO_KEEPALIVE' via
    'setsockopt' MUST produce accept()'d child sockets / sessions
    that inherit the flag, so the entire fork lineage benefits
    from the per-listener keep-alive opt-in.
    """

    def _patch_keepalive_constants(self) -> None:
        """
        Patch keep-alive timer constants to small test values so a
        full idle / probe cycle completes in a few hundred
        milliseconds of virtual time.
        """

        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__KEEPALIVE__IDLE_TIME_MS",
            TEST__KEEPALIVE_IDLE_TIME_MS,
        )
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__KEEPALIVE__PROBE_INTERVAL_MS",
            TEST__KEEPALIVE_PROBE_INTERVAL_MS,
        )
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TCP__KEEPALIVE__PROBE_MAX_COUNT",
            TEST__KEEPALIVE_PROBE_MAX_COUNT,
        )

    def test__keepalive__listener_fork_inherits_so_keepalive(self) -> None:
        """
        Ensure that a listening 'TcpSocket' with
        'setsockopt(SO_KEEPALIVE, 1)' produces an accept()'d
        child socket whose '_so_keepalive' is True AND whose
        underlying TcpSession's '_keepalive_enabled' is True.

        Reference: RFC 1122 §4.2.3.6 (per-connection keep-alive opt-in inheritance).
        """

        self._patch_keepalive_constants()
        self._force_iss(0x3000)

        # Build a listening TcpSocket with SO_KEEPALIVE set, then
        # construct its TcpSession the way 'TcpSocket.listen()'
        # would (mirroring the 'handshake__passive' fixture but
        # going through setsockopt to exercise the propagation).
        listen_socket = TcpSocket(family=AddressFamily.INET4)
        listen_socket.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        listen_socket._local_ip_address = STACK__IP
        listen_socket._local_port = STACK__PORT
        listen_socket._remote_ip_address = Ip4Address()
        listen_socket._remote_port = 0
        listen_session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=listen_socket,
        )
        listen_socket._tcp_session = listen_session
        # Mirror what TcpSocket.listen() does post-construction:
        # propagate SO_KEEPALIVE before driving the FSM into LISTEN.
        listen_session._keepalive.enabled = listen_socket._so_keepalive
        stack.sockets[listen_socket.socket_id] = listen_socket
        listen_session.tcp_fsm(syscall=SysCall.LISTEN)

        self.assertIs(
            listen_session._keepalive.enabled,
            True,
            msg=(
                "Setup precondition: the listening session must have "
                "'_keepalive_enabled = True' so the fork pivot can "
                "inherit it."
            ),
        )

        # Drive a peer SYN. 'tcp__fsm__listen' performs the in-place
        # pivot: 'listen_session' becomes the child session, a fresh
        # listening session takes over the listening role, and a new
        # child socket is created for the application's eventual
        # 'accept()'.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000,
            ack=0,
            flags=("SYN",),
            win=64240,
            mss=1460,
        )
        self._drive_rx(frame=peer_syn)

        # After the pivot:
        #   - 'listen_session' is now the child session (mutated in-
        #     place); it must retain its '_keepalive_enabled = True'.
        #   - 'listen_session._socket' is now the NEW child socket;
        #     'child._so_keepalive' must be True (inherited from the
        #     listening parent).
        #   - 'listen_socket._tcp_session' is now the FRESH listening
        #     session; its '_keepalive_enabled' must also be True so
        #     subsequent forks inherit too.
        child_session = listen_session
        child_socket = child_session._socket
        fresh_listen_session = listen_socket._tcp_session

        self.assertIs(
            child_session._keepalive.enabled,
            True,
            msg=(
                "Listener-fork must preserve '_keepalive_enabled' on the "
                "child session (which is the in-place-mutated original)."
            ),
        )
        self.assertIs(
            child_socket._so_keepalive,
            True,
            msg=(
                "The new child TcpSocket created for the accepted "
                "connection must inherit '_so_keepalive' from the "
                "listening parent socket."
            ),
        )
        self.assertIs(
            fresh_listen_session._keepalive.enabled,
            True,
            msg=(
                "The fresh listening session created during the fork must "
                "inherit '_keepalive_enabled' so the NEXT incoming SYN's "
                "child also benefits from keep-alive."
            ),
        )

        # End-to-end: drive the third leg of the handshake to bring
        # the child session into ESTABLISHED, then advance past
        # TCP__KEEPALIVE__IDLE_TIME_MS and assert exactly one probe fires -
        # proving keep-alive is FUNCTIONALLY armed on the accepted
        # child, not just configured.
        self._advance(ms=1)  # let SYN+ACK fire from SYN_RCVD timer branch
        peer_third_leg_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4001,
            ack=child_session._snd_seq.nxt,
            flags=("ACK",),
            win=64240,
        )
        self._drive_rx(frame=peer_third_leg_ack)
        self.assertIs(
            child_session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: child session must reach ESTABLISHED.",
        )

        # Advance past the keep-alive idle boundary. Filter probes
        # (seq=SND.NXT-1) from any incidental data-acks (seq=SND.NXT).
        snd_nxt_when_idle = child_session._snd_seq.nxt

        def _is_probe(frame: bytes) -> bool:
            return self._parse_tx(frame).seq != snd_nxt_when_idle

        all_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS + 1)
        probe_count = sum(1 for frame in all_tx if _is_probe(frame))
        self.assertEqual(
            probe_count,
            1,
            msg=(
                "After listener-fork inheritance, the accepted child must "
                "fire exactly one keep-alive probe past TCP__KEEPALIVE__IDLE_TIME_MS "
                f"of idle time. Got {probe_count} probe(s)."
            ),
        )


class TestTcpKeepaliveCrossRfcRecovery(TcpTestCase):
    """
    Cross-RFC interaction (Phase B1 of the test-coverage audit):
    a keep-alive probe fired while the session is in fast
    recovery MUST NOT clear '_recovery_point' or otherwise
    interfere with the RFC 5681 §3.2 / RFC 6582 NewReno
    recovery state. The probe is a special-purpose ACK at
    'SND.NXT - 1'; the recovery machinery uses 'SND.UNA' and
    'SND.MAX' as anchors and is independent.
    """

    def test__keepalive__probe_during_fast_recovery_preserves_recovery_point(self) -> None:
        """
        Ensure that a keep-alive probe fired while the
        session is in fast recovery does not clear
        '_recovery_point' or otherwise interfere with the
        fast-recovery state.

        Reference: RFC 1122 §4.2.3.6 (keep-alive probe semantics).
        Reference: RFC 5681 §3.2 (fast recovery state independence).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Get N segments in flight then enter recovery.
        n_segments = 5
        payload = b"x" * (n_segments * PEER__MSS)
        session.send(data=payload)
        for _ in range(n_segments):
            self._advance(ms=1)

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
        self._advance(ms=1)

        recovery_point_pre = session._cc.recovery_point
        cwnd_pre = session._cc.cwnd
        ssthresh_pre = session._cc.ssthresh
        self.assertNotEqual(
            recovery_point_pre,
            0,
            msg="Setup invariant: '_recovery_point' MUST be set after entering fast recovery.",
        )

        # Fire a keep-alive probe directly. '_keepalive_tick'
        # synthesizes the wire-shape probe (ACK at SND.NXT - 1)
        # without touching '_recovery_point' or cwnd.
        session._keepalive.enabled = True
        session._keepalive_tick()

        self.assertEqual(
            session._cc.recovery_point,
            recovery_point_pre,
            msg=(
                "Cross-RFC: a keep-alive probe MUST NOT clear "
                "'_recovery_point'. The probe is independent of "
                "RFC 5681 §3.2 fast-recovery state."
            ),
        )
        self.assertEqual(
            session._cc.cwnd,
            cwnd_pre,
            msg="Cross-RFC: a keep-alive probe MUST NOT change cwnd.",
        )
        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_pre,
            msg="Cross-RFC: a keep-alive probe MUST NOT change ssthresh.",
        )
