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
This module contains integration tests for the TCP passive-open
('listen' / 'accept') side of the 'TcpSession' state machine,
covering the server role of the three-way handshake defined in
RFC 9293 §3.10.7.2.

The tests in this file drive the LISTEN-side FSM directly via
'tcp_fsm(syscall=SysCall.LISTEN)' rather than going through the
blocking 'TcpSocket.accept()' BSD-API wrapper - the integration
scope is the session, not the socket facade. The full RX/TX path
is exercised end to end: outbound segments flow through the real
'PacketHandler._phtx_tcp -> _phtx_ip4 -> _phtx_ethernet' chain and
land in the mocked 'TxRing'; inbound segments are fed into the real
'_phrx_ethernet' entry point and dispatched to the listening socket
via the real 'TcpSocket.process_tcp_packet'.

A passive-open session has a more complex life cycle than the active-
open path: the original listening 'TcpSession' mutates IN PLACE into
a child session bound to the incoming peer's 4-tuple, and a fresh
'TcpSession' is created to take over the wildcarded LISTEN role
(see '_tcp_fsm_listen' for the in-place transformation). Tests in
this file therefore assert against both objects: the listening
socket / its NEW session ('still in LISTEN, ready for the next
SYN'), and the newly-spawned child socket / the OLD-now-child
session ('transitioned to SYN_RCVD, ready to emit SYN+ACK').

Reference RFCs:
    RFC 9293 §3.10.7.2   Passive open / LISTEN state processing
    RFC 9293 §3.5.1      Three-way handshake
    RFC 9293 §3.7.1      MSS option / segment-size negotiation
    RFC 6691 §2          MSS calculation from link MTU
    RFC 5961 §4          SYN-on-established challenge ACK

pytcp/tests/integration/protocols/tcp/test__tcp__session__handshake__passive.py

ver 3.0.9
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.socket_id import SocketId
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing chosen so log output and byte-frame comments
# stay readable. STACK is the host running the SUT (the listener);
# PEER is the 'HOST_A' fixture that has a working ARP entry.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
LISTEN__PORT: int = 80
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 33000

# Initial sequence numbers chosen well clear of the 32-bit wrap so
# this baseline file exercises ordinary modular comparisons; the
# wraparound corner is covered separately in the seq_wraparound file.
LOCAL__ISS: int = 0x0000_3000
PEER__ISS: int = 0x0000_4000

# Peer's advertised receive window on the SYN it sends.
PEER__WIN: int = 64240

# Peer's MSS option value on the SYN. 1460 is the canonical IPv4
# Ethernet MSS (1500 MTU - 20 byte IPv4 header - 20 byte TCP header).
PEER__MSS: int = 1460


class TestTcpPassiveOpen__Handshake(TcpTestCase):
    """
    Integration tests for the server-side three-way handshake driven
    out of 'TcpSession' in the passive-open path.
    """

    def _make_listen_session(self, *, iss: int) -> tuple[TcpSocket, TcpSession]:
        """
        Build a 'TcpSocket' / 'TcpSession' pair wired up the way
        'TcpSocket.listen()' would wire them - bound to the wildcard
        listen 4-tuple '(STACK__IP, LISTEN__PORT, *, 0)', ISS pinned
        deterministically via '_force_iss', socket registered in
        'stack.sockets' so the packet handler's RX listener-match
        dispatch finds it on the second pass.

        Returns '(listen_socket, listen_session)'. After
        '_tcp_fsm_listen' processes an incoming SYN, the *session*
        attached to the socket will be replaced (the original session
        mutates in place into the child); callers should re-resolve
        the listening session via 'listen_socket._tcp_session' after
        any RX drive.
        """

        self._force_iss(iss)

        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = LISTEN__PORT
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0

        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=LISTEN__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock

        # Drive LISTEN syscall: state CLOSED -> LISTEN.
        session.tcp_fsm(syscall=SysCall.LISTEN)

        return sock, session  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def _child_socket_id(self) -> SocketId:
        """
        Construct the exact-match 'SocketId' the packet handler
        computes for an inbound segment from PEER to STACK on the
        listening port. After the handshake spawns a child socket
        this id is what 'stack.sockets' will key the child by.
        """

        return SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=STACK__IP,
            local_port=LISTEN__PORT,
            remote_address=PEER__IP,
            remote_port=PEER__PORT,
        )

    def test__passive_open__syn_to_listen_spawns_child_and_emits_syn_ack(self) -> None:
        """
        Ensure that when a fresh SYN arrives at a listening
        socket, the LISTEN-state FSM forks a child session
        bound to peer's 4-tuple, transitions the child to
        SYN_RCVD, and emits a SYN+ACK with seq=LOCAL_ISS,
        ack=PEER_ISS+1, MSS+WSCALE+TSopt+SACK-Permitted
        options. The listening socket remains available to
        accept further connections.

        Reference: RFC 9293 §3.5 (passive open, second leg of three-way handshake).
        Reference: RFC 9293 §3.10.7.2 (LISTEN segment processing).
        """

        listen_socket, original_session = self._make_listen_session(iss=LOCAL__ISS)

        self.assertIs(
            original_session.state,
            FsmState.LISTEN,
            msg="Setup precondition: listening session must be in LISTEN.",
        )

        # Peer sends a SYN to (STACK__IP, LISTEN__PORT). Build the frame
        # with the peer-specific 4-tuple and the customary handshake
        # options.
        syn_frame = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=syn_frame)

        self.assertEqual(
            tx_frames,
            [],
            msg=(
                "'_tcp_fsm_listen' must not emit any segment inline - "
                "the SYN+ACK is gated on the next timer tick by the "
                "SYN_RCVD '_transmit_data' branch (matches the same "
                "tick-gated pattern as the active-open initial SYN)."
            ),
        )

        # The listening socket has a fresh session in LISTEN now,
        # while the original session has mutated into the child bound
        # to the peer's 4-tuple and is sitting in SYN_RCVD.
        self.assertIn(
            listen_socket.socket_id,
            stack.sockets,
            msg=(
                "The listening socket must remain registered in "
                "'stack.sockets' under its wildcard id so subsequent "
                "SYNs from other peers also reach the listener."
            ),
        )
        self.assertIs(
            stack.sockets[listen_socket.socket_id],
            listen_socket,
            msg="The listening-socket registration must point at the same TcpSocket object.",
        )

        new_listen_session = listen_socket._tcp_session
        self.assertIsNotNone(
            new_listen_session,
            msg="The listening socket must have a fresh session attached after spawning the child.",
        )
        assert new_listen_session is not None  # narrow for mypy
        self.assertIs(
            new_listen_session.state,
            FsmState.LISTEN,
            msg=(
                "After spawning a child, the listening socket's "
                "session must be back in LISTEN state, ready to "
                "accept further inbound SYNs."
            ),
        )
        self.assertIsNot(
            new_listen_session,
            original_session,
            msg=(
                "'_tcp_fsm_listen' must replace the listening session - "
                "the original session has been mutated into the child "
                "bound to the peer's 4-tuple."
            ),
        )

        # The child socket / child session lives under the peer-
        # specific exact-match id.
        child_socket_id = self._child_socket_id()
        self.assertIn(
            child_socket_id,
            stack.sockets,
            msg=(
                "A new child socket bound to the peer's 4-tuple must "
                "be registered in 'stack.sockets' so subsequent "
                "segments from the same peer reach this child rather "
                "than the listener."
            ),
        )
        child_socket = stack.sockets[child_socket_id]
        assert isinstance(child_socket, TcpSocket)
        self.assertIs(
            child_socket._parent_socket,
            listen_socket,
            msg=(
                "The child socket's '_parent_socket' must point at the "
                "original listening socket so the eventual third-leg "
                "ACK can deposit the accepted child onto the listener's "
                "accept queue."
            ),
        )

        child_session = child_socket._tcp_session
        assert child_session is not None
        self.assertIs(
            child_session,
            original_session,
            msg=(
                "The child session must BE the originally returned "
                "session object (mutated in place) - this is how "
                "'_tcp_fsm_listen' implements the LISTEN -> SYN_RCVD "
                "transformation."
            ),
        )
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg=(
                "After processing the inbound SYN, the child session "
                "must be in SYN_RCVD per RFC 9293 §3.10.7.2, awaiting "
                "the peer's third-leg ACK."
            ),
        )
        self.assertEqual(
            child_session._snd_seq.ini,
            LOCAL__ISS,
            msg=(
                "The child session must inherit the deterministic ISS "
                "we forced via '_force_iss', so the SYN+ACK on the wire "
                "is reproducible."
            ),
        )
        self.assertEqual(
            child_session._snd_seq.nxt,
            LOCAL__ISS,
            msg=(
                "Before the SYN+ACK fires on the next timer tick, "
                "'_snd_nxt' must equal '_snd_ini' - the SYN's one byte "
                "of sequence space is consumed only when the segment "
                "is actually transmitted."
            ),
        )
        self.assertEqual(
            child_session._rcv_seq.nxt,
            PEER__ISS + 1,
            msg=(
                "After processing the peer's SYN, '_rcv_nxt' must equal "
                "PEER__ISS + 1 - consuming the SYN's one byte of "
                "sequence space (RFC 9293 §3.4)."
            ),
        )

        # On the first virtual-clock tick, the child session's SYN_RCVD
        # timer handler emits the SYN+ACK.
        tick_tx = self._advance(ms=1)
        self.assertEqual(
            len(tick_tx),
            1,
            msg=("Exactly one TX frame (the SYN+ACK) must be emitted on " "the first SYN_RCVD timer tick."),
        )

        syn_ack = self._parse_tx(tick_tx[0])
        self._assert_segment(
            syn_ack,
            flags=frozenset({"SYN", "ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=1460,
            wscale=None,
            win=65535,
        )

        self.assertEqual(
            child_session._snd_seq.nxt,
            LOCAL__ISS + 1,
            msg=(
                "After the SYN+ACK is transmitted, '_snd_nxt' must "
                "advance by one to consume the SYN's sequence space "
                "(RFC 9293 §3.4)."
            ),
        )
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg=(
                "Sending the SYN+ACK does not move us out of SYN_RCVD; "
                "we wait for the peer's third-leg ACK before "
                "transitioning to ESTABLISHED."
            ),
        )

    def test__passive_open__syn_ack_to_listen_emits_rst(self) -> None:
        """
        Ensure a SYN+ACK arriving on a listening socket
        triggers a bare RST with seq=SEG.ACK. The LISTEN
        state accepts only a bare SYN; any ACK-bearing
        segment cannot belong to a connection still in
        LISTEN. The listener remains in LISTEN, no child is
        spawned, and no entry is added to 'stack.sockets'
        under the peer-specific id.

        Reference: RFC 9293 §3.10.7.2 (LISTEN segment processing, ACK rejection).
        Reference: RFC 9293 §3.10.7.1 (RST shape for ACK-bearing no-socket-match).
        """

        listen_socket, listen_session = self._make_listen_session(iss=LOCAL__ISS)
        bogus_ack_value = 0x0000_CAFE

        rogue_frame = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=bogus_ack_value,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=rogue_frame)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "An ACK-bearing segment arriving on a listening socket "
                "must elicit exactly one outbound segment (a bare RST) "
                "per RFC 9293 §3.10.7.2 step 2. Got "
                f"{len(tx_frames)} TX frames."
            ),
        )

        rst = self._parse_tx(tx_frames[0])
        self._assert_segment(
            rst,
            flags=frozenset({"RST"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=bogus_ack_value,
            ack=0,
            payload=b"",
            mss=None,
            wscale=None,
        )

        self.assertIn(
            listen_socket.socket_id,
            stack.sockets,
            msg=(
                "The listening socket must remain registered after "
                "rejecting a rogue SYN+ACK - the listener is not "
                "disturbed by spurious ACK-bearing traffic."
            ),
        )
        self.assertIs(
            stack.sockets[listen_socket.socket_id],
            listen_socket,
            msg=(
                "The listening socket registration must still point at "
                "the same TcpSocket object - no replacement happened."
            ),
        )
        self.assertIs(
            listen_socket._tcp_session,
            listen_session,
            msg=(
                "The listening socket's session must be the same "
                "object we started with - rejecting a rogue ACK does "
                "not spawn a child or replace the listener (those side "
                "effects only follow a legal bare SYN)."
            ),
        )
        self.assertIs(
            listen_session.state,
            FsmState.LISTEN,
            msg=(
                "Rejecting a rogue ACK-bearing segment must not change "
                "the listener's state - it stays in LISTEN, ready for "
                "the next legitimate SYN."
            ),
        )

        # No child socket should have been registered under the
        # peer-specific exact-match id.
        self.assertNotIn(
            self._child_socket_id(),
            stack.sockets,
            msg=(
                "No child socket may be registered after rejecting a "
                "rogue ACK-bearing segment - the rejection happens "
                "before any session-spawning code runs."
            ),
        )

    def test__passive_open__syn_with_payload_to_listen_queues_data_and_acks_it(self) -> None:
        """
        Ensure that an initial SYN carrying piggybacked data
        on a listening socket is accepted: the child session
        transitions to SYN_RCVD, the data is queued into
        '_rx_buffer', RCV.NXT advances past the SYN's one
        byte and every byte of payload, and the outbound
        SYN+ACK acknowledges the data so the peer does not
        retransmit. The listening socket remains in LISTEN.

        Reference: RFC 9293 §3.10.7.2 (LISTEN segment processing, SYN with data).
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)
        payload = b"hello-world!"

        syn_with_data = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            payload=payload,
        )

        # Driving the SYN-with-data must not produce any inline TX
        # (matching the bare-SYN case - SYN+ACK is gated on the next
        # timer tick by the SYN_RCVD '_transmit_data' branch).
        inline_tx = self._drive_rx(frame=syn_with_data)
        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "'_tcp_fsm_listen' must not emit any segment inline "
                "even for SYN-with-data; the SYN+ACK fires on the "
                "next timer tick like the bare-SYN case."
            ),
        )

        # The child session is the original (mutated-in-place) listening
        # session, now bound to the peer's 4-tuple and in SYN_RCVD.
        child_socket = stack.sockets[self._child_socket_id()]
        assert isinstance(child_socket, TcpSocket)
        child_session = child_socket._tcp_session
        assert child_session is not None

        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg=(
                "Receiving a SYN-with-data must still transition the "
                "child session to SYN_RCVD per RFC 9293 §3.10.7.2 "
                "step 3; data does not gate the SYN handling."
            ),
        )
        self.assertEqual(
            child_session._rcv_seq.nxt,
            PEER__ISS + 1 + len(payload),
            msg=(
                "After processing a SYN-with-data, '_rcv_nxt' must "
                "advance past BOTH the SYN's one byte AND every byte "
                "of payload. Got "
                f"{child_session._rcv_seq.nxt:#x}, expected "
                f"{PEER__ISS + 1 + len(payload):#x}. "
                'RFC 9293 §3.10.7.2 step 3: "any other incoming '
                "control or data (combined with SYN) will be "
                'processed in the SYN-RECEIVED state".'
            ),
        )
        self.assertEqual(
            bytes(child_session._rx_buffer),
            payload,
            msg=(
                "The piggybacked payload must be queued into the "
                "child session's '_rx_buffer' so it is available to "
                "the application once ESTABLISHED is reached, rather "
                "than forcing the peer to retransmit it after the "
                "handshake completes."
            ),
        )

        # On the next tick, the SYN+ACK fires acknowledging both SYN
        # and data.
        tick_tx = self._advance(ms=1)
        self.assertEqual(
            len(tick_tx),
            1,
            msg=(
                "Exactly one TX frame (the SYN+ACK) must be emitted "
                "on the first SYN_RCVD timer tick after a SYN-with-data."
            ),
        )

        syn_ack = self._parse_tx(tick_tx[0])
        self._assert_segment(
            syn_ack,
            flags=frozenset({"SYN", "ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS,
            ack=PEER__ISS + 1 + len(payload),
            payload=b"",
            mss=1460,
            wscale=None,
            # Advertised window reflects '_rx_buffer' occupancy per
            # RFC 9293 §3.8.6: 65535 max minus the SYN-piggybacked
            # bytes now sitting in the buffer awaiting ESTABLISHED
            # delivery to the application.
            win=65535 - len(payload),
        )

        # The listening socket still accepts further connections.
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg=("Processing a SYN-with-data must leave the listener " "available to accept further connections."),
        )

    def test__passive_open__third_leg_ack_with_payload_completes_handshake_and_delivers_data(self) -> None:
        """
        Ensure peer's third-leg ACK arriving in SYN_RCVD with
        piggybacked data completes the handshake AND queues
        the data: state transitions to ESTABLISHED, the data
        is enqueued into '_rx_buffer', RCV.NXT advances past
        the payload, and we emit an ACK acknowledging the
        data so peer does not retransmit.

        Reference: RFC 9293 §3.10.7.4 (SYN-RECEIVED ACK processing with text).
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        # Stage 1: drive SYN -> child in SYN_RCVD; tick SYN+ACK out.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self._advance(ms=1)  # SYN+ACK fires.

        child_socket = stack.sockets[self._child_socket_id()]
        assert isinstance(child_socket, TcpSocket)
        child_session = child_socket._tcp_session
        assert child_session is not None
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: child must be in SYN_RCVD after the SYN+ACK tick.",
        )
        # Clear the SYN+ACK from the TX log so the assertions below
        # only reflect the third-leg-ACK-with-data response.
        self._frames_tx.clear()

        # Stage 2: peer sends third-leg ACK with piggybacked data.
        payload = b"hello-from-peer"
        third_leg_with_data = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=payload,
        )
        tx_frames = self._drive_rx(frame=third_leg_with_data)

        # Stage 3: assert ESTABLISHED + data delivered.
        self.assertIs(
            child_session.state,
            FsmState.ESTABLISHED,
            msg=(
                "A SYN_RCVD third-leg ACK whose 'ack' is in "
                "(SND.UNA, SND.NXT] MUST transition the session "
                "to ESTABLISHED, regardless of whether the segment "
                f"also carries data. Got state: {child_session.state!r}."
            ),
        )
        self.assertEqual(
            bytes(child_session._rx_buffer),
            payload,
            msg=(
                "Data piggybacked on the third-leg ACK MUST be "
                "enqueued into the child session's '_rx_buffer' "
                "so the application can receive it via 'recv()'. "
                f"Got: {bytes(child_session._rx_buffer)!r}, "
                f"expected: {payload!r}."
            ),
        )
        self.assertEqual(
            child_session._rcv_seq.nxt,
            PEER__ISS + 1 + len(payload),
            msg=(
                "'RCV.NXT' MUST advance past every byte of the "
                "third-leg ACK's payload. Got: "
                f"{child_session._rcv_seq.nxt:#x}, expected: "
                f"{PEER__ISS + 1 + len(payload):#x}."
            ),
        )
        # The cumulative ACK acknowledging the data should fire on
        # this same drive (RFC 9293 §3.10.7.4 step 7: 'Send an
        # acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT>
        # <CTL=ACK>'). Without it, peer keeps retransmitting their
        # data segment until our next outbound segment piggybacks
        # the cumulative ACK - which may take a while.
        self.assertGreaterEqual(
            len(tx_frames),
            1,
            msg=(
                "After enqueueing the third-leg ACK's payload "
                "the receiver MUST send an acknowledgment so peer "
                "learns the data is received. Got "
                f"{len(tx_frames)} TX frame(s)."
            ),
        )
        if tx_frames:
            cum_ack = self._parse_tx(tx_frames[-1])
            self.assertEqual(
                cum_ack.flags,
                frozenset({"ACK"}),
                msg=("The reply must be a bare ACK (no SYN / FIN / RST flags) per RFC 9293 §3.10.7.4 step 7."),
            )
            self.assertEqual(
                cum_ack.seq,
                LOCAL__ISS + 1,
                msg=("The reply's SEQ must equal SND.NXT after our SYN+ACK was sent (= LOCAL__ISS + 1)."),
            )
            self.assertEqual(
                cum_ack.ack,
                PEER__ISS + 1 + len(payload),
                msg=(
                    "The reply's ACK must acknowledge every byte of "
                    "peer's third-leg payload. Got: "
                    f"{cum_ack.ack:#x}, expected: "
                    f"{PEER__ISS + 1 + len(payload):#x}."
                ),
            )

        # The listening socket is unaffected.
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg=("Third-leg ACK on the child session must not disturb the listener."),
        )

    def test__passive_open__syn_without_mss_option_defaults_send_mss_to_536(self) -> None:
        """
        Ensure that when an inbound SYN omits the MSS option,
        the listener falls back to the IPv4 default send MSS
        of 536 octets (576-byte default IPv4 MTU minus 20-byte
        IPv4 header minus 20-byte TCP header). The outbound
        SYN+ACK still advertises our own MTU-derived receive
        MSS (1460); '_snd_mss' on the child session is 536.

        Reference: RFC 9293 §3.7.1 (default send MSS = 536 on IPv4).
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        syn_no_mss = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=None,  # explicitly omit MSS option from outbound TCP options
        )

        self._drive_rx(frame=syn_no_mss)

        # The child session is the (mutated-in-place) original session.
        child_socket = stack.sockets[self._child_socket_id()]
        assert isinstance(child_socket, TcpSocket)
        child_session = child_socket._tcp_session
        assert child_session is not None

        self.assertEqual(
            child_session._win.snd_mss,
            536,
            msg=(
                "When the peer's SYN omits the MSS option, "
                "'_snd_mss' must default to the RFC 9293 §3.7.1 "
                "IPv4 fallback of 536 octets (= 576 default MTU - 20 "
                "IPv4 hdr - 20 TCP hdr). Got "
                f"_snd_mss={child_session._win.snd_mss}."
            ),
        )
        self.assertEqual(
            child_session._win.rcv_mss,
            1460,
            msg=(
                "'_rcv_mss' is derived from our own MTU "
                "(stack.interface_mtu - 40 for IPv4) and is unaffected "
                "by what the peer advertises - it determines the value "
                "we send in our outbound MSS option."
            ),
        )

        # On the next tick, the SYN+ACK fires advertising OUR MSS
        # regardless of peer's omission.
        tick_tx = self._advance(ms=1)
        self.assertEqual(
            len(tick_tx),
            1,
            msg="Exactly one TX frame (the SYN+ACK) must be emitted on the first SYN_RCVD timer tick.",
        )

        syn_ack = self._parse_tx(tick_tx[0])
        self._assert_segment(
            syn_ack,
            flags=frozenset({"SYN", "ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=1460,  # our advertised MSS based on our MTU; absence on peer's SYN does not gate ours
            wscale=None,
            win=65535,
        )

        # Listener still accepts further connections.
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg=(
                "Processing a SYN without MSS option must leave the "
                "listener available to accept further connections."
            ),
        )

    def test__passive_open__concurrent_syns_from_distinct_peers_spawn_independent_children(self) -> None:
        """
        Ensure that a single listening socket can serve multiple
        simultaneous in-flight handshakes correctly: three SYNs from
        three distinct 4-tuples must spawn three independent child
        sessions, each in SYN_RCVD with its own '_rcv_nxt' tracking
        the corresponding peer's ISN, while the listening
        socket remains available throughout to accept further
        connections. Three SYNs from distinct source ports
        produce three independent children in SYN_RCVD plus
        one still-listening socket, and on the next tick three
        independent SYN+ACKs fire — each acknowledging its
        own peer's ISN.

        Reference: RFC 9293 §3.10.7.2 (LISTEN segment processing, child TCB spawning).
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        # (peer_port, peer_iss) tuples - same source IP HOST_A__IP
        # for all three so the mocked ARP cache resolves cleanly,
        # different source ports so each 4-tuple is unique.
        peers: list[tuple[int, int]] = [
            (33000, 0x0000_4000),
            (33001, 0x0000_5000),
            (33002, 0x0000_6000),
        ]

        for peer_port, peer_iss in peers:
            syn_frame = build_tcp4(
                sport=peer_port,
                dport=LISTEN__PORT,
                seq=peer_iss,
                ack=0,
                flags=("SYN",),
                win=PEER__WIN,
                mss=PEER__MSS,
            )
            inline_tx = self._drive_rx(frame=syn_frame)
            self.assertEqual(
                inline_tx,
                [],
                msg=(
                    f"SYN from HOST_A:{peer_port} must not produce any "
                    f"inline TX - SYN+ACK is gated on the next timer tick."
                ),
            )

        # Three children must now be registered, each under its own
        # peer-specific exact-match socket-id.
        for peer_port, peer_iss in peers:
            child_id = SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
                local_address=STACK__IP,
                local_port=LISTEN__PORT,
                remote_address=PEER__IP,
                remote_port=peer_port,
            )
            self.assertIn(
                child_id,
                stack.sockets,
                msg=(
                    f"Child socket for HOST_A:{peer_port} must be "
                    f"registered in 'stack.sockets'. Concurrent "
                    f"handshakes must not overwrite each other's "
                    f"registrations."
                ),
            )
            child_socket = stack.sockets[child_id]
            assert isinstance(child_socket, TcpSocket)
            child_session = child_socket._tcp_session
            assert child_session is not None
            self.assertIs(
                child_session.state,
                FsmState.SYN_RCVD,
                msg=(
                    f"Child session for HOST_A:{peer_port} must be in "
                    f"SYN_RCVD; the existence of other in-flight "
                    f"handshakes must not perturb its state."
                ),
            )
            self.assertEqual(
                child_session._rcv_seq.nxt,
                peer_iss + 1,
                msg=(
                    f"Child session for HOST_A:{peer_port} must have "
                    f"_rcv_nxt = {peer_iss + 1:#x} (= peer ISN + 1). "
                    f"Got {child_session._rcv_seq.nxt:#x}. A bug here "
                    f"would indicate concurrent SYNs are clobbering "
                    f"each other's '_rcv_nxt'."
                ),
            )
            self.assertIs(
                child_socket._parent_socket,
                listen_socket,
                msg=(
                    f"Child socket for HOST_A:{peer_port} must point "
                    f"at the original listening socket via "
                    f"'_parent_socket' so its eventual third-leg ACK "
                    f"deposits the accepted child onto the right "
                    f"accept queue."
                ),
            )

        # The listening socket itself is still in LISTEN, ready for a
        # fourth SYN.
        new_listener_session = listen_socket._tcp_session
        assert new_listener_session is not None
        self.assertIs(
            new_listener_session.state,
            FsmState.LISTEN,
            msg=(
                "After spawning three children, the listening socket "
                "must still have a LISTEN-state session attached so "
                "subsequent SYNs from other peers continue to be "
                "accepted."
            ),
        )
        self.assertIn(
            listen_socket.socket_id,
            stack.sockets,
            msg=(
                "The listening socket's wildcard registration must "
                "remain in 'stack.sockets' across the burst of SYNs."
            ),
        )

        # On the next virtual-clock tick, every child emits its
        # SYN+ACK. The listener's LISTEN-state session produces
        # nothing (LISTEN handler has no timer branch).
        tick_tx = self._advance(ms=1)
        self.assertEqual(
            len(tick_tx),
            len(peers),
            msg=(
                f"Expected {len(peers)} SYN+ACKs (one per child) on "
                f"the first tick after the SYN burst. Got "
                f"{len(tick_tx)}."
            ),
        )

        # Match TX frames to peers by destination port - the three
        # children fire in registration order but a future change to
        # the timer's task ordering should not break this test.
        probes = [self._parse_tx(frame) for frame in tick_tx]
        probes_by_dport = {probe.dport: probe for probe in probes}
        self.assertEqual(
            set(probes_by_dport),
            {peer_port for peer_port, _ in peers},
            msg=(
                "The set of destination ports across the emitted "
                "SYN+ACKs must exactly equal the set of source ports "
                "from the inbound SYN burst."
            ),
        )

        for peer_port, peer_iss in peers:
            probe = probes_by_dport[peer_port]
            self._assert_segment(
                probe,
                flags=frozenset({"SYN", "ACK"}),
                sport=LISTEN__PORT,
                dport=peer_port,
                seq=LOCAL__ISS,
                ack=peer_iss + 1,
                payload=b"",
                mss=1460,
                wscale=None,
                win=65535,
            )

    def test__passive_open__retransmitted_syn_in_syn_rcvd_emits_challenge_ack(self) -> None:
        """
        Ensure a duplicate SYN arriving on an existing
        SYN_RCVD child (peer retransmitted their SYN because
        they did not see our SYN+ACK) elicits a challenge ACK
        rather than being silently dropped or spawning a
        duplicate child session. The challenge ACK carries
        seq=SND.NXT, ack=RCV.NXT, flags={ACK} and the child
        session state is unchanged.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 5961 §4 (blind SYN-in-window mitigation).
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        original_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=original_syn)

        # Tick once so the SYN+ACK fires - this advances our SND.NXT
        # to ISS+1, which is the value the challenge ACK must echo.
        self._advance(ms=1)

        child_socket_id = self._child_socket_id()
        child_socket = stack.sockets[child_socket_id]
        assert isinstance(child_socket, TcpSocket)
        child_session_before = child_socket._tcp_session
        assert child_session_before is not None
        snd_nxt_before = child_session_before._snd_seq.nxt
        snd_una_before = child_session_before._snd_seq.una
        rcv_nxt_before = child_session_before._rcv_seq.nxt
        sockets_before = set(stack.sockets)

        self.assertIs(
            child_session_before.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: child session must be in SYN_RCVD before driving the retransmit.",
        )
        self.assertEqual(
            snd_nxt_before,
            LOCAL__ISS + 1,
            msg=("Setup precondition: '_snd_nxt' must equal ISS+1 " "after the SYN+ACK was emitted on the first tick."),
        )

        # Peer retransmits the same SYN (same seq, same options).
        retransmitted_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=retransmitted_syn)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A retransmitted SYN arriving on a SYN_RCVD child "
                "must elicit exactly one outbound segment (a "
                "challenge ACK) per RFC 9293 §3.10.7.4 step 1 / "
                f"step 4. Got {len(tx_frames)} TX frames."
            ),
        )

        challenge_ack = self._parse_tx(tx_frames[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=None,
            wscale=None,
            win=65535,
        )

        # The child session must be unchanged - same object, same
        # state, same sequence-number bookkeeping. The retransmit
        # carries no new information so processing it must be
        # idempotent on our state.
        child_session_after = child_socket._tcp_session
        self.assertIs(
            child_session_after,
            child_session_before,
            msg=(
                "A retransmitted SYN must not replace the child "
                "session - the existing session object must remain "
                "attached to the child socket."
            ),
        )
        assert child_session_after is not None
        self.assertIs(
            child_session_after.state,
            FsmState.SYN_RCVD,
            msg=(
                "A challenge ACK must not transition the child out "
                'of SYN_RCVD (RFC 9293 §3.10.7.4: "the connection '
                'state is not changed").'
            ),
        )
        self.assertEqual(
            child_session_after._snd_seq.nxt,
            snd_nxt_before,
            msg="Challenge ACK consumes no sequence space - '_snd_nxt' must be unchanged.",
        )
        self.assertEqual(
            child_session_after._snd_seq.una,
            snd_una_before,
            msg="Challenge ACK does not affect '_snd_una' - the original SYN+ACK is still unacknowledged.",
        )
        self.assertEqual(
            child_session_after._rcv_seq.nxt,
            rcv_nxt_before,
            msg=(
                "Reprocessing a duplicate SYN must not advance "
                "'_rcv_nxt' - the SYN's one byte was already consumed "
                "during the original handshake processing."
            ),
        )

        # No new socket may be registered. Same set of registrations
        # as before the retransmit drive.
        self.assertEqual(
            set(stack.sockets),
            sockets_before,
            msg=(
                "A retransmitted SYN must not spawn a duplicate child "
                "socket. The set of registrations in 'stack.sockets' "
                "must be exactly what existed before the retransmit "
                "drive."
            ),
        )

        # Listener still LISTEN.
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg=("Processing a duplicate SYN on a child must not " "disturb the listener's state."),
        )

    def test__passive_open__syn_to_established_child_emits_challenge_ack(self) -> None:
        """
        Ensure a SYN arriving at a child session that has
        already reached ESTABLISHED triggers a challenge ACK
        with seq=SND.NXT, ack=RCV.NXT, flags={ACK}, rather
        than tearing down the connection or attempting a
        fresh handshake. Child state and sequence bookkeeping
        are unchanged.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 5961 §4 (blind SYN-in-window mitigation).
        """

        # Stage 1: drive handshake to ESTABLISHED.
        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self._advance(ms=1)  # SYN+ACK fires

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        child_socket = stack.sockets[self._child_socket_id()]
        assert isinstance(child_socket, TcpSocket)
        child_session = child_socket._tcp_session
        assert child_session is not None
        self.assertIs(
            child_session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Setup precondition: child must reach ESTABLISHED "
                "after the third-leg ACK before driving the "
                "challenge-ACK scenario."
            ),
        )

        snd_nxt_before = child_session._snd_seq.nxt
        snd_una_before = child_session._snd_seq.una
        rcv_nxt_before = child_session._rcv_seq.nxt
        sockets_before = set(stack.sockets)

        # Stage 2: inject a SYN to the established child's 4-tuple.
        rogue_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=0xDEAD_BEEF,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        tx_frames = self._drive_rx(frame=rogue_syn)

        # Stage 3: verify the challenge-ACK shape.
        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A SYN arriving on an ESTABLISHED child must elicit "
                "exactly one outbound challenge ACK per RFC 9293 "
                f"§3.10.7.4. Got {len(tx_frames)} TX frames."
            ),
        )

        challenge_ack = self._parse_tx(tx_frames[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=None,
            wscale=None,
            win=65535,
        )

        # Stage 4: verify state unchanged.
        self.assertIs(
            child_session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Challenge ACK must not transition the child out of "
                'ESTABLISHED (RFC 9293 §3.10.7.4: "the connection '
                'state is not changed").'
            ),
        )
        self.assertEqual(
            child_session._snd_seq.nxt,
            snd_nxt_before,
            msg="Challenge ACK consumes no sequence space; '_snd_nxt' must be unchanged.",
        )
        self.assertEqual(
            child_session._snd_seq.una,
            snd_una_before,
            msg=("Rogue SYN's ACK was 0 - it acknowledges nothing - so '_snd_una' must be unchanged."),
        )
        self.assertEqual(
            child_session._rcv_seq.nxt,
            rcv_nxt_before,
            msg=(
                "The rogue SYN's seq is far outside our receive "
                "window and is not legitimately part of this "
                "connection's data stream; '_rcv_nxt' must be "
                "unchanged."
            ),
        )
        self.assertEqual(
            set(stack.sockets),
            sockets_before,
            msg="A rogue SYN must not spawn a new child or otherwise perturb 'stack.sockets'.",
        )
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg="Processing a rogue SYN on an established child must not disturb the listener.",
        )
