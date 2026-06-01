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
This module contains integration tests for RFC 3168 Explicit
Congestion Notification (ECN) in 'TcpSession'. ECN lets routers
mark IP packets as having experienced congestion (CE bit) instead
of dropping them; the receiving TCP echoes the mark back via the
ECE flag and the sender reduces cwnd accordingly. The mechanism
saves the latency penalty of detecting congestion via packet loss
and is the substrate L4S (RFC 9332) builds on.

The negotiation handshake (RFC 3168 §6.1.1):

  Active-open SYN:    ECE=1, CWR=1, IP ECT(0) on data packets
  Passive-open SYN+ACK: ECE=1, CWR=0  (ECN-Echo only confirms support)

Once both sides have advertised, '_ecn_enabled' is True and the
session emits IP-layer ECT(0) on data packets, echoes peer's CE
marks via outbound ECE, and reduces cwnd / ssthresh on inbound
ECE per RFC 5681 §3.1 (same response as fast-retransmit).

pytcp/tests/integration/protocols/tcp/test__tcp__session__ecn.py

ver 3.0.8
"""

from net_addr import Ip4Address  # noqa: F401
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
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

# Peer's advertised window + MSS on its SYN+ACK reply.
PEER__WIN: int = 64240
PEER__MSS: int = 1460


class TestTcpSession__Ecn(TcpTestCase):
    """
    Integration tests for the RFC 3168 ECN negotiation,
    marking, echo, and cwnd-reduce response paths.
    """

    def test__ecn__active_open_syn_advertises_ece_and_cwr(self) -> None:
        """
        Ensure the active-open SYN sets both ECE and CWR
        flags - the canonical client-side ECN-setup
        advertisement. A peer that supports ECN responds
        with SYN+ACK setting only ECE (not CWR); a peer
        that does not support ECN responds with neither
        flag, and the session falls back to non-ECN
        operation per the bilateral non-offer rule.

        Reference: RFC 3168 §6.1.1 (ECN-setup SYN: ECE+CWR).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN MUST fire on the first tick.",
        )
        syn = self._parse_tx(syn_tx[0])

        self.assertIn(
            "SYN",
            syn.flags,
            msg="Setup precondition: outbound segment must be a SYN.",
        )
        self.assertIn(
            "ECE",
            syn.flags,
            msg=("RFC 3168 §6.1.1: client-side ECN-setup SYN " "MUST carry the ECE flag. Got " f"flags={syn.flags!r}."),
        )
        self.assertIn(
            "CWR",
            syn.flags,
            msg=("RFC 3168 §6.1.1: client-side ECN-setup SYN " "MUST carry the CWR flag. Got " f"flags={syn.flags!r}."),
        )

    def test__ecn__passive_open_syn_ack_echoes_ece_only(self) -> None:
        """
        Ensure that when a peer's active-open SYN carries
        ECE+CWR (the canonical ECN-setup signal), the
        server's SYN+ACK reply sets ECE (only)
        - NOT CWR. The asymmetry is the wire signal that
        confirms bilateral ECN support: the active opener
        advertises with ECE+CWR, the passive responder
        confirms with ECE alone. Once both sides have
        signalled, '_ecn_enabled' is True on the session
        and subsequent data-path ECN behaviour (ECT
        marking on outbound, CE echo on inbound, ECE ->
        cwnd reduce) kicks in.

        Reference: RFC 3168 §6.1.1 (passive-side ECN-Echo confirmation: ECE only).
        """

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.LISTEN)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN", "ECE", "CWR"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)

        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK MUST fire on the next tick.",
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        self.assertIn(
            "ECE",
            syn_ack.flags,
            msg=(
                "RFC 3168 §6.1.1: SYN+ACK responding to an "
                "ECN-setup SYN MUST carry ECE. Got "
                f"flags={syn_ack.flags!r}."
            ),
        )
        self.assertNotIn(
            "CWR",
            syn_ack.flags,
            msg=(
                "RFC 3168 §6.1.1: SYN+ACK responding to an "
                "ECN-setup SYN MUST NOT carry CWR (ECE alone "
                "is the ECN-Echo confirmation; ECE+CWR is "
                "the active-open SYN signal). Got "
                f"flags={syn_ack.flags!r}."
            ),
        )
        self.assertTrue(
            session._ecn.enabled,
            msg=(
                "RFC 3168 §6.1.1: bilateral ECN negotiation "
                "MUST set '_ecn_enabled = True' on the "
                "session after the passive-open SYN+ACK "
                "fires. Got "
                f"_ecn_enabled={session._ecn.enabled}."
            ),
        )

    def test__ecn__active_open_peer_syn_ack_with_ece_sets_ecn_enabled(self) -> None:
        """
        Ensure that on the active-open side, when our SYN
        carried ECE+CWR and the peer's SYN+ACK confirms with
        ECE, the session sets '_ecn_enabled = True'. This is
        the second half of the bilateral ECN negotiation
        (the first half is the passive-open confirmation in
        the previous test) - the client side must read the
        peer's SYN+ACK echo and lock in ECN for the data
        path.

        Reference: RFC 3168 §6.1.1 (active-open bilateral ECN confirmation).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "ECE"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=("Setup precondition: handshake must reach ESTABLISHED. " f"Got state={session.state!r}."),
        )
        self.assertTrue(
            session._ecn.enabled,
            msg=(
                "RFC 3168 §6.1.1: when our active-open SYN carried "
                "ECE+CWR and the peer's SYN+ACK echoes ECE, "
                "'_ecn_enabled' MUST become True on the session. "
                f"Got _ecn_enabled={session._ecn.enabled}."
            ),
        )

    def _drive_handshake_to_established_with_ecn(self, *, iss: int, peer_iss: int) -> TcpSession:
        """
        Drive an active-open three-way handshake to ESTABLISHED
        with bilateral ECN successfully negotiated. The peer's
        SYN+ACK carries ECE only (the canonical RFC 3168 §6.1.1
        passive-side confirmation). After this returns, the
        session has '_ecn_enabled = True'.
        """

        session = self._make_active_session(iss=iss)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # SYN fires on the first tick.
        self._advance(ms=1)

        # Peer's SYN+ACK confirms ECN with ECE alone.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss,
            ack=iss + 1,
            flags=("SYN", "ACK", "ECE"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED, (
            "Setup precondition: handshake must reach ESTABLISHED. " f"Got state={session.state!r}."
        )
        assert session._ecn.enabled, (
            "Setup precondition: bilateral ECN negotiation must succeed "
            "(client SYN ECE+CWR, peer SYN+ACK ECE). Got "
            f"_ecn_enabled={session._ecn.enabled}."
        )
        return session

    def test__ecn__data_segment_carries_ect_zero_in_ip_header(self) -> None:
        """
        Ensure that once bilateral ECN negotiation has succeeded
        ('_ecn_enabled = True'), every outbound data segment
        carries the ECT(0) codepoint (binary '10' = 2) in the
        IP header's 2-bit ECN field. Routers along the path use
        this codepoint as the signal "this flow is ECN-capable;
        instead of dropping me on congestion, mark me with the
        CE codepoint and let the receiver echo the mark via
        ECE." A receiver that sees a non-ECT segment knows the
        flow is not ECN-capable and falls back to drop-driven
        congestion signaling.

        Reference: RFC 3168 §6.1.5 (ECT codepoint on data packets of an ECN-capable connection).
        """

        session = self._drive_handshake_to_established_with_ecn(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        bytes_sent = session.send(data=b"hello, ecn!")
        self.assertEqual(
            bytes_sent,
            len(b"hello, ecn!"),
            msg=("Setup precondition: 'session.send' must return the " f"full payload length. Got {bytes_sent}."),
        )

        data_tx = self._advance(ms=1)
        self.assertEqual(
            len(data_tx),
            1,
            msg=("Setup precondition: outbound data segment MUST fire " "on the next tick after 'send'."),
        )
        data = self._parse_tx(data_tx[0])

        self.assertEqual(
            data.payload,
            b"hello, ecn!",
            msg="Setup precondition: outbound segment must carry the application's payload.",
        )
        self.assertEqual(
            data.ip_ecn,
            2,
            msg=(
                "RFC 3168 §6.1.5: every outbound data segment of an "
                "ECN-capable TCP connection MUST set the IP ECN field "
                "to ECT(0) (binary '10' = 2). Got "
                f"ip_ecn={data.ip_ecn} (0=Not-ECT, 1=ECT(1), 2=ECT(0), "
                "3=CE)."
            ),
        )

    def test__ecn__inbound_ce_marked_segment_elicits_ece_in_outbound_ack(self) -> None:
        """
        Ensure that when a router along the path marks an
        inbound data segment with the IP CE codepoint
        ('11' = 3) - the wire signal that the network has
        experienced congestion - the receiver echoes the
        mark back to the sender by setting the ECE flag on
        every outbound TCP segment until the sender confirms
        cwnd reduction via CWR. CE -> ECE is the substrate
        congestion signal that ECN was designed around;
        without it the sender never learns the network is
        congested and never reduces cwnd, defeating the
        whole point of ECN.

        Reference: RFC 3168 §6.1.2 (CE -> ECE echo on next ACK).
        """

        self._drive_handshake_to_established_with_ecn(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends a single data segment with the IP CE
        # codepoint set ('11' = 3). The session is now
        # ESTABLISHED with bilateral ECN, so this is a
        # well-formed congestion-experienced indication
        # from a router along the forward path.
        ce_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            ip_ecn=3,
            payload=b"congested!",
        )
        self._drive_rx(frame=ce_data)
        # Drain the delayed-ACK timer so the cumulative ACK
        # for the inbound data segment is emitted: per
        # RFC 1122 §4.2.3.2 the first inbound segment is
        # held back until the delayed-ACK timer fires.
        ack_tx = self._advance(ms=200)
        self.assertEqual(
            len(ack_tx),
            1,
            msg=(
                "Setup precondition: cumulative ACK MUST fire after the "
                "delayed-ACK timer expires. Got "
                f"{len(ack_tx)} TX frames."
            ),
        )
        ack = self._parse_tx(ack_tx[0])

        self.assertIn(
            "ACK",
            ack.flags,
            msg="Setup precondition: outbound segment must be an ACK.",
        )
        self.assertIn(
            "ECE",
            ack.flags,
            msg=(
                "RFC 3168 §6.1.2: receiver MUST echo the CE codepoint "
                "back to the sender via the ECE flag on the next "
                "outbound TCP segment. Got "
                f"flags={ack.flags!r}."
            ),
        )

    def test__ecn__inbound_ece_halves_ssthresh_and_cwnd(self) -> None:
        """
        Ensure that when an ECN-capable sender receives an
        inbound ACK carrying the ECE flag - the wire signal
        that the receiver observed a CE-marked segment along
        the forward path - the sender treats it as a single-
        packet loss event: ssthresh is halved (clamped at
        2*SMSS) and cwnd is collapsed to ssthresh. This is
        the substrate response that lets ECN drive cwnd
        reduction without the latency penalty of detecting
        loss via timeout or three dup-ACKs.

        Reference: RFC 3168 §6.1.2 (sender-side cwnd reduction on ECE).
        """

        session = self._drive_handshake_to_established_with_ecn(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Send enough data for flight_size to exceed the
        # 2*SMSS ABE floor; PyTCP fires one segment per ms
        # tick so advance ms=10 to drain the send buffer
        # before we capture flight_size_before.
        payload = b"x" * 6000
        session.send(data=payload)
        self._advance(ms=10)

        snd_mss = session._win.snd_mss
        flight_size_before = (session._snd_seq.max - session._snd_seq.una) & 0xFFFF_FFFF
        # RFC 8511 ABE: on ECN events the sender uses a less
        # aggressive multiplier (0.85) instead of the canonical
        # RFC 5681 §3.1 0.5. The 17/20 integer ratio yields the
        # canonical ABE recommended value 0.85.
        expected_ssthresh = max(flight_size_before * 17 // 20, 2 * snd_mss)

        # Peer sends an ACK with ECE - the sender's wire
        # signal that a CE-marked segment was observed.
        ece_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "ECE"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=ece_ack)

        self.assertEqual(
            session._cc.ssthresh,
            expected_ssthresh,
            msg=(
                "RFC 8511 §3 ABE: on inbound ECE the sender uses "
                "the less-aggressive backoff multiplier (0.85) "
                "instead of the RFC 5681 §3.1 0.5 used for loss "
                "events. Expected 'max(flight_size * 17 // 20, "
                f"2*SMSS)' = {expected_ssthresh}, got "
                f"{session._cc.ssthresh}. Pre-ECE flight_size was "
                f"{flight_size_before}."
            ),
        )
        self.assertEqual(
            session._cc.cwnd,
            expected_ssthresh,
            msg=(
                "RFC 3168 §6.1.2: on inbound ECE the sender MUST "
                "collapse cwnd to ssthresh. Got "
                f"cwnd={session._cc.cwnd}, ssthresh={session._cc.ssthresh}."
            ),
        )

    def test__ecn__cwr_set_on_next_data_segment_after_inbound_ece(self) -> None:
        """
        Ensure that after the sender has reduced cwnd in
        response to an inbound ECE, the CWR flag is set on
        the first new outbound data segment. CWR is the
        sender's wire confirmation to the receiver that the
        ECN response has been applied; the receiver uses CWR
        to stop echoing ECE on subsequent ACKs.

        Reference: RFC 3168 §6.1.2 (sender-side CWR confirmation).
        Reference: RFC 3168 §6.1.3 (receiver stops echoing ECE on CWR).
        """

        session = self._drive_handshake_to_established_with_ecn(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends an ACK with ECE, before we send any data
        # so the cwnd-halve doesn't strangle the test.
        ece_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "ECE"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=ece_ack)

        # Send some data; the next outbound segment must
        # carry CWR.
        session.send(data=b"hello, cwr!")
        data_tx = self._advance(ms=1)
        self.assertEqual(
            len(data_tx),
            1,
            msg=("Setup precondition: the post-ECE data send MUST emit " "a single outbound segment on the next tick."),
        )
        data = self._parse_tx(data_tx[0])

        self.assertIn(
            "CWR",
            data.flags,
            msg=(
                "RFC 3168 §6.1.2: after responding to an inbound ECE "
                "with cwnd reduction, the sender MUST set the CWR flag "
                "on the first new outbound data segment as the wire "
                "confirmation to the receiver. Got "
                f"flags={data.flags!r}."
            ),
        )

    def test__ecn__retransmit_does_not_carry_ect(self) -> None:
        """
        Ensure that when the RTO retransmit timer fires for a
        previously-ECT-marked data segment, the retransmit goes
        out with the IP-ECN field cleared to Not-ECT (binary
        '00' = 0). An ECN-capable TCP implementation MUST NOT
        set either ECT codepoint (ECT(0) or ECT(1)) in the IP
        header for retransmitted data packets. The rationale
        is that an ECT-marked retransmit that is later dropped
        in the network prevents the end nodes from seeing a CE
        mark on the original copy, and an ECT mark on the
        retransmit ambiguates the congestion signal.

        Reference: RFC 3168 §6.1.5 (no ECT on retransmits).
        """

        session = self._drive_handshake_to_established_with_ecn(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Original transmit: must carry ECT(0).
        session.send(data=b"hello, ecn!")
        original_tx = self._advance(ms=1)
        self.assertEqual(
            len(original_tx),
            1,
            msg="Setup precondition: original send must fire one segment.",
        )
        original = self._parse_tx(original_tx[0])
        self.assertEqual(
            original.ip_ecn,
            2,
            msg=(
                "Setup precondition: original segment of an ECN-capable "
                f"connection MUST carry ECT(0). Got ip_ecn={original.ip_ecn}."
            ),
        )

        # Drive past the RTO to force a retransmit. Peer is silent.
        retransmit_tx = self._advance(ms=session._rto_state.rto_ms + 10)
        retransmit_segments = [self._parse_tx(frame) for frame in retransmit_tx if self._parse_tx(frame).payload]
        self.assertGreaterEqual(
            len(retransmit_segments),
            1,
            msg=(
                "Setup precondition: at least one retransmit must fire "
                "after the RTO. Got "
                f"{len(retransmit_segments)} data segment(s) among "
                f"{len(retransmit_tx)} TX frames."
            ),
        )
        for retransmit in retransmit_segments:
            self.assertEqual(
                retransmit.payload,
                b"hello, ecn!",
                msg=(
                    "Setup precondition: retransmit must carry the same "
                    f"payload as the original. Got {retransmit.payload!r}."
                ),
            )
            self.assertEqual(
                retransmit.ip_ecn,
                0,
                msg=(
                    "RFC 3168 §6.1.5: a retransmitted data packet MUST "
                    "carry IP-ECN = Not-ECT (0). An ECT-marked retransmit "
                    "ambiguates the congestion signal because a later "
                    "drop of either copy hides the CE indication. Got "
                    f"ip_ecn={retransmit.ip_ecn} (expected 0)."
                ),
            )
