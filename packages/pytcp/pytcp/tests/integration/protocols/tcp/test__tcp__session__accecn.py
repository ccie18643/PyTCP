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
This module contains integration tests for RFC 9768 Accurate
ECN (AccECN) in 'TcpSession'. AccECN replaces RFC 3168's
binary CE/ECE feedback channel with byte-counter-based
feedback that is granular enough for L4S-style scalable
congestion control. The negotiation handshake (RFC 9768
§3.1.1) uses different SYN flag combinations from RFC 3168;
when both peers are AccECN-capable, '_accecn_enabled' is
True post-handshake and the data path uses the AccECN
option (kind 172/174) to carry per-segment byte counters.

The negotiation handshake (RFC 9768 §3.1.1):

  Active-open SYN:    AE=1, CWR=1, ECE=1 (the canonical
                      AccECN-setup SYN; AE=0 is RFC 3168).
  Server SYN+ACK:     One of four AccECN-capable codepoints
                      that encodes the IP-ECN of the SYN
                      received; AccECN-incapable servers
                      respond with classic RFC 3168 ECE
                      alone (AE=0, CWR=0, ECE=1).

When AccECN negotiation succeeds, '_accecn_enabled' is True.
When the peer falls back to RFC 3168 (AE=0, CWR=0, ECE=1
SYN+ACK), '_ecn_enabled' is True instead. When neither
applies (no ECN flags on the SYN+ACK), neither flag is set.

pytcp/tests/integration/protocols/tcp/test__tcp__session__accecn.py

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
from pytcp.tests.lib.tcp_testcase import TcpProbe, TcpTestCase

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


class TestTcpSession__Accecn(TcpTestCase):
    """
    Integration tests for the RFC 9768 AccECN negotiation,
    counter encoding, byte-count emission, and proportional
    cwnd response paths.
    """

    def test__accecn__active_open_syn_advertises_ae_cwr_ece(self) -> None:
        """
        Ensure the active-open SYN sets all three of AE, CWR,
        and ECE - the canonical client-side AccECN-setup
        signal. The AE bit (the legacy NS bit position) is
        what distinguishes an AccECN-capable SYN from a
        classic ECN SYN which sets only CWR+ECE. Servers
        that recognise AccECN respond with one of four
        AE/CWR/ECE codepoints encoding the IP-ECN of the
        received SYN; servers that do not recognise AccECN
        respond with classic ECE alone, and the session
        falls back gracefully.

        Reference: RFC 9768 §3.1.1 (AccECN-setup SYN: AE+CWR+ECE).
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
            msg=("RFC 9768 §3.1.1: AccECN-setup SYN MUST carry " f"the ECE flag. Got flags={syn.flags!r}."),
        )
        self.assertIn(
            "CWR",
            syn.flags,
            msg=("RFC 9768 §3.1.1: AccECN-setup SYN MUST carry " f"the CWR flag. Got flags={syn.flags!r}."),
        )
        self.assertIn(
            "NS",
            syn.flags,
            msg=(
                "RFC 9768 §3.1.1: AccECN-setup SYN MUST carry "
                "the AE flag (the legacy NS bit position). The "
                "AE bit is what distinguishes an AccECN SYN from "
                "a classic RFC 3168 SYN; without it a peer that "
                "recognises AccECN cannot tell our intent. Got "
                f"flags={syn.flags!r}."
            ),
        )

    def test__accecn__bilateral_negotiation_via_accecn_capable_synack(self) -> None:
        """
        Ensure that when our active-open SYN advertised
        AccECN (AE+CWR+ECE) and the peer's SYN+ACK responds
        with one of the four AccECN-capable codepoints, the
        session sets '_accecn_enabled = True' post-handshake.
        The four codepoints encode which IP-ECN codepoint
        the peer received on our SYN; in this test we use
        the (AE=0, CWR=1, ECE=0) codepoint that signals
        "saw Not-ECT". Once '_accecn_enabled' is True the
        data-path uses the AccECN option (kind 172/173) to
        carry per-segment byte counters.

        Reference: RFC 9768 §3.1.1 (server AccECN-capable SYN+ACK).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # AccECN-capable peer responds with the (AE=0, CWR=1,
        # ECE=0) codepoint - "I am AccECN-capable; I saw Not-
        # ECT on your SYN". The presence of CWR (without ECE)
        # is the wire signal an AccECN-capable client uses to
        # disambiguate from RFC 3168's (CWR=0, ECE=1) form.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "CWR"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Setup precondition: handshake MUST reach ESTABLISHED "
                f"on the AccECN-capable SYN+ACK. Got state={session.state!r}."
            ),
        )
        self.assertTrue(
            session._accecn.enabled,
            msg=(
                "RFC 9768 §3.1.1: when our SYN advertised AccECN "
                "and the peer's SYN+ACK carries one of the four "
                "AccECN-capable codepoints (here: AE=0, CWR=1, "
                "ECE=0 = saw Not-ECT), '_accecn_enabled' MUST "
                f"become True. Got _accecn_enabled={session._accecn.enabled}."
            ),
        )
        self.assertFalse(
            session._ecn.enabled,
            msg=(
                "When AccECN negotiation succeeds, the session "
                "uses AccECN (not RFC 3168 ECN). "
                "'_ecn_enabled' MUST remain False so the two "
                "paths cannot both fire. Got "
                f"_ecn_enabled={session._ecn.enabled}."
            ),
        )

    def test__accecn__active_open_rfc3168_only_synack_falls_back_to_classic_ecn(self) -> None:
        """
        Ensure that when our active-open SYN advertised
        AccECN (AE+CWR+ECE) and the peer's SYN+ACK responds
        with the classic RFC 3168 (AE=0, CWR=0, ECE=1) form
        - i.e. the peer recognised our SYN as ECN-setup but
        does not understand AccECN - the session falls back
        gracefully to RFC 3168 ECN: '_ecn_enabled' becomes
        True and '_accecn_enabled' stays False. This is the
        backward-compatibility guarantee that lets AccECN
        deploy incrementally on the internet.

        Reference: RFC 9768 §3.1.2 (active-open RFC 3168 fallback).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # RFC-3168-only server: SYN+ACK with ECE alone, no
        # AE, no CWR. This is the codepoint a classic-ECN-
        # only server uses to confirm ECN; an AccECN-capable
        # server would set CWR or AE alongside.
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
            msg="Setup precondition: handshake MUST reach ESTABLISHED.",
        )
        self.assertTrue(
            session._ecn.enabled,
            msg=(
                "RFC 9768 §3.1.2: when the peer's SYN+ACK is "
                "the RFC 3168 form (AE=0, CWR=0, ECE=1), the "
                "session MUST fall back to classic ECN. "
                f"Got _ecn_enabled={session._ecn.enabled}."
            ),
        )
        self.assertFalse(
            session._accecn.enabled,
            msg=(
                "RFC 9768 §3.1.2: classic RFC 3168 fallback "
                "MUST leave '_accecn_enabled' False. Got "
                f"_accecn_enabled={session._accecn.enabled}."
            ),
        )

    def _make_listen_session(self) -> TcpSession:
        """Build a wildcard-LISTEN 'TcpSocket' / 'TcpSession' pair."""

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
        return session

    def test__accecn__passive_open_syn_with_not_ect_emits_codepoint_a_synack(self) -> None:
        """
        Ensure that when a peer's AccECN-setup SYN
        (AE+CWR+ECE) arrives with the IP-ECN codepoint
        Not-ECT (00), the outbound SYN+ACK carries the
        canonical (AE=0, CWR=1, ECE=0) codepoint - the
        wire signal "AccECN-capable, saw Not-ECT on your
        SYN". The CWR-without-ECE encoding is what
        distinguishes the AccECN-capable response from a
        classic RFC 3168 (CWR=0, ECE=1) reply.

        Reference: RFC 9768 §3.1.1 (server SYN+ACK codepoint for received Not-ECT).
        """

        self._make_listen_session()

        # AccECN-setup SYN with IP-ECN = Not-ECT (00).
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN", "ECE", "CWR", "NS"),
            ip_ecn=0,
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

        self.assertNotIn(
            "NS",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to a "
                "Not-ECT AccECN SYN MUST clear the AE flag "
                "(the canonical codepoint is AE=0, CWR=1, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertIn(
            "CWR",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to a "
                "Not-ECT AccECN SYN MUST set the CWR flag "
                "(the canonical codepoint is AE=0, CWR=1, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertNotIn(
            "ECE",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to a "
                "Not-ECT AccECN SYN MUST clear the ECE flag "
                "(the canonical codepoint is AE=0, CWR=1, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )

    def test__accecn__passive_open_syn_with_ect_zero_emits_codepoint_c_synack(self) -> None:
        """
        Ensure that when a peer's AccECN-setup SYN
        (AE+CWR+ECE) arrives with the IP-ECN codepoint
        ECT(0) (10 - the canonical ECN-Capable codepoint),
        the outbound SYN+ACK carries the (AE=1, CWR=0,
        ECE=0) codepoint. This is one of the two codepoints
        with AE=1 set, the wire signal that the received
        SYN was a marked packet (ECT(0) or CE) rather than
        an unmarked one.

        Reference: RFC 9768 §3.1.1 (server SYN+ACK codepoint for received ECT(0)).
        """

        self._make_listen_session()

        # AccECN-setup SYN with IP-ECN = ECT(0) (10).
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN", "ECE", "CWR", "NS"),
            ip_ecn=2,
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
            "NS",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to an "
                "ECT(0) AccECN SYN MUST set the AE flag "
                "(the canonical codepoint is AE=1, CWR=0, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertNotIn(
            "CWR",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to an "
                "ECT(0) AccECN SYN MUST clear the CWR flag "
                "(the canonical codepoint is AE=1, CWR=0, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertNotIn(
            "ECE",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to an "
                "ECT(0) AccECN SYN MUST clear the ECE flag "
                "(the canonical codepoint is AE=1, CWR=0, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )

    def _drive_handshake_to_established_with_accecn(self) -> TcpSession:
        """
        Drive an active-open three-way handshake to ESTABLISHED
        with bilateral AccECN successfully negotiated. Returns
        the session AND the third-leg ACK frame so tests can
        inspect the post-handshake ACE encoding.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # AccECN-capable peer SYN+ACK (AE=0, CWR=1, ECE=0
        # codepoint: "I am AccECN-capable; saw Not-ECT").
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "CWR"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED, (
            "Setup precondition: handshake must reach ESTABLISHED. " f"Got state={session.state!r}."
        )
        assert session._accecn.enabled, (
            "Setup precondition: bilateral AccECN must succeed. " f"Got _accecn_enabled={session._accecn.enabled}."
        )
        return session

    def _drive_third_leg_ack_with_synack_ipecn(self, ip_ecn: int) -> TcpProbe:
        """
        Drive an active-open through the third-leg ACK, with the
        peer's SYN+ACK carrying the supplied IP-ECN codepoint.
        Returns the parsed third-leg ACK probe.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "CWR"),
            win=PEER__WIN,
            mss=PEER__MSS,
            ip_ecn=ip_ecn,
        )
        third_leg_tx = self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED, (
            "Setup precondition: handshake reaches ESTABLISHED. " f"Got state={session.state!r}."
        )
        assert len(third_leg_tx) == 1, (
            "Setup precondition: third-leg ACK MUST fire inline. " f"Got {len(third_leg_tx)} TX frames."
        )
        self._last_handshake_session = session
        return self._parse_tx(third_leg_tx[0])

    def test__accecn__handshake_encoding_not_ect_synack_emits_ace_010(self) -> None:
        """
        Ensure that on the active-open third-leg ACK following a
        SYN+ACK whose IP-ECN was Not-ECT (00), the AE+CWR+ECE
        flags carry the handshake encoding 010 (AE=0, CWR=1,
        ECE=0). The handshake encoding lets the server compare
        what IP-ECN it set on its SYN+ACK against what the
        client reports it received, enabling detection of IP-ECN
        mangling along the path.

        Reference: RFC 9768 §3.2.2.1 (Table 3 handshake encoding for ACK of SYN/ACK).
        """

        ack = self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=0)

        self.assertNotIn("NS", ack.flags, msg=f"AE MUST be 0 for Not-ECT-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertIn("CWR", ack.flags, msg=f"CWR MUST be 1 for Not-ECT-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertNotIn("ECE", ack.flags, msg=f"ECE MUST be 0 for Not-ECT-on-SYN/ACK. Got flags={ack.flags!r}.")

    def test__accecn__handshake_encoding_ect1_synack_emits_ace_011(self) -> None:
        """
        Ensure that on the active-open third-leg ACK following a
        SYN+ACK whose IP-ECN was ECT(1) (01), the AE+CWR+ECE
        flags carry the handshake encoding 011 (AE=0, CWR=1,
        ECE=1).

        Reference: RFC 9768 §3.2.2.1 (Table 3 handshake encoding for ACK of SYN/ACK).
        """

        ack = self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=1)

        self.assertNotIn("NS", ack.flags, msg=f"AE MUST be 0 for ECT(1)-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertIn("CWR", ack.flags, msg=f"CWR MUST be 1 for ECT(1)-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertIn("ECE", ack.flags, msg=f"ECE MUST be 1 for ECT(1)-on-SYN/ACK. Got flags={ack.flags!r}.")

    def test__accecn__handshake_encoding_ect0_synack_emits_ace_100(self) -> None:
        """
        Ensure that on the active-open third-leg ACK following a
        SYN+ACK whose IP-ECN was ECT(0) (10), the AE+CWR+ECE
        flags carry the handshake encoding 100 (AE=1, CWR=0,
        ECE=0).

        Reference: RFC 9768 §3.2.2.1 (Table 3 handshake encoding for ACK of SYN/ACK).
        """

        ack = self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=2)

        self.assertIn("NS", ack.flags, msg=f"AE MUST be 1 for ECT(0)-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertNotIn("CWR", ack.flags, msg=f"CWR MUST be 0 for ECT(0)-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertNotIn("ECE", ack.flags, msg=f"ECE MUST be 0 for ECT(0)-on-SYN/ACK. Got flags={ack.flags!r}.")

    def test__accecn__handshake_encoding_ce_synack_emits_ace_110(self) -> None:
        """
        Ensure that on the active-open third-leg ACK following a
        SYN+ACK whose IP-ECN was CE (11), the AE+CWR+ECE flags
        carry the handshake encoding 110 (AE=1, CWR=1, ECE=0).

        Reference: RFC 9768 §3.2.2.1 (Table 3 handshake encoding for ACK of SYN/ACK).
        """

        ack = self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=3)

        self.assertIn("NS", ack.flags, msg=f"AE MUST be 1 for CE-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertIn("CWR", ack.flags, msg=f"CWR MUST be 1 for CE-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertNotIn("ECE", ack.flags, msg=f"ECE MUST be 0 for CE-on-SYN/ACK. Got flags={ack.flags!r}.")

    def test__accecn__ce_marked_synack_increments_r_cep_to_6(self) -> None:
        """
        Ensure that when the active-open client receives a CE-
        marked SYN+ACK, the receiver-side 'r.cep' counter
        increments from its initial value 5 to 6. This ensures
        the CE marking is reliably delivered back to the server
        once the client starts using the ACE field on subsequent
        post-handshake segments. The increment is a one-shot
        cap: even multiple CE-marked SYN+ACKs (retransmissions)
        only advance r.cep by 1.

        Reference: RFC 9768 §3.2.2.2 (CE on SYN/ACK increments r.cep, capped at +1).
        """

        self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=3)
        session = self._last_handshake_session

        self.assertEqual(
            session._accecn.r_cep,
            6,
            msg=(
                "RFC 9768 §3.2.2.2: a CE-marked SYN+ACK MUST "
                "increment r.cep from 5 to 6 so the marking is "
                "reliably delivered to the peer via the ACE "
                f"field. Got _accecn_r_cep={session._accecn.r_cep}."
            ),
        )

    def test__accecn__post_handshake_data_ack_uses_regular_ace_encoding(self) -> None:
        """
        Ensure that after the handshake-encoded third-leg ACK,
        a subsequent outbound ACK (e.g. acknowledging an inbound
        data segment) uses the regular 'r.cep & 7' ACE encoding
        instead of the handshake encoding. The handshake encoding
        is one-shot per connection setup.

        Reference: RFC 9768 §3.2.2 (regular ACE encoding on non-handshake segments).
        """

        # Drive handshake with Not-ECT SYN+ACK so r.cep stays at 5
        # → regular encoding ACE = 5 = 0b101 = (AE=1, CWR=0, ECE=1).
        self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=0)
        session = self._last_handshake_session

        # Send an inbound data segment to elicit a non-handshake
        # outbound ACK after the delayed-ACK timer fires.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"hello",
        )
        self._drive_rx(frame=peer_data)
        ack_tx = self._advance(ms=200)

        self.assertEqual(
            len(ack_tx),
            1,
            msg=f"Setup precondition: delayed-ACK must fire. Got {len(ack_tx)} TX frames.",
        )
        ack = self._parse_tx(ack_tx[0])

        self.assertIn(
            "NS",
            ack.flags,
            msg=f"Regular ACE = 5 (binary 101) MUST set AE = 1. Got flags={ack.flags!r}.",
        )
        self.assertNotIn(
            "CWR",
            ack.flags,
            msg=f"Regular ACE = 5 (binary 101) MUST clear CWR. Got flags={ack.flags!r}.",
        )
        self.assertIn(
            "ECE",
            ack.flags,
            msg=f"Regular ACE = 5 (binary 101) MUST set ECE = 1. Got flags={ack.flags!r}.",
        )
        self.assertEqual(
            session._accecn.r_cep,
            5,
            msg=(
                "Setup precondition: r.cep MUST stay at 5 after a "
                "non-CE inbound segment (the inbound data is "
                "Not-ECT). Got "
                f"_accecn_r_cep={session._accecn.r_cep}."
            ),
        )

    def test__accecn__inbound_ce_increments_ace_counter(self) -> None:
        """
        Ensure that when an inbound segment arrives with the
        IP-ECN codepoint CE (11) on an AccECN-enabled
        connection, the receiver-side r.cep counter
        increments and the next outbound segment encodes the
        new value (6 = binary 110 = AE=1, CWR=1, ECE=0) in
        the AE+CWR+ECE flags. This is the substrate granular
        feedback that AccECN provides over RFC 3168's binary
        signal: the sender reads counter deltas across ACKs
        to count CE marks accurately.

        Reference: RFC 9768 §3.2.2 (r.cep counter increment on inbound CE).
        """

        session = self._drive_handshake_to_established_with_accecn()

        # Peer sends one CE-marked data segment.
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

        # Drain the delayed-ACK timer; the cumulative ACK
        # fires after the timer expiry.
        ack_tx = self._advance(ms=200)
        self.assertEqual(
            len(ack_tx),
            1,
            msg=(
                "Setup precondition: cumulative ACK MUST fire after "
                f"the delayed-ACK timer. Got {len(ack_tx)} TX frames."
            ),
        )
        ack = self._parse_tx(ack_tx[0])

        # ACE = 6 = binary 110 -> AE=1, CWR=1, ECE=0.
        self.assertEqual(
            session._accecn.r_cep,
            6,
            msg=(
                "RFC 9768 §3.2.2: r.cep MUST advance from 5 to 6 "
                "on receipt of one CE-marked inbound segment. Got "
                f"_accecn_r_cep={session._accecn.r_cep}."
            ),
        )
        self.assertIn(
            "NS",
            ack.flags,
            msg=(
                "RFC 9768 §3.2.2: ACE = 6 (binary 110) MUST "
                "encode AE (NS bit) = 1 on the next outbound "
                f"segment. Got flags={ack.flags!r}."
            ),
        )
        self.assertIn(
            "CWR",
            ack.flags,
            msg=(
                "RFC 9768 §3.2.2: ACE = 6 (binary 110) MUST "
                "encode CWR = 1 on the next outbound segment. "
                f"Got flags={ack.flags!r}."
            ),
        )
        self.assertNotIn(
            "ECE",
            ack.flags,
            msg=(
                "RFC 9768 §3.2.2: ACE = 6 (binary 110) MUST "
                "encode ECE = 0 on the next outbound segment. "
                f"Got flags={ack.flags!r}."
            ),
        )

    def test__accecn__post_handshake_first_segment_carries_accecn_option_with_initial_counters(self) -> None:
        """
        Ensure that the first outbound non-SYN segment after
        an AccECN handshake carries the AccECN option (kind
        172, AccECN0 form) with the spec-mandated initial
        counter values: r.ECT(0)=1, r.CE=0, r.ECT(1)=1. The
        non-zero r.ECT(0) and r.ECT(1) initial values
        distinguish a freshly-negotiated session from
        middlebox-zeroed fields; r.CE starts at 0 because
        zero CE marks at connection start is the expected
        steady state.

        Reference: RFC 9768 §3.2.1 (Initialization of Feedback Counters).
        Reference: RFC 9768 §3.2.3 (AccECN option emission post-handshake).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "CWR"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        third_leg_tx = self._drive_rx(frame=peer_syn_ack)

        self.assertEqual(
            len(third_leg_tx),
            1,
            msg="Setup precondition: third-leg ACK MUST fire inline.",
        )
        ack = self._parse_tx(third_leg_tx[0])

        self.assertIsNotNone(
            ack.accecn,
            msg=(
                "RFC 9768 §3.2.3: the first outbound non-SYN "
                "segment of an AccECN-enabled connection MUST "
                "carry the AccECN option (kind 172). Got "
                f"accecn={ack.accecn!r}."
            ),
        )
        self.assertEqual(
            ack.accecn,
            (1, 0, 1),
            msg=(
                "RFC 9768 §3.2.1: the AccECN option's three "
                "byte counters MUST start at (r.ECT(0)=1, "
                "r.CE=0, r.ECT(1)=1) immediately after the "
                "handshake. Non-zero ECT counters distinguish "
                "a freshly-negotiated session from middlebox-"
                f"zeroed fields. Got accecn={ack.accecn!r}."
            ),
        )

    def test__accecn__inbound_ce_data_segment_increments_r_ce_byte_counter(self) -> None:
        """
        Ensure that when an inbound data segment arrives with
        the IP-ECN codepoint CE (11) on an AccECN-enabled
        connection, the r.CE byte counter increments by the
        TCP-payload byte length (not by 1) and the next
        outbound segment's AccECN option carries the new
        value in its second slot. The byte-precision counter
        is what gives AccECN its granularity over RFC 3168's
        binary signal: a sender can read the delta in
        r.CE-bytes across two ACKs to compute exactly how
        many bytes the network marked.

        Reference: RFC 9768 §3.2.3 (r.CE byte counter increment by payload length).
        """

        session = self._drive_handshake_to_established_with_accecn()

        payload = b"congested-data"
        ce_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            ip_ecn=3,
            payload=payload,
        )
        self._drive_rx(frame=ce_data)

        ack_tx = self._advance(ms=200)
        self.assertEqual(
            len(ack_tx),
            1,
            msg="Setup precondition: cumulative ACK MUST fire after delayed-ACK timer.",
        )
        ack = self._parse_tx(ack_tx[0])

        self.assertEqual(
            session._accecn.r_ce_b,
            len(payload),
            msg=(
                "RFC 9768 §3.2.3: r.CEB MUST advance by the "
                f"TCP-payload byte length ({len(payload)}). Got "
                f"_accecn_r_ce_b={session._accecn.r_ce_b}."
            ),
        )
        self.assertIsNotNone(
            ack.accecn,
            msg="RFC 9768 §3.2.3: outbound ACK MUST carry the AccECN option.",
        )
        # Abbreviation: only r.CE advanced; r.ECT(0) and r.ECT(1)
        # are unchanged, so the option emits the Length 8 form
        # (ee0b + eceb on wire, ee1b dropped).
        self.assertEqual(
            ack.accecn,
            (1, len(payload), None),
            msg=(
                "RFC 9768 §3.2.3: the AccECN option's r.CE "
                "byte counter (second slot) MUST equal the "
                f"cumulative CE-marked payload bytes ({len(payload)}); "
                "r.ECT(0) stays at its initial 1 in the first "
                "slot and the trailing r.ECT(1) is dropped per "
                f"the Length 8 abbreviation. Got accecn={ack.accecn!r}."
            ),
        )

    def test__accecn__inbound_option_with_increased_r_ce_triggers_cwnd_reduction(self) -> None:
        """
        Ensure that on an AccECN-enabled connection, when a
        peer's inbound ACK carries an AccECN option whose r.CE
        byte counter has increased since the last received
        option, the sender treats it as a congestion event:
        ssthresh is halved and cwnd is collapsed to ssthresh.
        This is the substrate proportional-response that
        AccECN provides; for a full L4S-style scalable
        response a CC-mode-aware formula would weight the
        reduction by the marked-byte fraction, but the per-
        RTT halving is the canonical backwards-compatible
        fallback.

        Reference: RFC 9768 §3.4 (sender response to AccECN feedback).
        Reference: RFC 5681 §3.1 (ssthresh halving on congestion event).
        """

        session = self._drive_handshake_to_established_with_accecn()
        # Send enough data for flight_size to exceed the
        # 2*SMSS ABE floor; PyTCP fires one segment per ms
        # tick so advance ms=10 to drain the send buffer
        # before we capture flight_size_before.
        payload = b"x" * 6000
        session.send(data=payload)
        self._advance(ms=10)

        snd_mss = session._win.snd_mss
        flight_size_before = (session._snd_seq.max - session._snd_seq.una) & 0xFFFF_FFFF
        # RFC 8511 ABE: on ECN-class events the sender uses a
        # less aggressive multiplier (0.85) than the RFC 5681
        # §3.1 0.5 used for loss events. The 17/20 integer
        # ratio yields the canonical ABE value 0.85.
        expected_ssthresh = max(flight_size_before * 17 // 20, 2 * snd_mss)

        # Peer's ACK reporting a non-zero r.CE byte count
        # (1500 bytes marked CE - one MSS-sized packet).
        ack_with_ce = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            accecn0_counters=(0, 1500, 0),
        )
        self._drive_rx(frame=ack_with_ce)

        self.assertEqual(
            session._cc.ssthresh,
            expected_ssthresh,
            msg=(
                "RFC 8511 §3 ABE: on AccECN feedback with positive "
                "r.CE delta the sender uses the less-aggressive "
                "ABE backoff multiplier (0.85) instead of RFC 5681 "
                "§3.1's 0.5 used for loss events. Expected "
                "'max(flight_size * 17 // 20, 2*SMSS)' = "
                f"{expected_ssthresh}, got {session._cc.ssthresh}. "
                f"Pre-event flight_size was {flight_size_before}."
            ),
        )
        self.assertEqual(
            session._cc.cwnd,
            expected_ssthresh,
            msg=(
                "RFC 9768 §3.4: on AccECN feedback with positive "
                "r.CE delta the sender MUST collapse cwnd to "
                f"ssthresh. Got cwnd={session._cc.cwnd}, "
                f"ssthresh={session._cc.ssthresh}."
            ),
        )
        self.assertEqual(
            session._accecn.s_ce_b,
            1500,
            msg=(
                "RFC 9768 §3.4: the sender-side r.CE tracker "
                "MUST advance to the latest value reported by "
                "the peer (1500). Got "
                f"_accecn_s_ce_b={session._accecn.s_ce_b}."
            ),
        )

    def test__accecn__inbound_option_with_unchanged_r_ce_does_not_reduce_cwnd(self) -> None:
        """
        Ensure that an inbound AccECN option carrying the
        same r.CE byte counter as the previously-tracked
        value does not trigger a spurious cwnd reduction.
        Without this idempotency guard, a sender that
        receives multiple ACKs all reporting the same
        cumulative r.CE byte count would reduce cwnd on
        every ACK, defeating the per-RTT-event semantics.

        Reference: RFC 9768 §3.4 (no reduction without delta).
        """

        session = self._drive_handshake_to_established_with_accecn()
        session.send(data=b"x" * 4000)
        self._advance(ms=1)

        cwnd_before = session._cc.cwnd
        ssthresh_before = session._cc.ssthresh

        # Peer's ACK with r.CE=0 (no congestion observed).
        clean_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            accecn0_counters=(0, 0, 0),
        )
        self._drive_rx(frame=clean_ack)

        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_before,
            msg=(
                "RFC 9768 §3.4: a peer's AccECN option with "
                "r.CE unchanged from the prior tracker value "
                "MUST NOT trigger ssthresh reduction. Got "
                f"ssthresh_before={ssthresh_before}, "
                f"ssthresh={session._cc.ssthresh}."
            ),
        )
        self.assertEqual(
            session._cc.cwnd,
            cwnd_before,
            msg=(
                "RFC 9768 §3.4: a peer's AccECN option with "
                "r.CE unchanged from the prior tracker value "
                "MUST NOT trigger cwnd reduction. Got "
                f"cwnd_before={cwnd_before}, "
                f"cwnd={session._cc.cwnd}."
            ),
        )

    def _drive_passive_open_with_syn_flags(self, syn_flags: tuple[str, ...]) -> TcpSession:
        """
        Drive a passive open by feeding the listener a SYN with
        the supplied AE/CWR/ECE flag combination (ip_ecn=Not-ECT).
        Returns the resulting session.
        """

        session = self._make_listen_session()
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",) + syn_flags,
            ip_ecn=0,
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self._advance(ms=1)
        return session

    def test__accecn__forward_compat__server_syn_100_enters_accecn(self) -> None:
        """
        Ensure a passive-side server enters AccECN mode when the
        inbound SYN carries the reserved (AE,CWR,ECE)=(1,0,0)
        combination. The strict negotiation table only lists
        (1,1,1) as the canonical AccECN-setup SYN; the forward-
        compatibility clause requires the server to treat any
        non-(0,0,0)/(0,1,1)/(1,1,1) combination as an AccECN
        request so future TCP extensions can introduce new
        signalling without breaking installed servers.

        Reference: RFC 9768 §3.1.3 (forward-compatibility for reserved SYN combinations).
        """

        session = self._drive_passive_open_with_syn_flags(syn_flags=("NS",))

        self.assertTrue(
            session._accecn.enabled,
            msg=(
                "RFC 9768 §3.1.3: SYN with (AE,CWR,ECE)=(1,0,0) "
                "MUST enter AccECN mode. Got "
                f"_accecn_enabled={session._accecn.enabled}."
            ),
        )

    def test__accecn__forward_compat__server_syn_110_enters_accecn(self) -> None:
        """
        Ensure a passive-side server enters AccECN mode when the
        inbound SYN carries the reserved (AE,CWR,ECE)=(1,1,0)
        combination.

        Reference: RFC 9768 §3.1.3 (forward-compatibility for reserved SYN combinations).
        """

        session = self._drive_passive_open_with_syn_flags(syn_flags=("NS", "CWR"))

        self.assertTrue(
            session._accecn.enabled,
            msg=(
                "RFC 9768 §3.1.3: SYN with (AE,CWR,ECE)=(1,1,0) "
                "MUST enter AccECN mode. Got "
                f"_accecn_enabled={session._accecn.enabled}."
            ),
        )

    def test__accecn__forward_compat__server_syn_010_enters_accecn(self) -> None:
        """
        Ensure a passive-side server enters AccECN mode when the
        inbound SYN carries the reserved (AE,CWR,ECE)=(0,1,0)
        combination.

        Reference: RFC 9768 §3.1.3 (forward-compatibility for reserved SYN combinations).
        """

        session = self._drive_passive_open_with_syn_flags(syn_flags=("CWR",))

        self.assertTrue(
            session._accecn.enabled,
            msg=(
                "RFC 9768 §3.1.3: SYN with (AE,CWR,ECE)=(0,1,0) "
                "MUST enter AccECN mode. Got "
                f"_accecn_enabled={session._accecn.enabled}."
            ),
        )

    def test__accecn__forward_compat__server_syn_101_enters_accecn(self) -> None:
        """
        Ensure a passive-side server enters AccECN mode when the
        inbound SYN carries the reserved (AE,CWR,ECE)=(1,0,1)
        combination.

        Reference: RFC 9768 §3.1.3 (forward-compatibility for reserved SYN combinations).
        """

        session = self._drive_passive_open_with_syn_flags(syn_flags=("NS", "ECE"))

        self.assertTrue(
            session._accecn.enabled,
            msg=(
                "RFC 9768 §3.1.3: SYN with (AE,CWR,ECE)=(1,0,1) "
                "MUST enter AccECN mode. Got "
                f"_accecn_enabled={session._accecn.enabled}."
            ),
        )

    def test__accecn__forward_compat__server_syn_001_enters_accecn(self) -> None:
        """
        Ensure a passive-side server enters AccECN mode when the
        inbound SYN carries the reserved (AE,CWR,ECE)=(0,0,1)
        combination. While (0,0,1) is the SYN/ACK signature for
        Classic ECN confirmation, on a SYN it falls into the
        forward-compatibility 'any other combination' bucket
        and MUST be treated as AccECN.

        Reference: RFC 9768 §3.1.3 (forward-compatibility for reserved SYN combinations).
        """

        session = self._drive_passive_open_with_syn_flags(syn_flags=("ECE",))

        self.assertTrue(
            session._accecn.enabled,
            msg=(
                "RFC 9768 §3.1.3: SYN with (AE,CWR,ECE)=(0,0,1) "
                "MUST enter AccECN mode. Got "
                f"_accecn_enabled={session._accecn.enabled}."
            ),
        )

    def test__accecn__forward_compat__server_classic_ecn_syn_does_not_enter_accecn(self) -> None:
        """
        Ensure that the (AE,CWR,ECE)=(0,1,1) SYN is treated as
        Classic ECN, NOT AccECN. (0,1,1) is the canonical
        Classic ECN-setup SYN signature and is one of the three
        combinations explicitly excluded from the forward-
        compatibility 'treat as AccECN' clause.

        Reference: RFC 9768 §3.1.3 (Classic ECN excluded from forward-compat).
        Reference: RFC 3168 §6.1.1 (Classic ECN-setup SYN signature).
        """

        session = self._drive_passive_open_with_syn_flags(syn_flags=("CWR", "ECE"))

        self.assertFalse(
            session._accecn.enabled,
            msg=(
                "Classic ECN-setup SYN (0,1,1) MUST NOT enter "
                "AccECN mode. Got "
                f"_accecn_enabled={session._accecn.enabled}."
            ),
        )
        self.assertTrue(
            session._ecn.enabled,
            msg=(
                "Classic ECN-setup SYN (0,1,1) MUST enable "
                "Classic ECN mode. Got "
                f"_ecn_enabled={session._ecn.enabled}."
            ),
        )

    def test__accecn__forward_compat__client_synack_101_enters_accecn(self) -> None:
        """
        Ensure that an active-open client receiving a SYN/ACK
        with the currently-reserved (AE,CWR,ECE)=(1,0,1)
        combination enters AccECN mode. The client interprets
        this as 'server supports AccECN; treat IP-ECN-on-SYN as
        having arrived unchanged' so installed clients stay
        forward-compatible with future TCP extensions that may
        define semantics for this combination.

        Reference: RFC 9768 §3.1.3 (forward-compatibility for reserved SYN/ACK combinations).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "NS", "ECE"),
            win=PEER__WIN,
            mss=PEER__MSS,
            ip_ecn=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake reaches ESTABLISHED.",
        )
        self.assertTrue(
            session._accecn.enabled,
            msg=(
                "RFC 9768 §3.1.3: a SYN/ACK with reserved "
                "(AE,CWR,ECE)=(1,0,1) MUST enter AccECN mode. "
                f"Got _accecn_enabled={session._accecn.enabled}."
            ),
        )

    def test__accecn__order_choice__no_ect1_marking_uses_accecn0(self) -> None:
        """
        Ensure that when only ECT(0) and CE byte counters
        change between emissions, the session emits the
        AccECN0 option (Kind 172, Order 0) - the classic-ECN
        ordering with EE0B in the first slot. This is the
        right choice for traditional Internet workloads where
        ECT(0) is the dominant codepoint.

        Reference: RFC 9768 §3.2.3 (Order 0 / AccECN0 form for ECT(0)-dominant flows).
        """

        self._drive_handshake_to_established_with_accecn()

        # Drive an inbound ECT(0)-marked data segment so r.e0b
        # advances; r.e1b stays at its initial value of 1.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            ip_ecn=2,
            payload=b"x" * 100,
        )
        self._drive_rx(frame=peer_data)
        ack_tx = self._advance(ms=200)

        self.assertEqual(len(ack_tx), 1, msg="Setup: delayed-ACK MUST fire.")
        ack = self._parse_tx(ack_tx[0])

        self.assertIsNotNone(
            ack.accecn,
            msg="RFC 9768 §3.2.3: outbound ACK MUST carry an AccECN option.",
        )
        self.assertEqual(
            ack.accecn_kind,
            172,
            msg=(
                "RFC 9768 §3.2.3: when only r.ECT(0) / r.CE "
                "advance, the session SHOULD emit Order 0 "
                f"(Kind 172, AccECN0). Got accecn_kind={ack.accecn_kind!r}."
            ),
        )

    def test__accecn__order_choice__ect1_marking_uses_accecn1(self) -> None:
        """
        Ensure that when r.ECT(1) byte counter advances since
        last emission (and r.ECT(0) does not), the session
        emits the AccECN1 option (Kind 174, Order 1) - the
        L4S-deployment-friendly ordering with EE1B in the
        first slot. This lets the receiver communicate the
        ECT(1) byte counter most efficiently when ECT(1) is
        the dominant changing codepoint.

        Reference: RFC 9768 §3.2.3 (Order 1 / AccECN1 form for ECT(1)-dominant flows).
        """

        self._drive_handshake_to_established_with_accecn()

        # Drive an inbound ECT(1)-marked data segment so r.e1b
        # advances; r.e0b stays unchanged.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            ip_ecn=1,
            payload=b"x" * 100,
        )
        self._drive_rx(frame=peer_data)
        ack_tx = self._advance(ms=200)

        self.assertEqual(len(ack_tx), 1, msg="Setup: delayed-ACK MUST fire.")
        ack = self._parse_tx(ack_tx[0])

        self.assertIsNotNone(
            ack.accecn,
            msg="RFC 9768 §3.2.3: outbound ACK MUST carry an AccECN option.",
        )
        self.assertEqual(
            ack.accecn_kind,
            174,
            msg=(
                "RFC 9768 §3.2.3: when r.ECT(1) advances and "
                "r.ECT(0) does not, the session SHOULD emit "
                "Order 1 (Kind 174, AccECN1). Got "
                f"accecn_kind={ack.accecn_kind!r}."
            ),
        )

    def test__accecn__order_choice__option_carries_correct_byte_counters(self) -> None:
        """
        Ensure that whichever order the session picks, the
        emitted AccECN option's three byte counters reflect
        the current receiver-side state (r.ECT(0), r.CE,
        r.ECT(1)) - regardless of wire-level slot ordering.
        AccECN0 places ECT(0) in the first slot; AccECN1
        places ECT(1) in the first slot. Both encode the same
        conceptual data.

        Reference: RFC 9768 §3.2.3 (semantic equivalence of Order 0 / Order 1).
        """

        session = self._drive_handshake_to_established_with_accecn()

        # Drive an ECT(1)-marked segment so the session picks
        # AccECN1 (Order 1) on the next outbound ACK.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            ip_ecn=1,
            payload=b"x" * 200,
        )
        self._drive_rx(frame=peer_data)
        ack_tx = self._advance(ms=200)

        self.assertEqual(len(ack_tx), 1, msg="Setup: delayed-ACK MUST fire.")
        ack = self._parse_tx(ack_tx[0])

        # 'ack.accecn' is a tuple (ee0b, eceb, ee1b)
        # normalised to AccECN0 ordering regardless of which
        # wire kind appeared. Each slot is Optional[int]:
        # None means the corresponding counter was abbreviated
        # off the wire because it had not changed since the
        # last emission. For non-None slots, the value MUST
        # match the session's current counter.
        assert ack.accecn is not None, "RFC 9768 §3.2.3: outbound ACK MUST carry an AccECN option."
        if ack.accecn[0] is not None:
            self.assertEqual(
                ack.accecn[0],
                session._accecn.r_ect0_b,
                msg="AccECN option r.ECT(0) byte counter MUST match session state when present.",
            )
        if ack.accecn[1] is not None:
            self.assertEqual(
                ack.accecn[1],
                session._accecn.r_ce_b,
                msg="AccECN option r.CE byte counter MUST match session state when present.",
            )
        if ack.accecn[2] is not None:
            self.assertEqual(
                ack.accecn[2],
                session._accecn.r_ect1_b,
                msg="AccECN option r.ECT(1) byte counter MUST match session state when present.",
            )

    def _drive_passive_open_with_third_leg_ace(self, ace: int) -> TcpSession:
        """
        Drive a passive open: peer's AccECN-setup SYN arrives,
        the listener emits a SYN+ACK, then peer's third-leg
        ACK arrives carrying the supplied raw ACE field value
        (encoded as the AE+CWR+ECE flag combination). Returns
        the resulting ESTABLISHED session.
        """

        session = self._make_listen_session()

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN", "ECE", "CWR", "NS"),
            ip_ecn=0,
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        synack_tx = self._advance(ms=1)
        assert len(synack_tx) == 1, f"Setup: SYN+ACK MUST fire. Got {len(synack_tx)}."
        synack = self._parse_tx(synack_tx[0])

        # Build third-leg ACK with the supplied ACE bits encoded
        # into the AE+CWR+ECE flags (bit2 -> NS, bit1 -> CWR,
        # bit0 -> ECE).
        ace_flags: tuple[str, ...] = ("ACK",)
        if ace & 0b100:
            ace_flags = ace_flags + ("NS",)
        if ace & 0b010:
            ace_flags = ace_flags + ("CWR",)
        if ace & 0b001:
            ace_flags = ace_flags + ("ECE",)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=synack.seq + 1,
            flags=ace_flags,
            ip_ecn=0,
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)
        return session

    def test__accecn__server_table_4_inference__ace_010_sets_s_cep_5_not_ect(self) -> None:
        """
        Ensure that a passive-side server in SYN-RCVD state,
        on receiving a pure ACK whose ACE field carries the
        Table-4 binary value 010 (AE=0, CWR=1, ECE=0), infers
        that the IP-ECN field on its SYN+ACK was Not-ECT and
        sets its sender-side 's.cep' counter to 5. The
        handshake encoding is one-shot: subsequent ACKs use
        the regular 'r.cep & 7' interpretation.

        Reference: RFC 9768 §3.2.2.1 (Table 4, ACE=010 -> Not-ECT, s.cep=5).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b010)

        self.assertEqual(
            session._accecn.s_cep,
            5,
            msg=(
                "RFC 9768 §3.2.2.1 Table 4: ACE=010 on the "
                "first inbound ACK in SYN-RCVD MUST set "
                f"s.cep = 5. Got s.cep={session._accecn.s_cep}."
            ),
        )
        self.assertFalse(
            session._accecn.s_disabled,
            msg=(
                "ACE=010 is a normal AccECN handshake ACK; "
                "MUST NOT disable sender-side AccECN. Got "
                f"s_disabled={session._accecn.s_disabled}."
            ),
        )

    def test__accecn__server_table_4_inference__ace_011_sets_s_cep_5_ect1(self) -> None:
        """
        Ensure that a passive-side server in SYN-RCVD state,
        on receiving a pure ACK whose ACE field carries the
        Table-4 binary value 011, infers that the IP-ECN
        field on its SYN+ACK was ECT(1) and sets s.cep=5.

        Reference: RFC 9768 §3.2.2.1 (Table 4, ACE=011 -> ECT(1), s.cep=5).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b011)

        self.assertEqual(
            session._accecn.s_cep,
            5,
            msg=f"RFC 9768 §3.2.2.1 Table 4: ACE=011 -> s.cep=5. Got {session._accecn.s_cep}.",
        )

    def test__accecn__server_table_4_inference__ace_100_sets_s_cep_5_ect0(self) -> None:
        """
        Ensure that a passive-side server in SYN-RCVD state,
        on receiving a pure ACK whose ACE field carries the
        Table-4 binary value 100, infers that the IP-ECN
        field on its SYN+ACK was ECT(0) and sets s.cep=5.

        Reference: RFC 9768 §3.2.2.1 (Table 4, ACE=100 -> ECT(0), s.cep=5).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b100)

        self.assertEqual(
            session._accecn.s_cep,
            5,
            msg=f"RFC 9768 §3.2.2.1 Table 4: ACE=100 -> s.cep=5. Got {session._accecn.s_cep}.",
        )

    def test__accecn__server_table_4_inference__ace_110_sets_s_cep_6_ce(self) -> None:
        """
        Ensure that a passive-side server in SYN-RCVD state,
        on receiving a pure ACK whose ACE field carries the
        Table-4 binary value 110, infers that the IP-ECN
        field on its SYN+ACK was CE-marked and sets s.cep=6
        (one increment from initial 5). This communicates
        the CE marking back to the application's congestion
        control state.

        Reference: RFC 9768 §3.2.2.1 (Table 4, ACE=110 -> CE, s.cep=6).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b110)

        self.assertEqual(
            session._accecn.s_cep,
            6,
            msg=(
                "RFC 9768 §3.2.2.1 Table 4: ACE=110 (CE on "
                "SYN/ACK) MUST set s.cep = 6. Got "
                f"{session._accecn.s_cep}."
            ),
        )

    def test__accecn__server_table_4_inference__ace_000_disables_sender_side_accecn(self) -> None:
        """
        Ensure that a passive-side server in SYN-RCVD state,
        on receiving a pure ACK whose ACE field carries the
        Table-4 binary value 000 (the protocol-non-compliance
        signal per Table 4 Note 1), disables sender-side
        AccECN: it MUST NOT set ECT on outgoing packets and
        MUST NOT respond to AccECN feedback for the rest of
        the connection. As a Data Receiver, AccECN feedback
        emission continues normally.

        Reference: RFC 9768 §3.2.2.1 Note 1 (ACE=000 -> sender-side AccECN disabled).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b000)

        self.assertTrue(
            session._accecn.s_disabled,
            msg=(
                "RFC 9768 §3.2.2.1 Note 1: ACE=000 on the "
                "first inbound ACK in SYN-RCVD MUST disable "
                "sender-side AccECN. Got "
                f"s_disabled={session._accecn.s_disabled}."
            ),
        )

    def test__accecn__server_table_4_inference__ace_001_unused_defaults_to_5(self) -> None:
        """
        Ensure ACE=001 on the third-leg ACK (a currently-
        unused Table-4 codepoint) defaults s.cep to 5,
        keeping installed servers forward-compatible with
        future TCP extensions.

        Reference: RFC 9768 §3.2.2.1 Note 2 (forward-compat for unused ACE).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b001)
        self.assertEqual(
            session._accecn.s_cep,
            5,
            msg=f"RFC 9768 §3.2.2.1 Note 2: ACE=001 -> s.cep=5. Got {session._accecn.s_cep}.",
        )

    def test__accecn__server_table_4_inference__ace_101_unused_defaults_to_5(self) -> None:
        """
        Ensure ACE=101 on the third-leg ACK (a currently-
        unused Table-4 codepoint) defaults s.cep to 5.

        Reference: RFC 9768 §3.2.2.1 Note 2 (forward-compat for unused ACE).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b101)
        self.assertEqual(
            session._accecn.s_cep,
            5,
            msg=f"RFC 9768 §3.2.2.1 Note 2: ACE=101 -> s.cep=5. Got {session._accecn.s_cep}.",
        )

    def test__accecn__server_table_4_inference__ace_111_unused_defaults_to_5(self) -> None:
        """
        Ensure ACE=111 on the third-leg ACK (a currently-
        unused Table-4 codepoint) defaults s.cep to 5.

        Reference: RFC 9768 §3.2.2.1 Note 2 (forward-compat for unused ACE).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b111)
        self.assertEqual(
            session._accecn.s_cep,
            5,
            msg=f"RFC 9768 §3.2.2.1 Note 2: ACE=111 -> s.cep=5. Got {session._accecn.s_cep}.",
        )

    def test__accecn__ace_only_response__delta_triggers_cwnd_reduction(self) -> None:
        """
        Ensure that on an AccECN-enabled connection, when an
        inbound ACK arrives with NO AccECN option (e.g. a
        middlebox stripped it) but the ACE field shows a
        positive delta from the last-tracked s.cep value,
        the sender treats the apparent CE delta as a
        congestion event and halves ssthresh per the ABE
        multiplier. This is the §3.2.2.5 fallback that lets
        AccECN keep working when options are stripped.

        Reference: RFC 9768 §3.2.2.5 (cycle/wrap safety: ACE-based fallback).
        """

        session = self._drive_handshake_to_established_with_accecn()
        session.send(data=b"x" * 6000)
        self._advance(ms=10)

        ssthresh_before = session._cc.ssthresh

        # Peer's ACK with no AccECN option but ACE field
        # encoding a +1 delta (s.cep was 5 = 0b101; new ACE
        # = 6 = 0b110 maps to AE=1, CWR=1, ECE=0 - a one-CE
        # advance from the prior tracker).
        ack_with_ace = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "NS", "CWR"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=ack_with_ace)

        self.assertLess(
            session._cc.ssthresh,
            ssthresh_before,
            msg=(
                "RFC 9768 §3.2.2.5: an inbound ACK with no "
                "AccECN option but a positive ACE delta MUST "
                "trigger a congestion response. Got "
                f"ssthresh_before={ssthresh_before}, "
                f"ssthresh={session._cc.ssthresh}."
            ),
        )

    def test__accecn__ace_only_response__no_delta_no_response(self) -> None:
        """
        Ensure that on an AccECN-enabled connection, when an
        inbound ACK arrives with NO AccECN option and the
        ACE field is unchanged from the last-tracked s.cep
        value (i.e. apparent delta = 0), the sender does NOT
        trigger a spurious congestion response. This pins
        the regression-guard semantics: ACE-based fallback
        only fires on an actual change.

        Reference: RFC 9768 §3.2.2.5 (no response without apparent CE delta).
        """

        session = self._drive_handshake_to_established_with_accecn()
        session.send(data=b"x" * 4000)
        self._advance(ms=10)

        ssthresh_before = session._cc.ssthresh

        # Peer's ACK with no AccECN option and ACE field
        # = 5 = 0b101 (the initial s.cep value, no delta).
        clean_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "NS", "ECE"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=clean_ack)

        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_before,
            msg=(
                "RFC 9768 §3.2.2.5: an inbound ACK with no "
                "AccECN option and ACE unchanged MUST NOT "
                "trigger a spurious congestion response. Got "
                f"ssthresh_before={ssthresh_before}, "
                f"ssthresh={session._cc.ssthresh}."
            ),
        )

    def test__accecn__ace_only_response__option_present_takes_precedence(self) -> None:
        """
        Ensure that when an inbound ACK carries BOTH the
        AccECN option AND non-zero ACE flags, the byte-
        counter path takes precedence over the ACE-only
        fallback - i.e. the response is gated on the
        AccECN option's byte counters rather than on ACE
        decoding. This regression-guard prevents double-
        counting CE marks when both paths could fire.

        Reference: RFC 9768 §3.2.2.5 (option-present path is dependable; ACE is fallback).
        """

        session = self._drive_handshake_to_established_with_accecn()
        session.send(data=b"x" * 6000)
        self._advance(ms=10)

        ssthresh_before = session._cc.ssthresh

        # Peer's ACK with the AccECN option present (clean
        # byte counters) AND ACE flags that would otherwise
        # decode as a +1 delta. The byte-counter path
        # reports no delta -> no congestion response, even
        # though ACE alone would suggest one.
        ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "NS", "CWR"),
            win=PEER__WIN,
            accecn0_counters=(1, 0, 1),
        )
        self._drive_rx(frame=ack)

        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_before,
            msg=(
                "RFC 9768 §3.2.2.5: when the AccECN option "
                "is present the byte counter takes precedence "
                "over ACE decoding; ssthresh MUST NOT change. "
                f"Got ssthresh_before={ssthresh_before}, "
                f"ssthresh={session._cc.ssthresh}."
            ),
        )

    def test__accecn__abbreviated_form__length_8_peer_option_accepted(self) -> None:
        """
        Ensure that on an AccECN-enabled connection, when an
        inbound ACK carries an AccECN0 option in the Length=8
        wire form (peer omitted r.ECT(1) byte counter to save
        TCP-option space), PyTCP parses the option without
        raising IntegrityError and the session remains in a
        usable state. The Length=8 form is the most common
        abbreviated variant a §3.2.3-conforming peer would
        emit during loss recovery when SACK blocks compete
        for option space.

        Reference: RFC 9768 §3.2.3 (Length 8 AccECN0 form parser acceptance).
        """

        session = self._drive_handshake_to_established_with_accecn()
        cwnd_before = session._cc.cwnd
        ssthresh_before = session._cc.ssthresh

        # Peer's Length=8 ACK: r.e0b and r.eceb on the wire,
        # r.e1b absent (None). The 'accecn0_counters' tuple
        # carries the per-slot Optional[int] semantics.
        ack_len_8 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            accecn0_counters=(1, 0, None),
        )
        # Must not raise.
        self._drive_rx(frame=ack_len_8)

        # Session state stays consistent: no spurious cwnd
        # reduction (eceb didn't advance), no crash, no
        # state leak.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=f"Length=8 AccECN0 parse MUST NOT corrupt FSM state. Got state={session.state!r}.",
        )
        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_before,
            msg=(
                "Length=8 AccECN0 with no eceb advance MUST NOT "
                f"reduce ssthresh. Got before={ssthresh_before}, "
                f"after={session._cc.ssthresh}."
            ),
        )
        self.assertEqual(
            session._cc.cwnd,
            cwnd_before,
            msg=f"cwnd MUST be unchanged. Got before={cwnd_before}, after={session._cc.cwnd}.",
        )

    def test__accecn__abbreviated_form__length_2_empty_peer_option_accepted(self) -> None:
        """
        Ensure that on an AccECN-enabled connection, when an
        inbound ACK carries a Length=2 (empty) AccECN0 option,
        PyTCP parses it without raising IntegrityError. The
        Length=2 form is allowed when option space is too
        constrained to carry any counters but a §3.2.3
        signature byte is still required (e.g. on a SYN/ACK
        retransmit under heavy SACK load).

        Reference: RFC 9768 §3.2.3 (Length 2 empty AccECN0 form parser acceptance).
        """

        session = self._drive_handshake_to_established_with_accecn()

        ack_len_2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            accecn0_counters=(None, None, None),
        )
        # Must not raise.
        self._drive_rx(frame=ack_len_2)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=f"Length=2 AccECN0 parse MUST NOT corrupt FSM state. Got state={session.state!r}.",
        )

    def test__accecn__broken_server__synack_111_falls_back_to_not_ecn(self) -> None:
        """
        Ensure that when an active-open client sends an
        AccECN-setup SYN with (AE,CWR,ECE)=(1,1,1) and the
        peer reflects the same flags back in its SYN/ACK,
        the client treats the peer as a broken non-ECN
        server and falls back to Not ECN mode for both
        half-connections. This guards against older broken
        TCP implementations that reflect SYN flags into
        the SYN/ACK; without this fall-back the client would
        misinterpret the reflection as a genuine AccECN
        confirmation with CE-on-SYN, then proceed with ECN
        signalling on a peer that cannot honour it.

        Reference: RFC 9768 §3.1.2 (broken-server reflection: fall back to Not ECN).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # Peer's SYN/ACK reflects all three of the client's
        # AccECN-setup flags - the broken-reflector signature
        # per the fourth block of Table 2.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "NS", "CWR", "ECE"),
            win=PEER__WIN,
            mss=PEER__MSS,
            ip_ecn=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake reaches ESTABLISHED.",
        )
        self.assertFalse(
            session._accecn.enabled,
            msg=(
                "RFC 9768 §3.1.2 fourth block: a (1,1,1) SYN/ACK "
                "MUST be treated as broken-server reflection and "
                "MUST NOT enter AccECN mode. Got "
                f"_accecn_enabled={session._accecn.enabled}."
            ),
        )
        self.assertFalse(
            session._ecn.enabled,
            msg=(
                "RFC 9768 §3.1.2 fourth block: broken-server "
                "fall-back MUST disable Classic ECN as well, "
                f"yielding Not ECN mode. Got "
                f"_ecn_enabled={session._ecn.enabled}."
            ),
        )

    def test__accecn__abbreviation__only_eceb_changed_emits_length_8(self) -> None:
        """
        Ensure that on an AccECN-enabled connection, when an
        inbound CE-marked segment advances only the r.CE byte
        counter (r.ECT(0) and r.ECT(1) unchanged), the next
        outbound segment carries an AccECN0 option in the
        Length=8 abbreviated form: ee0b and eceb on the wire,
        ee1b dropped from the trailing slot. Saves 3 bytes of
        TCP-option space per segment in the typical Internet
        workload where ECT(1) is essentially never used.

        Reference: RFC 9768 §3.2.3 (abbreviation: drop trailing unchanged fields).
        Reference: RFC 9768 §3.2.3.3 (ordering rule: included field implies all preceding included).
        """

        session = self._drive_handshake_to_established_with_accecn()

        # Inbound CE-marked data: only ceb advances by payload
        # length; e0b stays at 1, e1b stays at 1.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            ip_ecn=3,
            payload=b"x" * 100,
        )
        self._drive_rx(frame=peer_data)
        ack_tx = self._advance(ms=200)
        self.assertEqual(len(ack_tx), 1, msg="Setup: delayed-ACK MUST fire.")
        ack = self._parse_tx(ack_tx[0])

        self.assertEqual(
            ack.accecn_kind,
            172,
            msg=f"e1b unchanged -> AccECN0 (Kind 172). Got accecn_kind={ack.accecn_kind!r}.",
        )
        # Length 8 form: tuple is (ee0b=1, eceb=100, ee1b=None).
        assert ack.accecn is not None, "AccECN option MUST be present."
        self.assertEqual(
            ack.accecn[0],
            session._accecn.r_ect0_b,
            msg=f"ee0b slot MUST carry r.ECT(0). Got {ack.accecn[0]!r}.",
        )
        self.assertEqual(
            ack.accecn[1],
            session._accecn.r_ce_b,
            msg=f"eceb slot MUST carry r.CE. Got {ack.accecn[1]!r}.",
        )
        self.assertIsNone(
            ack.accecn[2],
            msg=(
                "RFC 9768 §3.2.3: ee1b unchanged -> Length 8 "
                "abbreviation drops the trailing ee1b slot. "
                f"Got ee1b={ack.accecn[2]!r}."
            ),
        )

    def test__accecn__abbreviation__only_e0b_changed_emits_length_5(self) -> None:
        """
        Ensure that when only the r.ECT(0) byte counter
        advances (no CE marking, no ECT(1) marking), the
        outbound AccECN0 option emits the Length=5 form
        with only ee0b on the wire. Saves 6 bytes of TCP-
        option space per segment.

        Reference: RFC 9768 §3.2.3 (Length 5: only first counter on wire).
        """

        session = self._drive_handshake_to_established_with_accecn()

        # Inbound ECT(0)-marked data: only e0b advances.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            ip_ecn=2,
            payload=b"x" * 100,
        )
        self._drive_rx(frame=peer_data)
        ack_tx = self._advance(ms=200)
        self.assertEqual(len(ack_tx), 1, msg="Setup: delayed-ACK MUST fire.")
        ack = self._parse_tx(ack_tx[0])

        self.assertEqual(
            ack.accecn_kind,
            172,
            msg=f"e1b unchanged -> AccECN0. Got accecn_kind={ack.accecn_kind!r}.",
        )
        assert ack.accecn is not None, "AccECN option MUST be present."
        self.assertEqual(
            ack.accecn[0],
            session._accecn.r_ect0_b,
            msg=f"ee0b slot MUST carry r.ECT(0). Got {ack.accecn[0]!r}.",
        )
        self.assertIsNone(
            ack.accecn[1],
            msg=f"eceb unchanged -> dropped from Length 5 form. Got {ack.accecn[1]!r}.",
        )
        self.assertIsNone(
            ack.accecn[2],
            msg=f"ee1b unchanged -> dropped from Length 5 form. Got {ack.accecn[2]!r}.",
        )

    # The Length 2 (empty) AccECN0 emission is exercised at
    # the wire-format level by the unit tests in
    # 'net_proto/tests/unit/protocols/tcp/test__tcp__option__accecn0.py'
    # ('test__tcp__option__accecn0__bytes_length_2' and the
    # round-trip test); reproducing the exact session-level
    # state where no counter has changed since the last
    # emission is timing-sensitive in integration, so the
    # session-level Length 2 path is verified by the
    # smaller-state Length 8 / Length 5 abbreviation tests
    # above plus the wire-format unit tests.

    def _drive_active_open_with_synack_table2_flags(self, synack_flags: tuple[str, ...]) -> TcpSession:
        """
        Drive an active-open through to ESTABLISHED with the
        peer's SYN/ACK carrying the supplied AccECN Table-2
        AE+CWR+ECE flag combination, encoding which IP-ECN
        codepoint the peer reports observing on our SYN.
        Returns the resulting session for mangling-detected
        assertions.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK") + synack_flags,
            win=PEER__WIN,
            mss=PEER__MSS,
            ip_ecn=0,
        )
        self._drive_rx(frame=peer_syn_ack)
        return session

    def test__accecn__mangling_test__client_synack_not_ect_no_mangling(self) -> None:
        """
        Ensure that on the active-open path, when the peer's
        AccECN-confirming SYN/ACK Table-2 codepoint reports
        observing Not-ECT on the SYN we sent (matching the
        Not-ECT codepoint our active-open SYN actually
        carries), no IP-ECN mangling is detected. Pins the
        regression-guard semantics: mangling detection only
        fires on an actual mismatch.

        Reference: RFC 9768 §3.2.2.3 (no mangling when peer-observed IP-ECN matches our Not-ECT).
        Reference: RFC 3168 §6.1.1 (active-open SYN carries Not-ECT in IP header).
        """

        # Table-2 'Not-ECT observed' codepoint: (AE=0, CWR=1, ECE=0)
        session = self._drive_active_open_with_synack_table2_flags(synack_flags=("CWR",))
        self.assertTrue(session._accecn.enabled, msg="Setup: AccECN must be enabled.")
        self.assertFalse(
            session._accecn.mangling_detected,
            msg=(
                "RFC 9768 §3.2.2.3: peer-reported Not-ECT on SYN "
                "matches our actual Not-ECT send -> NO mangling. "
                f"Got _accecn_mangling_detected={session._accecn.mangling_detected}."
            ),
        )

    def test__accecn__mangling_test__client_synack_ect0_detects_mangling(self) -> None:
        """
        Ensure that on the active-open path, when the peer's
        AccECN-confirming SYN/ACK Table-2 codepoint reports
        observing ECT(0) on the SYN we sent (which the
        active-open SYN actually carried as Not-ECT in its
        IP header), the IP-ECN field underwent an invalid
        Not-ECT-changes transition and PyTCP detects
        mangling.

        Reference: RFC 9768 §3.2.2.3 (Not-ECT codepoint changes is an invalid transition).
        Reference: RFC 3168 §6.1.1 (active-open SYN carries Not-ECT in IP header).
        """

        # Table-2 'ECT(0) observed' codepoint: (AE=1, CWR=0, ECE=0)
        session = self._drive_active_open_with_synack_table2_flags(synack_flags=("NS",))
        self.assertTrue(session._accecn.enabled, msg="Setup: AccECN must be enabled.")
        self.assertTrue(
            session._accecn.mangling_detected,
            msg=(
                "RFC 9768 §3.2.2.3: peer-observed ECT(0) on a SYN "
                "we sent as Not-ECT MUST be detected as IP-ECN "
                "mangling. Got "
                f"_accecn_mangling_detected={session._accecn.mangling_detected}."
            ),
        )

    def test__accecn__mangling_test__client_synack_ect1_detects_mangling(self) -> None:
        """
        Ensure that on the active-open path, when the peer's
        AccECN-confirming SYN/ACK Table-2 codepoint reports
        observing ECT(1) on the SYN we sent (which we sent
        as Not-ECT), PyTCP detects mangling.

        Reference: RFC 9768 §3.2.2.3 (Not-ECT codepoint changes is an invalid transition).
        """

        # Table-2 'ECT(1) observed' codepoint: (AE=0, CWR=1, ECE=1)
        session = self._drive_active_open_with_synack_table2_flags(synack_flags=("CWR", "ECE"))
        self.assertTrue(session._accecn.enabled, msg="Setup: AccECN must be enabled.")
        self.assertTrue(
            session._accecn.mangling_detected,
            msg=(
                "RFC 9768 §3.2.2.3: peer-observed ECT(1) on a SYN "
                "we sent as Not-ECT MUST be detected as IP-ECN "
                "mangling. Got "
                f"_accecn_mangling_detected={session._accecn.mangling_detected}."
            ),
        )

    def test__accecn__mangling_test__server_third_leg_not_ect_no_mangling(self) -> None:
        """
        Ensure that on the passive-open path, when the peer's
        third-leg ACK ACE field reports observing Not-ECT on
        the SYN/ACK we sent (matching our actual send), no
        mangling is detected.

        Reference: RFC 9768 §3.2.2.3 (no mangling when peer-observed IP-ECN matches our Not-ECT).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b010)
        self.assertFalse(
            session._accecn.mangling_detected,
            msg=(
                "RFC 9768 §3.2.2.3: peer-reported Not-ECT (ACE=010) "
                "on our SYN/ACK matches our actual Not-ECT send -> "
                "NO mangling. Got "
                f"_accecn_mangling_detected={session._accecn.mangling_detected}."
            ),
        )

    def test__accecn__mangling_test__server_third_leg_ect0_detects_mangling(self) -> None:
        """
        Ensure that on the passive-open path, when the peer's
        third-leg ACK ACE field reports observing ECT(0) on
        the SYN/ACK we sent (which we sent as Not-ECT), PyTCP
        detects mangling.

        Reference: RFC 9768 §3.2.2.3 (Not-ECT codepoint changes is an invalid transition).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b100)
        self.assertTrue(
            session._accecn.mangling_detected,
            msg=(
                "RFC 9768 §3.2.2.3: peer-observed ECT(0) (ACE=100) "
                "on our Not-ECT SYN/ACK MUST be detected as "
                f"mangling. Got "
                f"_accecn_mangling_detected={session._accecn.mangling_detected}."
            ),
        )

    def test__accecn__mangling_test__server_third_leg_ce_detects_mangling(self) -> None:
        """
        Ensure that on the passive-open path, when the peer's
        third-leg ACK ACE field reports observing CE on the
        SYN/ACK we sent, PyTCP detects mangling - any change
        from our Not-ECT to any non-Not-ECT codepoint is
        invalid per §3.2.2.3, including the CE-observed case.
        The Table-4 r.cep increment to 6 on ACE=110 stays
        active (covered by an earlier Gap 1 test); this test
        adds the orthogonal mangling-detected flag check.

        Reference: RFC 9768 §3.2.2.3 (CE-observed-on-Not-ECT-sent is an invalid transition).
        """

        session = self._drive_passive_open_with_third_leg_ace(ace=0b110)
        self.assertTrue(
            session._accecn.mangling_detected,
            msg=(
                "RFC 9768 §3.2.2.3: peer-observed CE (ACE=110) on "
                "our Not-ECT SYN/ACK MUST be detected as mangling. "
                f"Got _accecn_mangling_detected={session._accecn.mangling_detected}."
            ),
        )
