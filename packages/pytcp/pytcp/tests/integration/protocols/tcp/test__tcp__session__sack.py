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
This module contains integration tests for the TCP Selective
Acknowledgment (SACK) option support in the 'TcpSession' state
machine per RFC 2018 / RFC 6675.

See 'docs/rfc/tcp/rfc2018__sack/adherence.md' and
'docs/rfc/tcp/rfc6675__sack_loss_recovery/adherence.md' for
the per-clause spec audits.

Reference RFCs:
    RFC 2018            TCP Selective Acknowledgment Options
    RFC 2883            DSACK extension (deferred to phase 7)
    RFC 6675            Conservative Loss Recovery using SACK
    RFC 9293 §3.10.7.4  Synchronized state segment processing

pytcp/tests/integration/protocols/tcp/test__tcp__session__sack.py

ver 3.0.10
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__loss_recovery import pipe
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing for log readability and reproducibility.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
LISTEN__PORT: int = 80
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80
PEER__PASSIVE_PORT: int = 33000

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460


class TestTcpSession__Sack(TcpTestCase):
    """
    Integration tests for the TCP SACK option in the session FSM.
    Phase 1 covers the wire-level passthrough; phase 3 covers
    bilateral SACK-Permitted negotiation and receive-side SACK
    block emission on outbound ACKs when out-of-order data is
    queued.
    """

    def _make_listen_session(self, *, iss: int) -> TcpSession:
        """
        Build a wildcard-bound listening 'TcpSocket' / 'TcpSession'
        pair the way 'TcpSocket.listen()' would wire them, drive
        the LISTEN syscall so the FSM transitions CLOSED -> LISTEN,
        and return the session.
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

        session.tcp_fsm(syscall=SysCall.LISTEN)
        return session

    def test__sack__inbound_sack_option_does_not_crash_parser(self) -> None:
        """
        Ensure that an inbound ACK segment carrying a SACK
        option is consumed by the wire path without raising
        and without forcing a state transition. The TCP
        parser decodes 'TcpOptionSack' into '(left, right)'
        blocks; SACK is informational, never a control
        signal at the FSM level.

        Reference: RFC 2018 §3 (SACK option wire format).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        peer_ack_with_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(0xDEAD_BEEF, 0xDEAD_BF13)],
        )
        inline_tx = self._drive_rx(frame=peer_ack_with_sack)

        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "An inbound SACK-bearing dup-ACK must not elicit any "
                "inline TX from the FSM today; the option is decoded "
                "by the parser and silently consumed."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "An inbound SACK-bearing segment must not force a "
                "state transition out of ESTABLISHED; SACK is "
                "informational, never a control signal at the FSM "
                "level."
            ),
        )

    def test__sack__inbound_sack_blocks_silently_consumed_when_send_sack_disabled(self) -> None:
        """
        Ensure that when the bilateral SACK negotiation has
        not succeeded ('_send_sack = False'), an inbound ACK
        carrying SACK blocks is silently consumed: the
        scoreboard is not updated, no scoreboard-driven TX
        fires, and send-side counters do not move.

        Reference: RFC 2018 §3 (SACK information meaningful only when bilaterally negotiated).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Bypass slow-start so the application's send drains in one
        # outbound segment - we want a clean post-data state to
        # contrast with after the SACK-bearing dup-ACK arrives.
        session._cc.snd_ewn = PEER__WIN

        payload = b"X" * 200
        session.send(data=payload)
        self._advance(ms=1)

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt
        snd_max_before = session._snd_seq.max

        self.assertFalse(
            session._advertise.send_sack,
            msg=(
                "Setup precondition: bilateral SACK negotiation must "
                "have failed (peer didn't offer) so '_send_sack' is "
                "False - this test pins the ingestion-gate behaviour."
            ),
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "A fresh ESTABLISHED session must start with an empty "
                "SACK scoreboard - nothing has been peer-SACKed yet."
            ),
        )

        # Peer sends a dup-ACK whose SACK block claims to have
        # received the upper half of our outstanding range.
        sacked_left = LOCAL__ISS + 1 + 100
        sacked_right = LOCAL__ISS + 1 + 200
        peer_dup_ack_with_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        inline_tx = self._drive_rx(frame=peer_dup_ack_with_sack)

        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "An inbound dup-ACK without bilateral SACK must not "
                "synthesise any reply; SACK info is informational and "
                "the count-based dup-ACK threshold has not been met."
            ),
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "With '_send_sack = False' the scoreboard MUST remain "
                "empty even when peer sends SACK blocks - the "
                "ingestion gate per RFC 2018 §3 refuses to record "
                "SACK info on a connection where bilateral "
                "negotiation failed."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            snd_una_before,
            msg=(
                "A dup-ACK with SACK info must not advance SND.UNA - " "the cumulative ACK in the segment is unchanged."
            ),
        )
        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_before,
            msg=(
                "SND.NXT must not be perturbed by a SACK-bearing "
                "dup-ACK below the count-based fast-retransmit "
                "threshold."
            ),
        )
        self.assertEqual(
            session._snd_seq.max,
            snd_max_before,
            msg=(
                "SND.MAX must not be perturbed by a SACK-bearing "
                "dup-ACK; nothing on the SACK ingestion path "
                "extends the sent-bytes high-water mark."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Session must remain in ESTABLISHED after a SACK-"
                "bearing dup-ACK; the option does not affect the "
                "FSM transition rules."
            ),
        )

    def test__sack__outbound_syn_advertises_sack_permitted(self) -> None:
        """
        Ensure that an active-open session emits its initial
        SYN with the SACK-Permitted option, and that the
        session defaults to advertising it
        ('_advertise_sack = True').

        Reference: RFC 2018 §2 (SACK-Permitted option, offered on opening SYN).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self._assert_segment(
            syn_probe,
            flags=frozenset({"SYN"}),
            sackperm=True,
        )
        self.assertTrue(
            session._advertise.sack,
            msg="The default value of 'TcpSession._advertise.sack' must be True.",
        )

    def test__sack__bilateral_sack_negotiation_sets_send_sack(self) -> None:
        """
        Ensure that when both sides advertise SACK-Permitted
        on their SYN exchange, the active-open session
        records the successful bilateral negotiation by
        setting 'self._advertise.send_sack = True'.

        Reference: RFC 2018 §2 (SACK bilateral negotiation).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )
        self.assertTrue(
            session._advertise.send_sack,
            msg=(
                "After bilateral SACK-Permitted negotiation "
                "the session must record success in "
                "'_send_sack = True'."
            ),
        )

    def test__sack__out_of_order_data_segment_elicits_sack_block_in_outbound_ack(self) -> None:
        """
        Ensure that when a peer's data segment arrives out
        of order (gap before it), the resulting outbound
        dup-ACK carries a SACK option whose single block
        reports the buffered OOO range
        '[seq, seq + len(payload))'.

        Reference: RFC 2018 §4 (SACK block ordering, segment-triggering-ACK first).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        # Sanity: bilateral negotiation must have succeeded so the
        # SACK-emit path is enabled.
        self.assertTrue(
            session._advertise.send_sack,
            msg="Setup precondition: bilateral SACK negotiation must have succeeded.",
        )

        ooo_seg = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        ooo_tx = self._drive_rx(frame=ooo_seg)
        self.assertEqual(
            len(ooo_tx),
            1,
            msg=("An OOO segment arriving above RCV.NXT must elicit " "exactly one outbound ACK pointing at the gap."),
        )
        ooo_ack = self._parse_tx(ooo_tx[0])
        self._assert_segment(
            ooo_ack,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1,
            sack_blocks=[(PEER__ISS + 1 + 100, PEER__ISS + 1 + 200)],
        )

    def test__sack__multiple_ooo_segments_yield_multiple_sack_blocks(self) -> None:
        """
        Ensure that when multiple OOO segments are buffered,
        the outbound SACK option carries one block per
        disjoint OOO range, up to a maximum of 4 blocks per
        option.

        Reference: RFC 2018 §3 (SACK option, max 4 blocks).
        Reference: RFC 2018 §4 (SACK block ordering).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )
        self.assertTrue(
            session._advertise.send_sack,
            msg="Setup precondition: bilateral SACK negotiation must have succeeded.",
        )

        # First OOO segment.
        seg_a = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"A" * 100,
        )
        self._drive_rx(frame=seg_a)

        # Second OOO segment (disjoint from the first).
        seg_b = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 300,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"B" * 100,
        )
        seg_b_tx = self._drive_rx(frame=seg_b)
        self.assertEqual(
            len(seg_b_tx),
            1,
            msg="A second OOO arrival must trigger exactly one dup-ACK with SACK info.",
        )
        seg_b_ack = self._parse_tx(seg_b_tx[0])
        self.assertEqual(
            sorted(seg_b_ack.sack_blocks),
            sorted(
                [
                    (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),
                    (PEER__ISS + 1 + 300, PEER__ISS + 1 + 400),
                ]
            ),
            msg=(
                "The dup-ACK on the second OOO arrival must carry "
                "two SACK blocks - one per buffered OOO range - so "
                "peer can plan retransmits for both gaps. RFC 2018 §3."
            ),
        )

    def test__sack__cumulative_ack_drains_ooo_queue_clears_sack_blocks(self) -> None:
        """
        Ensure that once the gap is filled and the OOO
        queue drains, subsequent outbound ACKs no longer
        carry SACK blocks. The receiver-side SACK lifecycle:
        blocks appear when data arrives out of order,
        persist until the gap fills, then disappear.

        Reference: RFC 2018 §3 (SACK option requires at least one block).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        # OOO segment lands first.
        ooo_seg = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        ooo_tx = self._drive_rx(frame=ooo_seg)

        # Sanity: the OOO arrival's dup-ACK MUST carry a SACK block
        # so the lifecycle "blocks present during gap" -> "blocks
        # cleared after fill" is fully exercised.
        self.assertEqual(
            len(ooo_tx),
            1,
            msg="Setup precondition: OOO arrival must elicit one dup-ACK.",
        )
        ooo_ack_probe = self._parse_tx(ooo_tx[0])
        self.assertEqual(
            ooo_ack_probe.sack_blocks,
            ((PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),),
            msg=(
                "Setup precondition: the OOO dup-ACK must carry a SACK "
                "block reporting the buffered range so the post-fill "
                "clearing assertion below is meaningful."
            ),
        )

        # Gap-fill arrives.
        gap_fill = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"Y" * 100,
        )
        fill_tx = self._drive_rx(frame=gap_fill)

        self.assertEqual(
            session._ooo_packet_queue,
            {},
            msg=(
                "Gap-fill must drain the entire OOO queue: the cumulative "
                "ACK now covers everything that used to be buffered."
            ),
        )

        self.assertEqual(
            len(fill_tx),
            1,
            msg="The gap-fill arrival must produce exactly one cumulative ACK.",
        )
        fill_ack = self._parse_tx(fill_tx[0])
        self._assert_segment(
            fill_ack,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1 + 200,
            sack_blocks=[],
        )

    def test__sack__passive_open_mirrors_peer_sack_permitted_offer(self) -> None:
        """
        Ensure that when a peer's SYN to a listening socket
        carries SACK-Permitted, our SYN+ACK reply mirrors
        the offer back.

        Reference: RFC 2018 §2 (SACK bilateral negotiation, mirror peer's offer).
        """

        listen_session = self._make_listen_session(iss=LOCAL__ISS)
        peer_syn = build_tcp4(
            sport=PEER__PASSIVE_PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            sackperm=True,
        )
        self._drive_rx(frame=peer_syn)
        self.assertIs(
            listen_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: listening session must mutate into SYN_RCVD on peer's SYN.",
        )
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK must fire on the first tick after peer's SYN.",
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])
        self._assert_segment(
            syn_ack_probe,
            flags=frozenset({"SYN", "ACK"}),
            sackperm=True,
        )

    def test__sack__passive_open_omits_sack_when_peer_did_not_offer(self) -> None:
        """
        Ensure that when a peer's SYN does not carry
        SACK-Permitted, our SYN+ACK reply also omits it —
        the bilateral mirror rule forces the negotiation to
        fail closed.

        Reference: RFC 2018 §2 (SACK bilateral negotiation, no echo without peer offer).
        """

        listen_session = self._make_listen_session(iss=LOCAL__ISS)
        peer_syn = build_tcp4(
            sport=PEER__PASSIVE_PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            sackperm=False,
        )
        self._drive_rx(frame=peer_syn)
        self.assertIs(
            listen_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: listening session must mutate into SYN_RCVD on peer's SYN.",
        )
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK must fire on the first tick after peer's SYN.",
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])
        self._assert_segment(
            syn_ack_probe,
            flags=frozenset({"SYN", "ACK"}),
            sackperm=False,
        )

    def test__sack__inbound_sack_block_updates_scoreboard(self) -> None:
        """
        Ensure that when bilateral SACK is enabled and peer
        sends an ACK carrying a SACK block describing
        receipt of bytes in our outstanding (unacked) range,
        the session ingests that block into
        '_sack_scoreboard'.

        Reference: RFC 2018 §3 (SACK option wire format).
        Reference: RFC 2018 §4 (SACK block semantics).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )
        self.assertTrue(
            session._advertise.send_sack,
            msg="Setup precondition: bilateral SACK negotiation must have succeeded.",
        )

        # Bypass slow-start so the application's send drains in
        # one outbound segment.
        session._cc.snd_ewn = PEER__WIN
        session.send(data=b"X" * 200)
        self._advance(ms=1)

        sacked_left = LOCAL__ISS + 1 + 100
        sacked_right = LOCAL__ISS + 1 + 200
        peer_dup_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=peer_dup_ack)

        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [(sacked_left, sacked_right)],
            msg=("An inbound SACK block describing in-window " "bytes must be ingested into the scoreboard."),
        )

    def test__sack__cumulative_ack_prunes_scoreboard_below_snd_una(self) -> None:
        """
        Ensure that when peer's cumulative ACK advances
        SND.UNA past a SACK-recorded range, the
        corresponding block is pruned from the scoreboard.

        Reference: RFC 6675 §3 (SACK scoreboard tracks unacked-but-sacked bytes).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._cc.snd_ewn = PEER__WIN
        session.send(data=b"X" * 200)
        self._advance(ms=1)

        # First ACK ingests a SACK block.
        sacked_left = LOCAL__ISS + 1 + 100
        sacked_right = LOCAL__ISS + 1 + 200
        first_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=first_ack)
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [(sacked_left, sacked_right)],
            msg="Setup precondition: scoreboard must hold the SACK block before the cum-ACK advance.",
        )

        # Second ACK: cumulative-ack advances past the sacked range.
        second_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 200,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=second_ack)

        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1 + 200,
            msg="Setup precondition: cumulative-ACK must advance SND.UNA past the sacked range.",
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "The scoreboard MUST be pruned once the cumulative ACK "
                "absorbs the sacked range; "
                "'prune_below(SND.UNA)' drops blocks whose "
                "right edge lies at or below the new SND.UNA."
            ),
        )

    def test__sack__out_of_window_sack_block_silently_dropped(self) -> None:
        """
        Ensure an inbound SACK block whose edges fall
        outside '[SND.UNA, SND.MAX]' is silently dropped —
        such a block cannot describe legitimate in-flight
        bytes.

        Reference: RFC 2018 §3 (out-of-window SACK blocks ignored).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._cc.snd_ewn = PEER__WIN
        session.send(data=b"X" * 200)
        self._advance(ms=1)

        out_of_window_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(LOCAL__ISS + 1 + 1000, LOCAL__ISS + 1 + 1100)],
        )
        self._drive_rx(frame=out_of_window_ack)

        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "A SACK block whose edges fall outside "
                "'[SND.UNA, SND.MAX]' MUST be silently "
                "dropped. The scoreboard must remain empty."
            ),
        )

    def test__sack__three_dup_sacks_above_gap_trigger_fast_retransmit(self) -> None:
        """
        Ensure three SACK-bearing dup-ACKs above the gap at
        SND.UNA accumulate in the scoreboard as three
        distinct blocks AND trigger fast retransmit of the
        gap segment.

        Reference: RFC 5681 §3.2 (fast retransmit on third dup-ACK).
        Reference: RFC 6675 §3 (IsLost count rule).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._cc.snd_ewn = PEER__WIN
        mss = session._win.snd_mss
        session.send(data=b"X" * (4 * mss))
        # '_transmit_data' sends one MSS-sized segment per timer
        # tick; advance enough ticks so all 4 outstanding
        # segments fire and SND.MAX = LOCAL__ISS + 1 + 4*MSS.
        # The post-handshake retransmit-timer cadence puts each
        # tick safely under TCP__RTO__INITIAL_MS.
        for _ in range(4):
            self._advance(ms=1)
        self.assertEqual(
            session._snd_seq.max,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: all 4 MSS-sized segments must drain before the dup-ACK matrix runs.",
        )

        # Three SACK-bearing dup-ACKs, each adding one new block.
        # 1-byte gaps between the blocks prevent coalescing in
        # the scoreboard so the IsLost count rule sees three
        # distinct entries.
        block_1 = (LOCAL__ISS + 1 + 1 * mss, LOCAL__ISS + 1 + 1 * mss + 100)
        block_2 = (LOCAL__ISS + 1 + 2 * mss, LOCAL__ISS + 1 + 2 * mss + 100)
        block_3 = (LOCAL__ISS + 1 + 3 * mss, LOCAL__ISS + 1 + 3 * mss + 100)

        for blk in (block_1, block_2, block_3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                sack_blocks=[blk],
            )
            self._drive_rx(frame=dup_ack)

        # After all three dup-ACKs the scoreboard holds three
        # distinct blocks (insertion order preserved by
        # 'SackScoreboard.blocks()').
        self.assertEqual(
            sorted(session._sack_scoreboard.blocks()),
            sorted([block_1, block_2, block_3]),
            msg=("Three SACK-bearing dup-ACKs MUST accumulate " "three distinct blocks in the scoreboard."),
        )

        # The third dup-ACK sets '_snd_nxt' back to the gap;
        # the actual retransmit fires on the next timer tick
        # via '_transmit_data'. Advance one tick and capture
        # the resulting outbound segment.
        retransmit_tx = self._advance(ms=1)
        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=(
                "The third dup-ACK MUST elicit exactly one "
                "outbound fast-retransmit segment on the next "
                "timer tick."
            ),
        )
        retransmit_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            retransmit_probe,
            flags=frozenset({"ACK"}),
            seq=LOCAL__ISS + 1,
            payload=b"X" * mss,
        )

    def test__sack__pipe_excludes_sacked_bytes_from_in_flight_estimate(self) -> None:
        """
        Ensure that pipe() applied to the session's
        '_sack_scoreboard' excludes peer-SACKed bytes from
        the in-flight estimate.

        Reference: RFC 6675 §4 (Pipe estimate of FlightSize).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._cc.snd_ewn = PEER__WIN
        mss = session._win.snd_mss
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)

        # Peer SACKs the upper 2*MSS bytes (one contiguous block).
        sacked_left = LOCAL__ISS + 1 + 2 * mss
        sacked_right = LOCAL__ISS + 1 + 4 * mss
        sack_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=sack_ack)

        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [(sacked_left, sacked_right)],
            msg="Setup precondition: scoreboard must hold the SACKed range.",
        )

        in_flight = pipe(
            scoreboard=session._sack_scoreboard,
            snd_una=session._snd_seq.una,
            snd_max=session._snd_seq.max,
        )
        self.assertEqual(
            in_flight,
            2 * mss,
            msg=(
                "Pipe must subtract the 2*MSS SACKed bytes from "
                "the 4*MSS in-flight range, returning 2*MSS bytes "
                "still considered in flight."
            ),
        )

    def test__sack__byte_rule_triggers_fast_retransmit_on_first_dup_sack(self) -> None:
        """
        Ensure that the IsLost byte-rule fires fast
        retransmit on the FIRST SACK-bearing dup-ACK when
        peer reports more than '(dup_thresh - 1) * SMSS'
        bytes SACKed above SND.UNA, and that the
        '_recovery_point' marker prevents re-firing on a
        second dup-SACK with the same info.

        Reference: RFC 6675 §3 (IsLost byte rule).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._cc.snd_ewn = PEER__WIN
        mss = session._win.snd_mss
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)
        self.assertEqual(
            session._snd_seq.max,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: all 4 MSS-sized segments must drain.",
        )

        # Single SACK block carrying '2*MSS + 1' bytes - just
        # over the byte-rule threshold.
        sacked_left = LOCAL__ISS + 1 + mss
        sacked_right = sacked_left + 2 * mss + 1
        self.assertLessEqual(
            sacked_right,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: the test SACK block must lie within [SND.UNA, SND.MAX].",
        )
        first_dup_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=first_dup_sack)

        # Byte-rule fired; we entered recovery.
        self.assertNotEqual(
            session._cc.recovery_point,
            0,
            msg=(
                "The IsLost byte-rule MUST fire fast retransmit on "
                "the first dup-SACK when peer reports > 2*MSS "
                "bytes SACKed above SND.UNA - '_recovery_point' "
                "must be non-zero (RFC 6675 §3, RFC 5681 §3.2)."
            ),
        )

        # Next tick fires the retransmit at SND.UNA (the gap
        # in this single-gap scenario; NextSeg returns SND.UNA).
        retransmit_tx = self._advance(ms=1)
        self.assertEqual(
            len(retransmit_tx),
            1,
            msg="Setup expectation: exactly one outbound retransmit on the next tick after byte-rule trigger.",
        )
        retransmit_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            retransmit_probe,
            flags=frozenset({"ACK"}),
            seq=LOCAL__ISS + 1,
            payload=b"X" * mss,
        )

        # A second dup-SACK during recovery MUST NOT re-enter
        # recovery. The '_recovery_point' guard suppresses the
        # re-trigger; '_recovery_point' must remain at the same
        # non-zero value from the original entry. (Subsequent
        # outbound data may still flow through '_transmit_data'
        # past SND.NXT - that is normal sliding-window
        # operation, not a re-fire of the retransmit.)
        recovery_point_after_first = session._cc.recovery_point
        second_dup_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=second_dup_sack)
        self.assertEqual(
            session._cc.recovery_point,
            recovery_point_after_first,
            msg=(
                "A second dup-SACK during recovery MUST NOT re-enter "
                "recovery - '_recovery_point' stays unchanged at the "
                "original SND.MAX marker (RFC 5681 §3.2 step 4 / "
                "RFC 6675 §5 one-shot)."
            ),
        )

    def test__sack__recovery_skips_already_sacked_bytes(self) -> None:
        """
        Ensure that during fast-retransmit recovery the
        sender skips over peer-SACKed ranges in SND.NXT so
        subsequent outbound segments do not redundantly
        retransmit bytes peer already received.

        Reference: RFC 6675 §6 (multi-gap recovery skips SACKed bytes).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._cc.snd_ewn = PEER__WIN
        mss = session._win.snd_mss
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)
        self.assertEqual(
            session._snd_seq.max,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: all 4 MSS-sized segments must drain.",
        )

        # Three dup-ACKs each reporting the same SACK block
        # covering segments 2 and 3 (= [SND.UNA+MSS, SND.UNA+3*MSS)).
        # Single-block ingestion coalesces (idempotent) so the
        # scoreboard ends with one entry, but the count-rule
        # fires on the 3rd dup-ACK.
        sacked_left = LOCAL__ISS + 1 + 1 * mss
        sacked_right = LOCAL__ISS + 1 + 3 * mss
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                sack_blocks=[(sacked_left, sacked_right)],
            )
            self._drive_rx(frame=dup_ack)

        self.assertNotEqual(
            session._cc.recovery_point,
            0,
            msg="Setup precondition: 3 dup-ACKs must enter recovery via count rule.",
        )

        # Tick #1: retransmit segment 1 (= the gap at SND.UNA).
        retransmit_1_tx = self._advance(ms=1)
        self.assertEqual(
            len(retransmit_1_tx),
            1,
            msg="Tick #1 must produce exactly one retransmit at the SND.UNA gap.",
        )
        retransmit_1_probe = self._parse_tx(retransmit_1_tx[0])
        self._assert_segment(
            retransmit_1_probe,
            flags=frozenset({"ACK"}),
            seq=LOCAL__ISS + 1,
            payload=b"X" * mss,
        )

        # Tick #2: '_advance_snd_nxt_past_sacked' jumps SND.NXT
        # past the SACKed block (segments 2 and 3) so the next
        # outbound segment carries SEQ = SND.UNA + 3*MSS, NOT
        # SND.UNA + MSS (which would re-send bytes peer already
        # has).
        retransmit_2_tx = self._advance(ms=1)
        self.assertEqual(
            len(retransmit_2_tx),
            1,
            msg="Tick #2 must produce one segment - past the SACKed range.",
        )
        retransmit_2_probe = self._parse_tx(retransmit_2_tx[0])
        self._assert_segment(
            retransmit_2_probe,
            flags=frozenset({"ACK", "PSH"}),
            seq=LOCAL__ISS + 1 + 3 * mss,
            payload=b"X" * mss,
        )

    def test__sack__dsack__fully_duplicate_segment_elicits_dsack_in_outbound_ack(self) -> None:
        """
        Ensure that when peer retransmits a segment whose
        entire payload range we have already received and
        cumulatively acknowledged, the next outbound ACK
        carries a DSACK report — the duplicated range is
        encoded as the FIRST SACK block.

        Reference: RFC 2883 §3 (DSACK case-1, full duplicate below cum-ACK).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        # Peer sends segment 1 (50 bytes).
        payload = b"abcdefghij" * 5  # 50 bytes
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=payload,
        )
        self._drive_rx(frame=seg1)
        # Drain the delayed-ACK so the receive state settles
        # before we test the duplicate path. (The delayed-ACK
        # interval is 100ms by default; advance well past it.)
        self._advance(ms=200)

        rx_buffer_before = bytes(session._rx_buffer)
        rcv_nxt_before = session._rcv_seq.nxt

        # Peer re-sends segment 1 - fully duplicate.
        seg1_dup = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=payload,
        )
        dup_tx = self._drive_rx(frame=seg1_dup)

        self.assertEqual(
            len(dup_tx),
            1,
            msg=(
                "A fully-duplicate inbound segment MUST "
                "elicit exactly one outbound ACK so peer's "
                "retransmit machinery sees fresh activity."
            ),
        )
        dup_ack_probe = self._parse_tx(dup_tx[0])
        self._assert_segment(
            dup_ack_probe,
            flags=frozenset({"ACK"}),
            ack=rcv_nxt_before,
            sack_blocks=[(PEER__ISS + 1, PEER__ISS + 1 + 50)],
        )
        # Sanity: rx_buffer is unchanged - the duplicate brought
        # no new bytes and the FSM did not double-deliver.
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_before,
            msg="A fully-duplicate segment must NOT re-enqueue bytes into '_rx_buffer'.",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Duplicate-segment receipt must not perturb the FSM state.",
        )

    def test__sack__dsack__inbound_dsack_below_snd_una_detected_and_not_ingested(self) -> None:
        """
        Ensure that when peer sends an ACK whose SACK
        option's first block reports a range entirely below
        SND.UNA, the sender recognises the DSACK signature,
        increments '_dsack_received', and does not add the
        DSACK range to the loss-recovery scoreboard.

        Reference: RFC 2883 §4 (DSACK detection, range below cum-ACK).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._cc.snd_ewn = PEER__WIN
        mss = session._win.snd_mss
        session.send(data=b"X" * (2 * mss))
        for _ in range(2):
            self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * mss,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(LOCAL__ISS + 1, LOCAL__ISS + 1 + 100)],
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._dsack_received,
            1,
            msg=(
                "An inbound SACK option whose first block "
                "lies entirely below SND.UNA MUST be "
                "recognised as a DSACK report."
            ),
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "A DSACK block describes already-acknowledged "
                "bytes; it MUST NOT be added to the in-flight "
                "scoreboard."
            ),
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1 + 2 * mss,
            msg="Cumulative-ACK advancement must proceed normally despite the DSACK report.",
        )

    def test__sack__dsack__inbound_dsack_contained_in_outer_block_detected(self) -> None:
        """
        Ensure that the second DSACK signature is
        recognised: when the first SACK block lies entirely
        within a subsequent SACK block in the same option,
        the first block is a DSACK marker (peer received
        those bytes twice and is reporting the duplicate
        alongside the normal SACK info).

        Reference: RFC 2883 §4 (DSACK detection, contained-in-outer signature).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._cc.snd_ewn = PEER__WIN
        mss = session._win.snd_mss
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)

        outer_left = LOCAL__ISS + 1 + mss
        outer_right = LOCAL__ISS + 1 + 3 * mss
        dsack_inner_left = outer_left
        dsack_inner_right = outer_left + 100
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[
                (dsack_inner_left, dsack_inner_right),  # DSACK marker
                (outer_left, outer_right),  # outer covers it
            ],
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._dsack_received,
            1,
            msg=(
                "An inbound SACK option whose first block "
                "lies entirely within a subsequent block "
                "MUST be recognised as a DSACK report."
            ),
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [(outer_left, outer_right)],
            msg=(
                "The outer SACK block must be ingested into the "
                "scoreboard normally; only the contained DSACK "
                "marker is excluded."
            ),
        )

    def test__sack__dsack__case_2__full_duplicate_of_ooo_queued_segment_elicits_dsack(self) -> None:
        """
        Ensure that when peer retransmits an OOO segment
        whose range exactly matches an entry already
        buffered in our OOO queue, the next outbound ACK
        carries a DSACK case-2 report — DSACK block first,
        regular OOO block second.

        Reference: RFC 2883 §3 (DSACK case-2, full duplicate of OOO-queued segment).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        ooo_seg = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        first_tx = self._drive_rx(frame=ooo_seg)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first OOO segment elicits exactly one dup-ACK.",
        )

        # Peer retransmits the EXACT same OOO segment.
        ooo_seg_dup = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        dup_tx = self._drive_rx(frame=ooo_seg_dup)

        self.assertEqual(
            len(dup_tx),
            1,
            msg=(
                "A retransmit of an OOO-queued segment MUST "
                "elicit exactly one outbound ACK so peer's "
                "retransmit machinery sees fresh activity."
            ),
        )
        dup_ack_probe = self._parse_tx(dup_tx[0])
        self._assert_segment(
            dup_ack_probe,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1,
            sack_blocks=[
                (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),  # DSACK marker
                (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),  # regular OOO block
            ],
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Duplicate-OOO receipt must not perturb the FSM state.",
        )

    def test__sack__dsack__case_2__partial_overlap_with_ooo_queued_segment_elicits_dsack(self) -> None:
        """
        Ensure that when peer's OOO segment partially
        overlaps an existing entry in our OOO queue, the
        next outbound ACK carries a DSACK report whose
        range is the intersection of the new segment with
        the existing entry, followed by both regular OOO
        blocks.

        Reference: RFC 2883 §3 (DSACK case-2, partial overlap with OOO queue).
        """

        self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        first_tx = self._drive_rx(frame=seg1)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first OOO segment elicits exactly one dup-ACK.",
        )

        # Second OOO segment overlaps the first by 50 bytes.
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 150,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"Y" * 100,
        )
        overlap_tx = self._drive_rx(frame=seg2)

        self.assertEqual(
            len(overlap_tx),
            1,
            msg=(
                "An OOO segment overlapping a queued entry "
                "MUST elicit exactly one outbound ACK "
                "reporting the duplicate range via DSACK."
            ),
        )
        overlap_ack_probe = self._parse_tx(overlap_tx[0])
        self._assert_segment(
            overlap_ack_probe,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1,
            sack_blocks=[
                # RFC 2883 §4: DSACK first.
                (PEER__ISS + 1 + 150, PEER__ISS + 1 + 200),  # DSACK overlap
                # RFC 2018 §4 first-block ordering: most-recent
                # OOO arrival comes first after the DSACK.
                (PEER__ISS + 1 + 150, PEER__ISS + 1 + 250),  # new OOO
                (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),  # original OOO
            ],
        )

    def test__sack__dsack__case_2__disjoint_ooo_segments_emit_no_dsack(self) -> None:
        """
        Ensure that when peer's OOO segments do not overlap
        any existing OOO-queue entry, the resulting SACK
        option carries only regular SACK blocks — no DSACK
        marker. Disjoint OOO ingestion is not a duplicate
        event and must not trigger DSACK emission.

        Reference: RFC 2883 §3 (DSACK reserved for duplicate-range case).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        self._drive_rx(frame=seg1)

        # Second OOO segment - DISJOINT from the first.
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 300,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"Y" * 100,
        )
        disjoint_tx = self._drive_rx(frame=seg2)

        self.assertEqual(
            len(disjoint_tx),
            1,
            msg="A disjoint OOO segment MUST elicit exactly one outbound ACK.",
        )
        disjoint_ack_probe = self._parse_tx(disjoint_tx[0])
        self._assert_segment(
            disjoint_ack_probe,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1,
            sack_blocks=[
                # RFC 2018 §4 first-block ordering: most-recent
                # OOO arrival comes first.
                (PEER__ISS + 1 + 300, PEER__ISS + 1 + 400),
                (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),
            ],
        )
        # Sanity: the case-2 signature requires block-0 to be
        # contained in a later block. Confirm that NEITHER
        # block-0 sits inside any later block here - the
        # negative-control invariant.
        block0 = (PEER__ISS + 1 + 300, PEER__ISS + 1 + 400)
        block1 = (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200)
        self.assertFalse(
            block1[0] <= block0[0] and block0[1] <= block1[1],
            msg="Negative control: block-0 must NOT lie inside any later block (no spurious DSACK signature).",
        )
        self.assertIsNone(
            session._pending_dsack,
            msg="Disjoint OOO ingestion must not stash a pending DSACK report.",
        )

    def test__sack__cross_rfc__paws_drops_stale_segment_before_dsack_detector(self) -> None:
        """
        Ensure a stale-TSval segment that would otherwise be
        a DSACK candidate (fully duplicate, below RCV.NXT)
        is dropped by PAWS before the DSACK detector fires;
        no DSACK report on the next outbound ACK.

        Reference: RFC 7323 §5 (PAWS).
        Reference: RFC 2883 §3 (DSACK detection).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )
        # Promote the session to bilateral TSopt. The handshake
        # helper doesn't drive TSopt; flip the flags directly so
        # the post-handshake test focus is on the PAWS+DSACK
        # interaction, not on the negotiation.
        session._ts.send_ts = True
        session._ts.ts_recent = 0x1234_5678

        # Drive an in-order data segment so RCV.NXT advances,
        # creating the precondition for a "fully duplicate" segment.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=0x1234_5679,
            tsecr=0x1234_5678,
            payload=b"hello",
        )
        self._drive_rx(frame=peer_data)
        # Drain the delayed-ACK timer so '_pending_dsack' state is
        # observable cleanly.
        self._advance(ms=400)
        session._pending_dsack = None

        # Now drive a stale-TSval, fully-duplicate segment. The
        # DSACK detector at '_check_segment_acceptability' would
        # ordinarily latch '_pending_dsack' for this segment; PAWS
        # must drop the segment first.
        stale_dup = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=0x1234_5670,  # < _ts_recent
            tsecr=0x1234_5678,
            payload=b"hello",
        )
        self._drive_rx(frame=stale_dup)

        self.assertIsNone(
            session._pending_dsack,
            msg=(
                "PAWS-rejected segment MUST NOT latch a "
                "pending DSACK report; the PAWS check fires "
                "before the DSACK detector."
            ),
        )
