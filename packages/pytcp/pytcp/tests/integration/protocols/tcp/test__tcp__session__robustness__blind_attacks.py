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
This module contains integration tests for the TCP blind-attack
robustness mitigations described by RFC 9293 §3.10.7.4 (folding
RFC 5961). Specifically, this file targets the SYN-in-synchronized-
state challenge-ACK rule for the FSM states that the existing
'TcpSession' implementation does NOT yet handle: FIN_WAIT_1,
FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT.

ESTABLISHED and SYN_RCVD already emit the challenge ACK
(line 1354 and 1247 respectively, surfaced and fixed in the
'handshake__active.py' / 'handshake__passive.py' files). The
remaining six synchronized states share the same RFC 9293
mandate but currently silently drop a SYN-bearing segment,
leaving the connection vulnerable to blind reset attacks where
an off-path adversary injects a SYN and waits for the legitimate
peer's confused response to leak sequence-space information.

The blind-RST mitigation (in-window-but-mismatched RST -> challenge
ACK) is covered by 'close__rst.py' scenario #6.

The blind-data-injection mitigation (data with bogus ACK -> empty
ACK reply) is covered by 'data_transfer__recv.py' scenario #4
(commit '7893c97').

Reference RFCs:
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 5961 §4          Mitigating Blind Connection Attacks (SYN
                         injection)
    RFC 5961 §3          Blind RST Attacks (covered separately)
    RFC 5961 §5          Blind Data Injection (covered separately)

pytcp/tests/integration/protocols/tcp/test__tcp__session__robustness__blind_attacks.py

ver 3.0.8
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


class TestTcpRobustness__BlindAttacks(TcpTestCase):
    """
    Integration tests for the SYN-in-synchronized-state challenge-
    ACK rule across the FSM states that currently lack the
    mitigation (FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING,
    LAST_ACK, TIME_WAIT).
    """

    def test__robustness__syn_in_fin_wait_1_must_elicit_challenge_ack(self) -> None:
        """
        Ensure a peer-issued SYN arriving while we are in
        FIN_WAIT_1 (we have sent our FIN and are awaiting its
        ACK) elicits a challenge ACK at our current SND.NXT /
        RCV.NXT and does NOT change state. The challenge ACK
        carries flags={ACK}, seq=SND.NXT, ack=RCV.NXT and the
        graceful 4-way close is unaffected.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 5961 §4 (blind SYN-in-window mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Walk into FIN_WAIT_1 by closing and ticking through the
        # transition + FIN-emit ticks.
        session.close()
        self._advance(ms=1)
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: FIN_WAIT_1's first tick must emit our FIN+ACK.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1 after the FIN-emit tick.",
        )
        self.assertEqual(
            session._snd_seq.nxt,
            LOCAL__ISS + 2,
            msg=("Setup precondition: 'SND.NXT' must reflect the " "post-FIN sequence number (LOCAL__ISS + 2)."),
        )

        # Peer (or attacker) sends a fresh SYN to our 4-tuple.
        # The seq is intentionally arbitrary to encode the RFC's
        # "irrespective of the sequence number" rule.
        attacker_syn_seq = 0x4000_0000  # well clear of legitimate seq space
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=attacker_syn_seq,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        # The spec encoding: exactly one challenge ACK fires.
        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in FIN_WAIT_1 MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4 "
                "('irrespective of the sequence number, TCP endpoints "
                "MUST send a challenge ACK'). Current code's "
                "'_tcp_fsm_fin_wait_1' has no SYN-matching branch and "
                "the segment falls through silently."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 1,
            payload=b"",
        )

        # State must remain FIN_WAIT_1. The SYN is rejected; the
        # graceful 4-way close is unaffected.
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "A SYN in FIN_WAIT_1 MUST NOT change state - the "
                "challenge ACK is the only response, and the in-"
                "progress close continues normally."
            ),
        )

    def test__robustness__syn_in_fin_wait_2_must_elicit_challenge_ack(self) -> None:
        """
        Ensure a peer-issued SYN arriving while we are in
        FIN_WAIT_2 (we have sent our FIN and received its ACK;
        we are awaiting peer's FIN) elicits a challenge ACK
        and does NOT change state. The challenge ACK carries
        flags={ACK}, seq=SND.NXT, ack=RCV.NXT.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 5961 §4 (blind SYN-in-window mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Walk into FIN_WAIT_2.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="Setup precondition: state must be FIN_WAIT_2.",
        )

        # Attacker SYN.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000_0000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in FIN_WAIT_2 MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. "
                "Current code's '_tcp_fsm_fin_wait_2' has no SYN-"
                "matching branch and the segment falls through "
                "silently."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 1,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="A SYN in FIN_WAIT_2 MUST NOT change state.",
        )

    def test__robustness__syn_in_close_wait_must_elicit_challenge_ack(self) -> None:
        """
        Ensure a peer-issued SYN arriving while we are in
        CLOSE_WAIT (peer closed first; we have not yet called
        close()) elicits a challenge ACK and does NOT change
        state. The challenge ACK acknowledges peer's FIN
        cumulatively at seq=SND.NXT, ack=RCV.NXT.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 5961 §4 (blind SYN-in-window mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Walk into CLOSE_WAIT.
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
            msg="Setup precondition: state must be CLOSE_WAIT.",
        )

        # Attacker SYN before any tick fires the delayed ACK.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000_0000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in CLOSE_WAIT MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. "
                "Current code's '_tcp_fsm_close_wait' has no SYN-"
                "matching branch and the segment falls through "
                "silently."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="A SYN in CLOSE_WAIT MUST NOT change state.",
        )

    def test__robustness__syn_in_closing_must_elicit_challenge_ack(self) -> None:
        """
        Ensure a peer-issued SYN arriving while we are in
        CLOSING (simultaneous-close state - both sides have
        sent FIN, neither has ACKed the other's FIN) elicits a
        challenge ACK and does NOT change state. The challenge
        ACK carries flags={ACK}, seq=SND.NXT, ack=RCV.NXT.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 5961 §4 (blind SYN-in-window mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Walk to FIN_WAIT_1.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

        # Simultaneous-close FIN+ACK with non-fin-acking ack.
        peer_fin_simultaneous = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin_simultaneous)
        self.assertIs(
            session.state,
            FsmState.CLOSING,
            msg="Setup precondition: state must be CLOSING.",
        )

        # Attacker SYN.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000_0000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in CLOSING MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. "
                "Current code's '_tcp_fsm_closing' has no SYN-"
                "matching branch and the segment falls through "
                "silently."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSING,
            msg="A SYN in CLOSING MUST NOT change state.",
        )

    def test__robustness__syn_in_last_ack_must_elicit_challenge_ack(self) -> None:
        """
        Ensure a peer-issued SYN arriving while we are in
        LAST_ACK (we sent our FIN after the peer closed first;
        we are awaiting peer's ACK of our FIN) elicits a
        challenge ACK and does NOT change state. The challenge
        ACK carries flags={ACK}, seq=SND.NXT, ack=RCV.NXT.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 5961 §4 (blind SYN-in-window mitigation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self._advance(ms=1)

        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK.",
        )

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000_0000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in LAST_ACK MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. "
                "Current code's '_tcp_fsm_last_ack' has no SYN-"
                "matching branch."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="A SYN in LAST_ACK MUST NOT change state.",
        )

    def test__robustness__no_evidence_syn_in_time_wait_must_elicit_challenge_ack(self) -> None:
        """
        Ensure a peer-issued SYN arriving in TIME_WAIT WITHOUT
        fresh evidence on either freshness axis (seq <=
        RCV.NXT AND no TSopt) elicits a challenge ACK and
        does NOT change state. SYNs with fresh seq evidence
        are accepted as fresh connections per the Linux-style
        OR'd freshness predicate; this test pins the no-
        evidence challenge-ACK fallback path used as the blind
        SYN-in-window mitigation.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 5961 §4 (blind SYN-in-window mitigation).
        Reference: RFC 6191 §2 A.4 / B.3 (no-evidence default).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Walk to TIME_WAIT via the active-close path.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg="Setup precondition: state must be TIME_WAIT.",
        )

        # No-evidence SYN: seq == RCV.NXT - 1 (replay of last
        # byte we ACKed) AND no TSopt — neither RFC 6191 §2
        # acceptance axis fires, falls through to challenge-ACK.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_seq.nxt - 1,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "No-evidence SYN in TIME_WAIT MUST elicit "
                "exactly one challenge ACK per RFC 9293 "
                "§3.10.7.4 / RFC 5961 §4 / RFC 6191 §2 A.4."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg="A SYN in TIME_WAIT (without PAWS) MUST NOT change state.",
        )

    def test__blind_attack__challenge_ack_burst_is_rate_limited_per_rfc_5961_3(self) -> None:
        """
        Ensure a burst of unacceptable segments arriving in a
        sub-1-second window does NOT produce one challenge ACK
        per inbound segment. The receiver rate-limits
        challenge-ACK responses to mitigate ACK-amplification
        DoS attacks where a small volume of malicious or buggy
        inbound segments would otherwise produce a large
        outbound ACK flood.

        Reference: RFC 5961 §3 (challenge-ACK rate limit, sliding window).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Drain any post-handshake state (delayed-ACK timers, etc.).
        self._advance(ms=200)

        # Peer sends 10 unacceptable data segments back-to-back.
        # Each carries seq below RCV.NXT (fully duplicate; the
        # acceptability check rejects each segment with an ACK
        # reply).
        unacceptable_segments_count = 10
        before_count = len(self._frames_tx)
        for _ in range(unacceptable_segments_count):
            unacceptable_segment = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS,  # below RCV.NXT (= PEER__ISS + 1)
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                payload=b"X",  # 1 byte, fully below RCV.NXT
            )
            self._drive_rx(frame=unacceptable_segment)
        after_count = len(self._frames_tx)
        burst_tx_count = after_count - before_count

        # Rate-limit principle: count is bounded well below
        # the inbound count. Allow up to 2 challenge ACKs
        # (opening window + small implementation margin);
        # 10 inbound -> 10 outbound is clearly broken.
        self.assertLessEqual(
            burst_tx_count,
            2,
            msg=(
                f"RFC 5961 §3: a burst of {unacceptable_segments_count} "
                "unacceptable segments arriving in a sub-1-second "
                "window MUST be rate-limited to at most ~1 challenge "
                "ACK. PyTCP today emits one ACK per inbound segment "
                f"(observed {burst_tx_count} outbound ACKs) - this is "
                "an ACK-amplification DoS vector. Fix: introduce a "
                "'_emit_challenge_ack' helper that enforces a 1-per-"
                "second sliding-window rate limit and route all "
                "challenge-ACK emission sites through it."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Sanity: rate-limited or not, the burst MUST NOT change FSM state.",
        )


class TestTcpRobustness__BlindAckRfc5961S5(TcpTestCase):
    """
    Integration tests for RFC 5961 §5 blind ACK acceptability
    hardening. The receiver tracks 'MAX.SND.WND' (largest peer
    window ever seen) and considers an inbound ACK acceptable
    only when 'SND.UNA - MAX.SND.WND <= SEG.ACK <= SND.NXT'.

    Above SND.MAX is already covered (commit '7893c97' / fix
    #12) - the gap is the LOWER bound: an ACK below
    'SND.UNA - MAX.SND.WND' MUST elicit a rate-limited
    challenge ACK rather than silent drop, so a legitimate
    peer with a wedged stale view of the connection can
    re-sync.

    Reference RFC:
        RFC 5961 §5 Mitigating Blind Data Injection
    """

    def test__ack__below_snd_una_minus_max_window_emits_challenge_ack(self) -> None:
        """
        Ensure an inbound ACK with SEG.ACK below
        'SND.UNA - MAX.SND.WND' elicits a rate-limited
        challenge ACK rather than a silent drop, so a wedged
        peer with a stale view can re-sync.

        Reference: RFC 5961 §5 (blind data injection, ACK lower bound).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Burn the initial-window challenge-ACK token so we
        # observe only this segment's response.
        self._advance(ms=1100)

        snd_una_pre = session._snd_seq.una
        max_snd_wnd = PEER__WIN
        stale_ack = (snd_una_pre - 2 * max_snd_wnd) & 0xFFFF_FFFF
        stale_ack_seg = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=stale_ack,
            flags=("ACK",),
            win=PEER__WIN,
        )
        tx = self._drive_rx(frame=stale_ack_seg)

        self.assertGreaterEqual(
            len(tx),
            1,
            msg=(
                f"RFC 5961 §5: an ACK with SEG.ACK={stale_ack} below "
                f"SND.UNA - MAX.SND.WND ({snd_una_pre - max_snd_wnd}) "
                f"MUST elicit a challenge ACK. Got {len(tx)} outbound "
                "frames."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="A blind stale ACK MUST NOT change FSM state.",
        )

    def test__ack__within_max_window_silently_dropped(self) -> None:
        """
        Ensure a stale-but-within-MAX.SND.WND ACK is silently
        dropped (no challenge-ACK). Only ACKs below
        'SND.UNA - MAX.SND.WND' trigger the §5 hardening path.

        Reference: RFC 5961 §5 (blind data injection, acceptable-ACK window).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._advance(ms=1100)

        snd_una_pre = session._snd_seq.una
        almost_stale_ack = (snd_una_pre - PEER__WIN // 2) & 0xFFFF_FFFF
        almost_stale_seg = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=almost_stale_ack,
            flags=("ACK",),
            win=PEER__WIN,
        )
        tx = self._drive_rx(frame=almost_stale_seg)

        self.assertEqual(
            len(tx),
            0,
            msg=(
                "Stale ACK within MAX.SND.WND is acceptable per RFC "
                "5961 §5 - silent drop, no challenge-ACK. Got "
                f"{len(tx)} outbound frames."
            ),
        )
