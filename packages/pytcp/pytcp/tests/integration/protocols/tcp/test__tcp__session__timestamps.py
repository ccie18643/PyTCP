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
This module contains integration tests for the RFC 7323 §3
Timestamps option (TSopt) machinery in PyTCP's TcpSession.

RFC 7323 §3 specifies a 10-byte option carrying <TSval, TSecr>:
    - TSval: sender's current TS clock value.
    - TSecr: most-recently-seen peer TSval, echoed back so peer
      can compute exact RTT without Karn's ambiguity.

The four invariants the project must satisfy:
    1. Bilateral negotiation - TSopt on SYN/SYN+ACK iff both
       sides advertise.
    2. Per-segment emission - every post-handshake segment
       carries TSopt when '_send_ts' is True.
    3. RTTM via TSecr - 'now_ms - tsecr' on cum-ACK supersedes
       Karn-tainted sample tracker.
    4. PAWS - reject inbound segments with stale TSval.

This file exercises Phase 1 (bilateral negotiation). Phases
2-4 add their own suites.

Reference RFCs:
    RFC 7323 §3   Timestamps option wire format + negotiation
    RFC 7323 §4   RTTM via TSecr
    RFC 7323 §5   PAWS

pytcp/tests/integration/protocols/tcp/test__tcp__session__timestamps.py

ver 3.0.9
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
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

# Peer's TS clock starting value (arbitrary).
PEER__TSVAL_INITIAL: int = 0x1234_5678


class TestTcpTimestampsPhase1Active(TcpTestCase):
    """
    Phase 1 active-open bilateral-negotiation invariants.
    """

    def test__ts__active_open_syn_carries_tsopt(self) -> None:
        """
        Ensure an active-open SYN includes the Timestamps
        option with TSval = current TS clock and TSecr = 0
        (peer's TSval is unknown until the SYN+ACK arrives).

        Reference: RFC 7323 §3 (Timestamps option wire format).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        send_now_ms = self._timer.now_ms + 1
        tx = self._advance(ms=1)

        self.assertEqual(
            len(tx),
            1,
            msg="Setup invariant: connect must emit one SYN frame.",
        )
        probe = self._parse_tx(tx[0])
        self.assertIn(
            "SYN",
            probe.flags,
            msg="Setup invariant: outbound frame must be the SYN.",
        )
        self.assertIsNotNone(
            probe.tsval,
            msg=("Active-open SYN MUST carry the Timestamps " "option. Got no TSopt."),
        )
        self.assertEqual(
            probe.tsval,
            send_now_ms,
            msg=(
                "SYN's TSval MUST equal the sender's "
                "current TS clock value "
                f"(stack.timer.now_ms = {send_now_ms}). "
                f"Got TSval={probe.tsval}."
            ),
        )
        self.assertEqual(
            probe.tsecr,
            0,
            msg=(
                "TSecr on the active-open SYN MUST be zero "
                "(peer's TSval is not yet known). Got "
                f"TSecr={probe.tsecr}."
            ),
        )

    def test__ts__bilateral_send_ts_set_post_handshake_when_peer_supports(self) -> None:
        """
        Ensure post-handshake '_send_ts' is True when both
        sides advertised TSopt during the SYN exchange.

        Reference: RFC 7323 §3 (Timestamps bilateral negotiation).
        """

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
            tsval=PEER__TSVAL_INITIAL,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: handshake must complete with peer's TSopt.",
        )
        self.assertTrue(
            session._ts.send_ts,
            msg=("Bilateral negotiation success - both sides " "advertised TSopt - MUST set '_send_ts = True'."),
        )

    def test__ts__peer_no_tsopt_disables_send_ts(self) -> None:
        """
        Ensure that if peer's SYN+ACK does not include
        TSopt, '_send_ts' stays False; we cannot
        unilaterally include TSopt on subsequent segments.

        Reference: RFC 7323 §3 (Timestamps bilateral negotiation).
        """

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
            # No tsval/tsecr - peer doesn't advertise TSopt.
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: handshake must complete even without TSopt.",
        )
        self.assertFalse(
            session._ts.send_ts,
            msg=(
                "Peer did not advertise TSopt - '_send_ts' " "MUST stay False. Got " f"_send_ts={session._ts.send_ts}."
            ),
        )

    def test__ts__advertise_opt_out_disables_outbound_tsopt(self) -> None:
        """
        Ensure that when the application disables TSopt
        advertisement via '_advertise_ts = False' before
        connect, the outbound SYN does not carry TSopt and
        the post-handshake '_send_ts' stays False even if
        peer advertised.

        Reference: RFC 7323 §3 (Timestamps bilateral negotiation, application opt-out).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session._advertise.ts = False
        session.tcp_fsm(syscall=SysCall.CONNECT)
        tx = self._advance(ms=1)

        probe = self._parse_tx(tx[0])
        self.assertIsNone(
            probe.tsval,
            msg=(
                "RFC 7323 §3: with '_advertise_ts = False' the "
                "outbound SYN MUST NOT carry TSopt. Got "
                f"TSval={probe.tsval}."
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
            tsval=PEER__TSVAL_INITIAL,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertFalse(
            session._ts.send_ts,
            msg=(
                "Asymmetric-guard: even if peer advertises "
                "TSopt, we MUST NOT enable '_send_ts' when "
                "our side opted out. Got "
                f"_send_ts={session._ts.send_ts}."
            ),
        )


# Passive-open (LISTEN-side) bilateral-negotiation tests are
# deferred to Phase 2 — they require the LISTEN__PORT-style
# listening setup and re-resolution of the child session post-
# SYN. Active-open coverage (4 scenarios above) exercises the
# bilateral-negotiation logic on the active side; the passive
# side will be covered transitively when Phase 2's
# per-segment emission tests drive both directions.


class TestTcpTimestampsPhase2(TcpTestCase):
    """
    Phase 2 invariants: post-handshake TSopt emission on every
    segment + '_ts_recent' tracking on accepted inbound segments.
    """

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """
        Drive the active-open three-way handshake with bilateral
        TSopt negotiation. Returns the established session with
        '_send_ts == True' and '_ts_recent == peer_tsval'.
        """

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED
        assert session._ts.send_ts, "Setup invariant: bilateral TSopt negotiation must succeed."
        # Bypass slow-start.
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__ts__post_handshake_data_segment_carries_tsopt(self) -> None:
        """
        Ensure post-handshake outbound segments carry TSopt
        with TSval = now_ms and TSecr = _ts_recent when
        bilateral negotiation succeeded.

        Reference: RFC 7323 §3 (TSopt emission on every segment after bilateral negotiation).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        payload = b"hello"
        session.send(data=payload)
        send_now_ms = self._timer.now_ms + 1
        tx = self._advance(ms=1)

        probe = self._parse_tx(tx[0])
        self.assertEqual(
            probe.tsval,
            send_now_ms,
            msg=(
                "Post-handshake data segment MUST "
                f"carry TSval = current TS clock ({send_now_ms}). "
                f"Got TSval={probe.tsval}."
            ),
        )
        self.assertEqual(
            probe.tsecr,
            PEER__TSVAL_INITIAL,
            msg=(
                "TSecr MUST equal '_ts_recent' "
                f"(= peer's last seen TSval = "
                f"{PEER__TSVAL_INITIAL:#x}). Got "
                f"TSecr={probe.tsecr}."
            ),
        )

    def test__ts__ts_recent_updated_on_accepted_inbound_segment(self) -> None:
        """
        Ensure that an accepted inbound segment's TSval
        updates '_ts_recent' so subsequent outbound TSecr
        echoes the latest peer TS clock value.

        Reference: RFC 7323 §4.3 (_ts_recent update on accepted segment).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        new_tsval = PEER__TSVAL_INITIAL + 100
        # Use a data-bearing inbound segment so the FSM routes
        # to '_process_ack_packet' (the dup-ACK / wnd-update
        # paths take a different early-return route that
        # bypasses the TS-recent hook today; full RFC 7323 §4.3
        # conformance for those paths is a Phase-4-or-later
        # concern).
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=new_tsval,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"peer-data",
        )
        self._drive_rx(frame=peer_data)

        self.assertEqual(
            session._ts.ts_recent,
            new_tsval,
            msg=(
                "An accepted inbound segment's TSval MUST "
                "update '_ts_recent'. Expected "
                f"{new_tsval:#x}, got {session._ts.ts_recent:#x}."
            ),
        )

    def test__ts__post_update_outbound_segment_echoes_new_ts_recent(self) -> None:
        """
        Ensure that after '_ts_recent' updates from an
        inbound segment, the next outbound segment's TSecr
        reflects the new value.

        Reference: RFC 7323 §3 (TSecr echoes _ts_recent).
        Reference: RFC 7323 §4.3 (_ts_recent update on accepted segment).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        new_tsval = PEER__TSVAL_INITIAL + 200
        # Use a data-bearing inbound segment so the FSM routes
        # to '_process_ack_packet' (the dup-ACK / wnd-update
        # paths take a different early-return route that
        # bypasses the TS-recent hook today; full RFC 7323 §4.3
        # conformance for those paths is a Phase-4-or-later
        # concern).
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=new_tsval,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"peer-data",
        )
        self._drive_rx(frame=peer_data)

        session.send(data=b"world")
        tx = self._advance(ms=1)
        probe = self._parse_tx(tx[0])

        self.assertEqual(
            probe.tsecr,
            new_tsval,
            msg=(
                "Outbound TSecr MUST reflect the "
                f"updated '_ts_recent' = {new_tsval:#x}. Got "
                f"TSecr={probe.tsecr}."
            ),
        )


class TestTcpTimestampsPhase3(TcpTestCase):
    """
    Phase 3 invariants: TSecr-driven RTTM (RFC 7323 §4)
    measures RTT cleanly even on Karn-tainted retransmits,
    where the Phase-2 sample tracker would skip the update.

    The distinguishing test is the retransmit case: the
    Phase-2 sample tracker invalidates samples from
    retransmitted segments per RFC 6298 §3 (Karn's algorithm),
    so the smoothed estimator stops moving until a fresh
    non-retransmitted sample arrives. RFC 7323 §4 obviates
    Karn entirely - peer's TSecr identifies WHICH transmission
    it acknowledges, so RTT can be measured cleanly.
    """

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED
        assert session._ts.send_ts
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__rttm__karn_tainted_retransmit_measures_rtt_via_tsecr(self) -> None:
        """
        Ensure that when peer's ACK echoes a TSecr
        identifying the retransmitted segment's TSval, the
        runtime measures RTT directly from TSecr and folds
        it into '_rto_state' via 'update', superseding the
        Phase-2 sample tracker's Karn-mandated skip.

        Reference: RFC 7323 §4 (TSecr-driven RTTM obviates Karn).
        """

        from pytcp.protocols.tcp.tcp__rto import update as rto_update

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        payload = b"hello"
        session.send(data=payload)
        self._advance(ms=1)

        # Drive past the RTO timer so retransmit fires.
        # Post-handshake rto_ms = 1000 (clamped). Retransmit at
        # ~ t=1002 ms.
        self._advance(ms=1001)

        # Verify the retransmit fired (Karn-tainted sample).
        self.assertTrue(
            session._rtt.retransmitted,
            msg="Setup invariant: retransmit must have tainted the sample.",
        )
        post_retransmit_state = session._rto_state
        # Capture the retransmit's TSval - the retransmit
        # segment was emitted at ~t=1002 ms and its TSval
        # equals stack.timer.now_ms at that moment. With the
        # FakeTimer's 1ms tick the retransmit's TSval is
        # roughly the now_ms at the retransmit fire time.
        # Find it from the latest TX frame.
        all_tx = list(self._frames_tx)
        retransmit_probe = self._parse_tx(all_tx[-1])
        retransmit_tsval = retransmit_probe.tsval
        assert retransmit_tsval is not None

        # Advance another 5 ms then drive peer ACK echoing the
        # retransmit's TSval as TSecr.
        self._advance(ms=5)
        observed_rtt = self._timer.now_ms - retransmit_tsval

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL + 100,
            tsecr=retransmit_tsval,
        )
        self._drive_rx(frame=peer_ack)

        # Phase 3 expectation: '_rto_state' moved via update
        # despite the Karn taint. Compute expected.
        expected = rto_update(post_retransmit_state, observed_rtt)
        self.assertEqual(
            session._rto_state,
            expected,
            msg=(
                "TSecr-driven RTTM MUST fold "
                f"observed_rtt={observed_rtt} via 'update' even "
                f"after a Karn-tainted retransmit. Without "
                f"Phase 3 the Karn skip leaves '_rto_state' at "
                f"the post-back_off snapshot. Expected "
                f"{expected!r}, got {session._rto_state!r}."
            ),
        )

    def test__rttm__non_tsopt_peer_falls_back_to_sample_tracker(self) -> None:
        """
        Ensure a peer that did not negotiate the Timestamps
        option falls through to the RTT sample tracker - the
        bilateral negotiation gate keeps the TSecr path off for
        legacy peers, so the existing sample-harvest logic is
        used unchanged.

        Reference: RFC 7323 §3 (Timestamps option bilateral negotiation).
        Reference: RFC 6298 §2 (RTO sample tracker).
        """

        from pytcp.protocols.tcp.tcp__rto import update as rto_update

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
            # No tsval/tsecr.
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertFalse(session._ts.send_ts, msg="Peer did not advertise TSopt.")
        session._cc.snd_ewn = PEER__WIN

        pre_ack_state = session._rto_state
        payload = b"hello"
        session.send(data=payload)
        self._advance(ms=1)
        sample_send_time = session._rtt.send_time_ms

        self._advance(ms=10)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        observed_rtt = self._timer.now_ms - (sample_send_time or 0)
        expected = rto_update(pre_ack_state, observed_rtt)
        self.assertEqual(
            session._rto_state,
            expected,
            msg=(
                f"Sample-tracker fallback: non-TSopt peer's "
                f"ACK MUST fold observed_rtt={observed_rtt} via "
                f"update. Expected {expected!r}, got "
                f"{session._rto_state!r}."
            ),
        )


class TestTcpTimestampsPhase4(TcpTestCase):
    """
    Phase 4 invariants: PAWS (Protection Against Wrapped
    Sequence numbers) per RFC 7323 §5.

    PAWS drops inbound segments whose TSval is less than
    '_ts_recent' (modular 32-bit comparison) - this defends
    against wrapped-sequence attacks across the 4 GB seq
    space.
    """

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED
        assert session._ts.send_ts
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__paws__stale_tsval_segment_dropped(self) -> None:
        """
        Ensure an inbound data segment with TSval strictly
        less than '_ts_recent' is dropped without affecting
        session state. PAWS defends against wrapped-sequence
        attacks where an old segment delayed in the network
        re-emerges with a low TSval but a newly-valid seq.

        Reference: RFC 7323 §5 (PAWS).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        rcv_nxt_pre = session._rcv_seq.nxt
        rx_buffer_pre = bytes(session._rx_buffer)

        stale_tsval = PEER__TSVAL_INITIAL - 100
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=stale_tsval,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"stale-data",
        )
        self._drive_rx(frame=peer_data)

        self.assertEqual(
            session._rcv_seq.nxt,
            rcv_nxt_pre,
            msg=(
                f"Stale-TSval segment "
                f"(tsval={stale_tsval:#x} < _ts_recent="
                f"{PEER__TSVAL_INITIAL:#x}) MUST be dropped "
                "without advancing RCV.NXT. Got "
                f"_rcv_nxt={session._rcv_seq.nxt}."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_pre,
            msg="Stale-TSval segment's data MUST NOT enter the RX buffer.",
        )

    def test__paws__current_tsval_segment_accepted(self) -> None:
        """
        Ensure an inbound segment with TSval greater than
        or equal to '_ts_recent' is accepted normally; PAWS
        only rejects strictly-stale TSvals.

        Reference: RFC 7323 §5 (PAWS).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        fresh_tsval = PEER__TSVAL_INITIAL + 1
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=fresh_tsval,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"fresh-data",
        )
        self._drive_rx(frame=peer_data)

        self.assertEqual(
            session._rcv_seq.nxt,
            PEER__ISS + 1 + len(b"fresh-data"),
            msg=("A fresh-TSval segment MUST be accepted " "normally; RCV.NXT advances past the data."),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            b"fresh-data",
            msg="Fresh-TSval segment's data MUST enter the RX buffer.",
        )


class TestTcpTimestampsPhase4FsmWide(TcpTestCase):
    """
    Phase 4b extension: PAWS + '_ts_recent' update must apply
    to ALL FSM dispatch paths, not only segments routed through
    '_process_ack_packet'. Specifically the dup-ACK fast-
    retransmit branch, the OOO-queue branch in ESTABLISHED, and
    the late-segment branch in TIME_WAIT all currently bypass
    the PAWS check shipped in commit '79ed38e'.

    RFC 7323 §4.3 mandates '_ts_recent' refresh on every
    accepted segment in receive sequence space. RFC 7323 §5
    mandates PAWS rejection of stale-TSval segments at every
    inbound dispatch boundary. Without these tests the bypass
    paths can leak old-incarnation segments into recovery
    machinery.
    """

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED
        assert session._ts.send_ts
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__paws__dup_ack_with_stale_tsval_dropped(self) -> None:
        """
        Ensure that a duplicate ACK whose TSval is strictly
        less than '_ts_recent' is dropped at the FSM
        dispatch boundary before the dup-ACK count fast-
        retransmit machinery sees it.

        Reference: RFC 7323 §5 (PAWS at FSM-wide dispatch).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        session._tx.buffer.extend(b"X" * 100)
        self._advance(ms=1)

        snd_una_pre = session._snd_seq.una
        cwnd_pre = session._cc.cwnd
        retransmit_request_count_pre = session._tx.retransmit_request_counter.get(snd_una_pre, 0)

        stale_tsval = PEER__TSVAL_INITIAL - 100
        for _ in range(3):
            stale_dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=snd_una_pre,
                flags=("ACK",),
                win=PEER__WIN,
                tsval=stale_tsval,
                tsecr=PEER__TSVAL_INITIAL,
            )
            self._drive_rx(frame=stale_dup_ack)

        self.assertEqual(
            session._cc.cwnd,
            cwnd_pre,
            msg=(
                "Stale-TSval dup-ACKs MUST be dropped "
                "before the fast-retransmit count "
                "increments. cwnd MUST be unchanged."
            ),
        )
        self.assertEqual(
            session._tx.retransmit_request_counter.get(snd_una_pre, 0),
            retransmit_request_count_pre,
            msg="Stale-TSval dup-ACKs MUST NOT increment the per-seq dup-ACK counter.",
        )

    def test__paws__ts_recent_updated_on_dup_ack_with_fresh_tsval(self) -> None:
        """
        Ensure an accepted dup-ACK with a fresh TSval
        refreshes '_ts_recent' so peer's TS clock progress
        is reflected before peer sends data again.

        Reference: RFC 7323 §4.3 (_ts_recent update on dup-ACK with fresh TSval).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        session._tx.buffer.extend(b"X" * 100)
        self._advance(ms=1)

        snd_una_pre = session._snd_seq.una
        fresh_tsval = PEER__TSVAL_INITIAL + 500
        dup_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=snd_una_pre,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=fresh_tsval,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=dup_ack)

        self.assertEqual(
            session._ts.ts_recent,
            fresh_tsval,
            msg=(
                "RFC 7323 §4.3: '_ts_recent' MUST refresh on an "
                f"accepted dup-ACK carrying TSval={fresh_tsval}. "
                f"Got _ts_recent={session._ts.ts_recent}."
            ),
        )

    def test__paws__time_wait_late_segment_with_stale_tsval_dropped(self) -> None:
        """
        Ensure PAWS applies to TIME_WAIT: a delayed peer-FIN
        retransmit from an earlier incarnation with stale
        TSval is dropped before the FIN-retransmit handler
        re-arms the TIME_WAIT timer.

        Reference: RFC 7323 §5 (PAWS in TIME_WAIT).
        Reference: RFC 1337 §3 (TIME-WAIT assassination mitigations).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        # Active close: ESTABLISHED -> FIN_WAIT_1 -> FIN_WAIT_2 ->
        # TIME_WAIT. The transition takes 2 timer ticks: tick 1
        # walks ESTABLISHED -> FIN_WAIT_1, tick 2 emits the FIN
        # from FIN_WAIT_1.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL + 1,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL + 2,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=peer_fin)

        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=f"Active-close path must deterministically reach TIME_WAIT; got {session.state}.",
        )

        ts_recent_pre = session._ts.ts_recent
        stale_late_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL - 1000,
            tsecr=PEER__TSVAL_INITIAL,
        )
        frames_tx_before = len(self._frames_tx)
        self._drive_rx(frame=stale_late_fin)
        new_frames = list(self._frames_tx[frames_tx_before:])

        # PAWS MUST gate the segment before the FIN-retransmit
        # handler runs; '_ts_recent' MUST NOT advance and the
        # only legal outbound is the §5.3 R1 challenge-ACK
        # reply (a no-data, no-FIN ACK at SND.NXT/RCV.NXT).
        self.assertEqual(
            session._ts.ts_recent,
            ts_recent_pre,
            msg=("PAWS-rejected segment MUST NOT update " "'_ts_recent'."),
        )
        for frame in new_frames:
            probe = self._parse_tx(frame)
            self.assertNotIn(
                "FIN",
                probe.flags,
                msg=(
                    "PAWS gate MUST drop the stale FIN before "
                    "the TIME_WAIT FIN-retransmit handler runs; "
                    f"got TX FIN flags={probe.flags}."
                ),
            )
            self.assertEqual(
                probe.payload,
                b"",
                msg=("Only legal post-PAWS-drop emit is an empty " f"R1 ACK; got payload={probe.payload!r}."),
            )


class TestTcpTimestampsPhase1PassiveCrossRfc(TcpTestCase):
    """
    Cross-RFC interaction (Phase B1 of the test-coverage audit):
    bilateral TSopt negotiation across the passive-open path,
    confirming the TSopt + listener fork pattern composes
    correctly with the existing wildcard-listen mechanism.
    """

    def _make_listen_session(self, *, iss: int) -> tuple[TcpSocket, TcpSession]:
        """Build a wildcard-listen TcpSession."""

        from net_addr import Ip4Address as _Ip4Address
        from pytcp.protocols.tcp.tcp__enums import SysCall as _SysCall

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
        session.tcp_fsm(syscall=_SysCall.LISTEN)
        return sock, session  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def test__ts__passive_open_with_peer_tsopt_emits_syn_ack_with_tsopt(self) -> None:
        """
        Ensure that a peer SYN carrying TSopt + WSCALE +
        SACK-permitted causes the listener to spawn a child
        whose SYN+ACK echoes peer's TSval and carries our
        own TSopt + WSCALE + SACK-permitted.

        Reference: RFC 7323 §3 (Timestamps bilateral negotiation, passive open).
        """

        listen_sock, _ = self._make_listen_session(iss=0x0000_3000)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_4000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=7,
            sackperm=True,
            tsval=PEER__TSVAL_INITIAL,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn)
        tx = self._advance(ms=1)

        self.assertEqual(
            len(tx),
            1,
            msg="Passive-open path must emit exactly one SYN+ACK on the first tick.",
        )
        syn_ack = self._parse_tx(tx[0])
        self.assertIn("SYN", syn_ack.flags)
        self.assertIn("ACK", syn_ack.flags)
        self.assertIsNotNone(
            syn_ack.tsval,
            msg="Cross-RFC: peer offered TSopt; our SYN+ACK MUST echo with our TSopt.",
        )
        self.assertEqual(
            syn_ack.tsecr,
            PEER__TSVAL_INITIAL,
            msg=(
                "Cross-RFC: SYN+ACK's TSecr MUST equal peer's " f"TSval ({PEER__TSVAL_INITIAL}). Got {syn_ack.tsecr}."
            ),
        )
        self.assertIsNotNone(
            syn_ack.wscale,
            msg="Cross-RFC: peer offered WSCALE; our SYN+ACK MUST advertise WSCALE.",
        )
        self.assertTrue(
            syn_ack.sackperm,
            msg="Cross-RFC: peer offered SACK-permitted; our SYN+ACK MUST advertise SACK-permitted.",
        )

        # Reset stack.sockets to the listener-only state so other tests are
        # not contaminated by the spawned child socket.
        for sid in list(stack.sockets):
            if sid != listen_sock.socket_id:
                del stack.sockets[sid]

    def test__ts__passive_open_without_peer_tsopt_omits_tsopt_in_syn_ack(self) -> None:
        """
        Ensure that a peer SYN without TSopt causes the
        listener's SYN+ACK to omit TSopt.

        Reference: RFC 7323 §3 (Timestamps bilateral negotiation, passive open omit).
        """

        listen_sock, _ = self._make_listen_session(iss=0x0000_3100)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_4000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        tx = self._advance(ms=1)

        self.assertEqual(len(tx), 1)
        syn_ack = self._parse_tx(tx[0])
        self.assertIsNone(
            syn_ack.tsval,
            msg=("Peer did not offer TSopt; our SYN+ACK " "MUST NOT advertise TSopt."),
        )

        for sid in list(stack.sockets):
            if sid != listen_sock.socket_id:
                del stack.sockets[sid]


class TestTcpTimestampsRetransmitFreshness(TcpTestCase):
    """
    Regression guards for RFC 7323 §3 freshness on retransmit:
    a retransmitted segment MUST carry the CURRENT 'now_ms' as
    TSval (not a value captured at original-queue time) and the
    CURRENT '_ts_recent' as TSecr (not a stale captured value).

    PyTCP's '_transmit_packet' computes both fields at the
    moment of transmission ('tcp__session.py:880-906'), so a
    retransmit naturally picks up the latest clock and the
    latest peer TSval. These tests pin that behaviour so a
    future refactor that introduces a per-segment queue or
    captures TSopt at enqueue time cannot silently re-introduce
    the original-vs-retransmit ambiguity that TSopt is meant
    to resolve at the wire level.

    RFC 7323 §3 wording: "The Timestamp Value field (TSval)
    contains the current value of the timestamp clock of the
    TCP sending the option." The 'current value' MUST mean
    "current at transmission", not "current at queue time".
    """

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._ts.send_ts
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__retransmit__tsval_reflects_current_now_ms_not_queue_time(self) -> None:
        """
        Ensure that a retransmitted segment carries TSval =
        current now_ms, not the value captured at the
        original transmission, so peer's RTT measurement on
        the retransmit's ACK identifies the retransmission.

        Reference: RFC 7323 §3 (TSval freshness on retransmit).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        session.send(data=b"hello")
        original_send_now_ms = self._timer.now_ms + 1
        original_tx = self._advance(ms=1)
        self.assertEqual(
            len(original_tx),
            1,
            msg="Setup invariant: original data segment must fire on the next tick.",
        )
        original_probe = self._parse_tx(original_tx[0])
        self.assertEqual(
            original_probe.tsval,
            original_send_now_ms,
            msg=(
                "Setup invariant: original segment's TSval MUST equal "
                f"the now_ms at send time ({original_send_now_ms}). "
                f"Got {original_probe.tsval}."
            ),
        )

        # Advance past the RTO so the retransmit fires.
        retransmit_send_now_ms_lower = self._timer.now_ms + 1
        retransmit_tx = self._advance(ms=1500)
        retransmit_probes = [self._parse_tx(f) for f in retransmit_tx if f]
        retransmits = [p for p in retransmit_probes if p.payload]
        self.assertGreaterEqual(
            len(retransmits),
            1,
            msg=(
                "Setup invariant: by t=original+1500 ms the RTO MUST "
                "have fired and a retransmit MUST be on the wire. "
                f"Got {len(retransmits)} data segment(s)."
            ),
        )
        first_retransmit = retransmits[0]

        retransmit_tsval = first_retransmit.tsval
        original_tsval = original_probe.tsval
        assert retransmit_tsval is not None and original_tsval is not None
        self.assertGreater(
            retransmit_tsval,
            original_tsval,
            msg=(
                "Retransmit's TSval MUST be GREATER than "
                f"the original's TSval ({original_tsval}). "
                f"Got retransmit TSval={retransmit_tsval}."
            ),
        )
        self.assertGreaterEqual(
            retransmit_tsval,
            retransmit_send_now_ms_lower,
            msg=(
                "Retransmit's TSval MUST be at least the "
                "now_ms at the moment the retransmit was "
                f"scheduled ({retransmit_send_now_ms_lower}). "
                f"Got TSval={retransmit_tsval}."
            ),
        )

    def test__retransmit__tsecr_reflects_current_ts_recent_not_stale_capture(self) -> None:
        """
        Ensure that a retransmitted segment carries TSecr =
        current '_ts_recent', not a value captured at the
        original transmission. If peer sent any other
        segment in the meantime, its TSval has updated
        '_ts_recent' and the retransmit echoes the latest
        value.

        Reference: RFC 7323 §3 (TSecr echoes _ts_recent on every send).
        Reference: RFC 7323 §4.3 (_ts_recent update).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        session.send(data=b"hello")
        original_tx = self._advance(ms=1)
        original_probe = self._parse_tx(original_tx[0])
        self.assertEqual(
            original_probe.tsecr,
            PEER__TSVAL_INITIAL,
            msg=(
                "Setup invariant: original segment's TSecr MUST echo "
                f"_ts_recent at send time ({PEER__TSVAL_INITIAL}). "
                f"Got {original_probe.tsecr}."
            ),
        )

        # Peer sends a wnd-update (dup-ACK shape with new win)
        # carrying a fresh TSval. The PAWS helper updates
        # '_ts_recent' on accepted in-window segments per
        # RFC 7323 §4.3.
        fresh_peer_tsval = PEER__TSVAL_INITIAL + 500
        peer_wnd_update = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,  # snd_una; doesn't ack the data
            flags=("ACK",),
            win=PEER__WIN + 1,
            tsval=fresh_peer_tsval,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=peer_wnd_update)
        self.assertEqual(
            session._ts.ts_recent,
            fresh_peer_tsval,
            msg=(
                "Setup invariant: peer's wnd-update TSval MUST refresh "
                f"_ts_recent to {fresh_peer_tsval}. Got "
                f"_ts_recent={session._ts.ts_recent}."
            ),
        )

        # Advance past the RTO; retransmit fires.
        retransmit_tx = self._advance(ms=1500)
        retransmit_probes = [self._parse_tx(f) for f in retransmit_tx if f]
        retransmits = [p for p in retransmit_probes if p.payload]
        self.assertGreaterEqual(
            len(retransmits),
            1,
            msg=("Setup invariant: RTO MUST have fired by t=1500 ms. " f"Got {len(retransmits)} data segment(s)."),
        )
        first_retransmit = retransmits[0]

        self.assertEqual(
            first_retransmit.tsecr,
            fresh_peer_tsval,
            msg=(
                "RFC 7323 §3 + §4.3 freshness: retransmit's TSecr "
                "MUST echo the CURRENT '_ts_recent' "
                f"({fresh_peer_tsval}, refreshed by peer's wnd-update "
                "between original send and retransmit), NOT the "
                f"value captured at original transmission "
                f"({PEER__TSVAL_INITIAL}). Got "
                f"TSecr={first_retransmit.tsecr}."
            ),
        )

    def test__timestamps__outdated__paws_invalidates_ts_recent_after_24_day_idle(self) -> None:
        """
        Ensure that when the connection has been idle for
        more than 24 days, an inbound segment whose TSval
        appears 'stale' under the strict PAWS check is NOT
        dropped: TS.Recent is invalidated per the §5.5
        outdated-timestamps mitigation, the segment is
        accepted, and TS.Recent is refreshed to the
        incoming TSval. Without this gate a connection
        idled past the 24-day window would freeze (PAWS
        rejecting every subsequent segment) until the peer's
        TS clock wrapped its sign bit again.

        Reference: RFC 7323 §5.5 (invalidate TS.Recent on idle > 24 days).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )
        # Snapshot current state and make TS.Recent look as
        # if it was last updated 25 days ago.
        ts_recent_before = session._ts.ts_recent
        twenty_five_days_ms = 25 * 24 * 3600 * 1000
        session._ts.ts_recent_updated_at_ms -= twenty_five_days_ms

        # Inbound segment with TSval one tick older than
        # _ts_recent. Under strict PAWS this would be
        # dropped; under §5.5 it MUST be accepted because
        # _ts_recent is now outdated.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=(ts_recent_before - 1) & 0xFFFF_FFFF,
            tsecr=session._snd_seq.ini,
            payload=b"hello",
        )
        self._drive_rx(frame=peer_data)
        self._advance(ms=200)

        # Segment was accepted: data made it into the rx
        # buffer (non-empty) and _ts_recent advanced to the
        # new (apparently-stale) value.
        self.assertEqual(
            bytes(session._rx_buffer),
            b"hello",
            msg=(
                "RFC 7323 §5.5: a stale-TSval segment past the "
                "24-day idle threshold MUST be accepted; the "
                "payload should be enqueued. Got "
                f"_rx_buffer={bytes(session._rx_buffer)!r}."
            ),
        )
        self.assertEqual(
            session._ts.ts_recent,
            (ts_recent_before - 1) & 0xFFFF_FFFF,
            msg=(
                "RFC 7323 §5.5: after accepting a stale-TSval "
                "segment via the outdated-mitigation path, "
                "TS.Recent MUST be refreshed to the segment's "
                f"TSval. Got _ts_recent={session._ts.ts_recent}."
            ),
        )

    def test__timestamps__outdated__paws_still_drops_stale_segment_within_idle_window(self) -> None:
        """
        Ensure the regression-guard direction: when the
        connection has been idle for less than 24 days, a
        stale-TSval segment is still dropped by strict
        PAWS. The §5.5 outdated-timestamps mitigation only
        relaxes the check past the 24-day threshold; before
        that, the strict §5 PAWS rule applies unchanged.

        Reference: RFC 7323 §5 (strict PAWS within the 24-day idle window).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )
        ts_recent_before = session._ts.ts_recent
        # Pretend TS.Recent is 1 hour old - well within the
        # 24-day idle window. Strict PAWS must still apply.
        one_hour_ms = 3600 * 1000
        session._ts.ts_recent_updated_at_ms -= one_hour_ms

        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=(ts_recent_before - 1) & 0xFFFF_FFFF,
            tsecr=session._snd_seq.ini,
            payload=b"world",
        )
        self._drive_rx(frame=peer_data)
        self._advance(ms=200)

        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg=(
                "RFC 7323 §5: within the 24-day idle window, "
                "PAWS MUST still drop a stale-TSval segment. "
                f"Got _rx_buffer={bytes(session._rx_buffer)!r}."
            ),
        )
        self.assertEqual(
            session._ts.ts_recent,
            ts_recent_before,
            msg=(
                "RFC 7323 §5: TS.Recent MUST NOT advance on a "
                "stale-TSval segment dropped by strict PAWS. "
                f"Got _ts_recent={session._ts.ts_recent}."
            ),
        )


class TestTcpTimestampsRfc7323ShouldClauses(TcpTestCase):
    """
    RFC 7323 SHOULD-level deviations audited in
    'docs/rfc/tcp/rfc7323__timestamps_wscale_paws/adherence.md':

    1. §3.2 - TSopt SHOULD be present on every non-<RST> segment
       (already met by '_transmit_packet'); the matching
       SHOULD-include-TSopt-on-RST is also met because
       '_transmit_packet' carries no RST-specific suppress gate.
    2. §3.2 - "If a non-<RST> segment is received without a TSopt,
       a TCP SHOULD silently drop the segment". Implemented by
       '_check_paws_and_update_ts_recent' returning False when
       '_send_ts' is True and the inbound segment lacks TSopt.
    3. §5.3 R1 - the PAWS-stale drop SHOULD be accompanied by an
       ACK reply. Implemented by '_emit_paws_ack_reply' helper
       called from each PAWS-drop call site.
    4. §4.3 - 'Last.ACK.sent' gate on '_ts_recent' update. The
       A/B/C echo cases reduce to "advance _ts_recent only on
       segments that fall within the most-recent-ACKed window";
       PyTCP's strict PAWS check + cum-ACK left-edge advance
       satisfies this without an extra Last.ACK.sent variable.
    """

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._ts.send_ts
        session._cc.snd_ewn = PEER__WIN
        return session

    def test__rfc7323__rst_in_synchronized_state_carries_tsopt(self) -> None:
        """
        Ensure that an RST emitted by the session FSM in a
        synchronized state (here: ABORT from ESTABLISHED) carries
        the Timestamps option when bilateral TSopt negotiation
        succeeded. The §3.2 "TSopt SHOULD be sent in an <RST>"
        SHOULD is implemented implicitly by '_transmit_packet'
        having no RST-specific suppress gate.

        Reference: RFC 7323 §3.2 (TSopt on RST SHOULD).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        before_tx = len(self._frames_tx)
        send_now_ms = self._timer.now_ms
        session.abort()
        tx = list(self._frames_tx[before_tx:])

        rsts = [self._parse_tx(frame) for frame in tx if "RST" in self._parse_tx(frame).flags]
        self.assertEqual(
            len(rsts),
            1,
            msg=(
                "ABORT in ESTABLISHED MUST emit exactly one RST. "
                f"Got {len(rsts)} RST frames among {len(tx)} TX frames."
            ),
        )
        probe = rsts[0]
        self.assertIsNotNone(
            probe.tsval,
            msg=(
                "RFC 7323 §3.2: RST emitted in a TS-negotiated "
                "session MUST carry the Timestamps option. Got "
                f"tsval={probe.tsval} on RST={probe.flags}."
            ),
        )
        self.assertEqual(
            probe.tsval,
            send_now_ms,
            msg=("RST TSval MUST equal current TS clock. Got " f"tsval={probe.tsval}, expected {send_now_ms}."),
        )
        self.assertEqual(
            probe.tsecr,
            PEER__TSVAL_INITIAL,
            msg=(
                "RST TSecr MUST equal '_ts_recent' (peer's last "
                f"TSval = {PEER__TSVAL_INITIAL:#x}). Got "
                f"tsecr={probe.tsecr}."
            ),
        )

    def test__rfc7323__missing_tsopt_segment_silently_dropped(self) -> None:
        """
        Ensure that a non-RST inbound segment lacking TSopt on a
        TS-negotiated session is silently dropped: its payload
        does not enter the receive buffer and no FIN-ack reply is
        emitted by the data path.

        Reference: RFC 7323 §3.2 (silent drop of missing-TSopt segments).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        # Inbound DATA segment with NO TSopt on a TS-negotiated session.
        data_frame_no_ts = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"missing-tsopt",
        )
        self._drive_rx(frame=data_frame_no_ts)

        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg=(
                "RFC 7323 §3.2: a non-RST inbound segment lacking "
                "TSopt on a TS-negotiated session MUST be silently "
                "dropped before its data enters the RX buffer. "
                f"Got _rx_buffer={bytes(session._rx_buffer)!r}."
            ),
        )

    def test__rfc7323__paws_drop_emits_ack_reply(self) -> None:
        """
        Ensure a stale-TSval segment dropped by PAWS triggers an
        ACK reply so the peer can re-sync its sender state without
        waiting for its own RTO.

        Reference: RFC 7323 §5.3 (R1 ACK reply on PAWS drop).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        stale_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL - 1,
            tsecr=0,
            payload=b"paws-stale",
        )
        tx = self._drive_rx(frame=stale_data)

        # Payload MUST NOT enter the buffer.
        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg=(
                "PAWS drop must keep the stale segment's data out "
                f"of the buffer. Got _rx_buffer={bytes(session._rx_buffer)!r}."
            ),
        )
        # An ACK reply MUST be emitted.
        replies = [self._parse_tx(frame) for frame in tx]
        ack_replies = [p for p in replies if "ACK" in p.flags and "RST" not in p.flags]
        self.assertGreaterEqual(
            len(ack_replies),
            1,
            msg=(
                "RFC 7323 §5.3 R1: PAWS-stale drop MUST be "
                f"accompanied by an ACK reply. Got {len(ack_replies)} "
                f"ACK frames among {len(replies)} TX frames."
            ),
        )

    def test__rfc7323__ooo_segment_does_not_refresh_ts_recent(self) -> None:
        """
        Ensure an inbound out-of-order segment (SEG.SEQ >
        RCV.NXT) passes PAWS but does NOT refresh '_ts_recent':
        the SEG.SEQ <= Last.ACK.sent gate must reject it.
        Without the gate, out-of-order segments inflate
        TS.Recent and the next outbound TSecr echoes a TSval the
        peer has not yet seen acknowledged, distorting the
        peer's RTT estimator.

        Reference: RFC 7323 §4.3 (Last.ACK.sent gate on TS.Recent).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )
        ts_recent_before = session._ts.ts_recent

        # OOO data segment: SEQ jumps past RCV.NXT by 1000 bytes,
        # leaving a hole. Fresh-TSval so PAWS lets it through.
        ooo_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 1000,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL + 50,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"ooo-bytes",
        )
        self._drive_rx(frame=ooo_data)

        self.assertEqual(
            session._ts.ts_recent,
            ts_recent_before,
            msg=(
                "RFC 7323 §4.3 rule (2): OOO segment's TSval "
                "MUST NOT refresh TS.Recent. Got "
                f"_ts_recent={session._ts.ts_recent}, expected "
                f"{ts_recent_before}."
            ),
        )

    def test__rfc7323__in_order_segment_refreshes_ts_recent(self) -> None:
        """
        Ensure an in-order inbound segment (SEG.SEQ == RCV.NXT)
        refreshes '_ts_recent': the SEG.SEQ <= Last.ACK.sent
        gate passes for in-order segments so TS.Recent is
        updated.

        Reference: RFC 7323 §4.3 (TS.Recent refresh on in-order accept).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        in_order_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL + 100,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"in-order",
        )
        self._drive_rx(frame=in_order_data)

        self.assertEqual(
            session._ts.ts_recent,
            PEER__TSVAL_INITIAL + 100,
            msg=(
                "RFC 7323 §4.3 rule (2): in-order segment's "
                "TSval MUST refresh TS.Recent. Got "
                f"_ts_recent={session._ts.ts_recent}."
            ),
        )


class TestTcpTimestampsClockWrap32Bit(TcpTestCase):
    """
    RFC 7323 §5.4 32-bit TS clock wrap-around tests.
    """

    def test__ts__active_open_syn_masks_tsval_to_32_bits(self) -> None:
        """
        Ensure an active-open SYN whose 'stack.timer.now_ms' exceeds
        the 32-bit unsigned range emits a TSval masked to UINT32_MAX
        rather than crashing in the TcpOptionTimestamps assertion.
        On hosts with uptime above 49.7 days, monotonic-ms-derived
        TS clocks naturally exceed 0xFFFFFFFF; the wire field is a
        4-byte unsigned integer that must wrap, not overflow.

        Reference: RFC 7323 §5.4 (TS clock 32-bit wrap-around).
        """

        # Set the FakeTimer's now_ms to one tick above UINT32_MAX
        # so the active-open SYN's TSval crosses the wrap boundary.
        UINT32_MAX = 0xFFFF_FFFF
        self._timer.now_ms = UINT32_MAX + 1

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        tx = self._advance(ms=1)

        self.assertEqual(
            len(tx),
            1,
            msg="Setup invariant: connect must emit one SYN frame.",
        )
        probe = self._parse_tx(tx[0])
        self.assertIn(
            "SYN",
            probe.flags,
            msg="Setup invariant: outbound frame must be the SYN.",
        )
        self.assertIsNotNone(
            probe.tsval,
            msg="Active-open SYN must carry the Timestamps option.",
        )
        # After advancing by 1 ms, now_ms = UINT32_MAX + 2 = 0x100000001;
        # masked to 32 bits this is 0x00000001.
        self.assertEqual(
            probe.tsval,
            0x0000_0001,
            msg=(
                "TSval must be masked to UINT32_MAX so the 4-byte "
                "wire field carries the wrapped clock value. Got "
                f"TSval={probe.tsval!r}."
            ),
        )

    def test__ts__post_handshake_data_segment_masks_tsval_to_32_bits(self) -> None:
        """
        Ensure post-handshake data segments also mask the TSval to
        32 bits when the TS clock has wrapped — the same wrap path
        that crashes on long-uptime hosts during a passive-open
        SYN+ACK reply.

        Reference: RFC 7323 §5.4 (TS clock 32-bit wrap-around).
        """

        # Establish a session with TSopt negotiated bilaterally.
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
            tsval=PEER__TSVAL_INITIAL,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        # Bypass slow-start so the data segment fires immediately.
        session._cc.snd_ewn = PEER__WIN

        # Cross the 32-bit wrap boundary mid-session.
        UINT32_MAX = 0xFFFF_FFFF
        self._timer.now_ms = UINT32_MAX

        session.send(data=b"x")
        tx = self._advance(ms=1)

        probe = self._parse_tx(tx[0])
        self.assertIsNotNone(
            probe.tsval,
            msg="Setup invariant: post-handshake segment must carry TSopt.",
        )
        # _now_ms = UINT32_MAX + 1 = 0x100000000 after the 1 ms tick;
        # masked to 32 bits this is 0x00000000.
        self.assertEqual(
            probe.tsval,
            0x0000_0000,
            msg=(
                "TSval must be masked to UINT32_MAX so the 4-byte "
                "wire field carries the wrapped clock value. Got "
                f"TSval={probe.tsval!r}."
            ),
        )
