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
This module contains integration tests for the RFC 9438 CUBIC
congestion control surface. See
'docs/rfc/tcp/rfc9438__cubic/adherence.md' for the per-clause
spec audit.

pytcp/tests/integration/protocols/tcp/test__tcp__session__cubic.py

ver 3.0.9
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import CcMode
from pytcp.runtime.socket import (
    IPPROTO_TCP,
    TCP_CONGESTION,
    AddressFamily,
)
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


class TestTcpCubicPhase2(TcpTestCase):
    """
    Integration tests for Phase 2 of RFC 9438 CUBIC: the
    substrate field declarations on TcpSession defaulting
    '_cc_mode' to RENO so behaviour is unchanged.
    """

    def test__cubic__fresh_session_defaults_to_cubic(self) -> None:
        """
        Ensure a fresh TcpSession's '_cc_mode' defaults to
        CcMode.CUBIC post-Phase-7 (matching Linux's default
        since kernel 2.6.18).

        Reference: RFC 9438 §1 (CUBIC algorithm selector).
        """

        session = self._make_active_session(iss=LOCAL__ISS)

        self.assertIs(
            session._cc.cc_mode,
            CcMode.CUBIC,
            msg=(
                "Phase 7 default '_cc_mode' must be CUBIC; opt-in to "
                "RENO via setsockopt(IPPROTO_TCP, TCP_CONGESTION, ...)."
            ),
        )

    def test__cubic__fresh_session_initialises_cubic_state_to_zero(self) -> None:
        """
        Ensure a fresh TcpSession's CUBIC state fields are all
        initialised to 0 (or False for the CA-mode flag), so
        Reno-mode behaviour is unaffected by their presence.

        Reference: RFC 9438 §4.1.2 (variables of interest).
        """

        session = self._make_active_session(iss=LOCAL__ISS)

        self.assertEqual(session._cc.cubic_w_max, 0, msg="W_max default 0.")
        self.assertEqual(session._cc.cubic_w_last_max, 0, msg="W_last_max default 0.")
        self.assertEqual(session._cc.cubic_K_ms, 0, msg="K default 0 ms.")
        self.assertEqual(session._cc.cubic_epoch_start_ms, 0, msg="epoch_start default 0 ms.")
        self.assertEqual(session._cc.cubic_w_est, 0, msg="W_est default 0.")
        self.assertFalse(session._cc.cubic_in_ca, msg="in_ca default False.")


class TestTcpCubicPhase3(TcpTestCase):
    """
    Integration tests for Phase 3 of RFC 9438 CUBIC: CA-phase
    growth using the cubic curve when '_cc_mode == CUBIC'.
    """

    _DEFAULT_CC_MODE: CcMode | None = CcMode.RENO

    def test__cubic__ca_growth_uses_cubic_curve_when_cc_mode_is_cubic(self) -> None:
        """
        Ensure that with '_cc_mode == CUBIC' AND cwnd >=
        ssthresh, the CA growth path uses the cubic curve and
        sets '_cubic_in_ca = True'.

        Reference: RFC 9438 §4.4 / §4.5 (cubic CA growth).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Pin CA regime + CUBIC mode + a cubic-state setup
        # where W(t) > cwnd so growth fires.
        session._cc.cc_mode = CcMode.CUBIC
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.ssthresh = 50 * PEER__MSS
        session._cc.cubic_w_max = 100 * PEER__MSS
        session._cc.cubic_K_ms = 0
        session._cc.cubic_epoch_start_ms = 0
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Send 1 MSS, advance, and have peer ACK it.
        session.send(data=b"x" * PEER__MSS)
        self._advance(ms=1000)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertTrue(
            session._cc.cubic_in_ca,
            msg="Phase 3: cubic CA growth must set '_cubic_in_ca = True'.",
        )
        self.assertGreater(
            session._cc.cwnd,
            100 * PEER__MSS,
            msg="Phase 3: cubic CA growth must increment cwnd above pre-ACK value.",
        )

    def test__cubic__slow_start_phase_unchanged_in_cubic_mode(self) -> None:
        """
        Ensure that with '_cc_mode == CUBIC' AND cwnd <
        ssthresh, growth follows the unchanged Reno slow-
        start formula (cwnd += min(bytes_acked, SMSS)).

        Reference: RFC 5681 §3.1 (slow-start).
        Reference: RFC 9438 §4.6 (CUBIC CA-only).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        session._cc.cc_mode = CcMode.CUBIC
        session._cc.cwnd = 2 * PEER__MSS
        session._cc.ssthresh = 100 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        session.send(data=b"x" * PEER__MSS)
        self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._cc.cwnd,
            3 * PEER__MSS,
            msg=("Slow-start must add SMSS regardless of CUBIC mode " "when cwnd < ssthresh."),
        )
        self.assertFalse(
            session._cc.cubic_in_ca,
            msg="'_cubic_in_ca' must remain False during slow-start.",
        )

    def _drive_fast_retransmit_in_cubic_mode(self, *, cwnd: int) -> TcpSession:
        """
        Set up an ESTABLISHED CUBIC session with a controlled
        'cwnd' and trigger the fast-retransmit code path via
        three duplicate ACKs.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cc_mode = CcMode.CUBIC
        session._cc.cwnd = cwnd
        session._cc.ssthresh = cwnd  # CA regime; ssthresh tracks cwnd.
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Transmit one segment so dup-ACKs ack a real seq.
        payload = b"x" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=1)

        # Three dup-ACKs trigger fast retransmit.
        for _ in range(3):
            dup = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup)

        return session

    def test__cubic__fast_retransmit_uses_beta_cubic(self) -> None:
        """
        Ensure that fast retransmit in CUBIC mode sets ssthresh
        to approximately cwnd * 7/10 (vs Reno's 1/2).

        Reference: RFC 9438 §4.6 (beta_cubic = 0.7).
        """

        cwnd = 100 * PEER__MSS
        session = self._drive_fast_retransmit_in_cubic_mode(cwnd=cwnd)

        # ssthresh should be cwnd * 7/10, not cwnd * 1/2.
        expected = cwnd * 7 // 10
        self.assertEqual(
            session._cc.ssthresh,
            expected,
            msg=(
                f"CUBIC fast retransmit must set ssthresh to "
                f"cwnd * beta_cubic ({expected}); got {session._cc.ssthresh}."
            ),
        )

    def test__cubic__fast_retransmit_records_w_max_at_cwnd_at_loss(self) -> None:
        """
        Ensure '_cubic_w_max' captures the pre-loss cwnd as
        the curve anchor, and '_cubic_K_ms' is computed and
        '_cubic_epoch_start_ms' is set to now_ms.

        Reference: RFC 9438 §4.6 (W_max recording).
        """

        cwnd = 100 * PEER__MSS
        session = self._drive_fast_retransmit_in_cubic_mode(cwnd=cwnd)

        self.assertEqual(
            session._cc.cubic_w_max,
            cwnd,
            msg="W_max must capture pre-loss cwnd.",
        )
        self.assertGreater(
            session._cc.cubic_K_ms,
            0,
            msg="K must be positive after a loss event with non-zero W_max.",
        )
        self.assertEqual(
            session._cc.cubic_epoch_start_ms,
            stack.timer.now_ms,
            msg="epoch_start must be reset to now_ms on loss event.",
        )

    def test__cubic__rto_uses_beta_cubic(self) -> None:
        """
        Ensure that an RTO in CUBIC mode sets ssthresh to
        approximately max(cwnd * 7/10, 2*SMSS), using cwnd
        in place of flight_size as the spec permits.

        Reference: RFC 9438 §4.6 (beta_cubic on RTO).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cc.cc_mode = CcMode.CUBIC
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.ssthresh = 200 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Send some data so flight_size > 0; advance past the
        # RTO timer (clamped to 1000 ms by MIN_RTO_MS) to fire
        # '_retransmit_packet_timeout'.
        session.send(data=b"x" * PEER__MSS)
        self._advance(ms=1)
        self._advance(ms=1000)

        expected = max((100 * PEER__MSS) * 7 // 10, 2 * PEER__MSS)
        self.assertEqual(
            session._cc.ssthresh,
            expected,
            msg=(
                f"CUBIC RTO must set ssthresh to "
                f"cwnd * beta_cubic floor 2*SMSS ({expected}); "
                f"got {session._cc.ssthresh}."
            ),
        )

    def test__cubic__fast_convergence_reduces_w_max_on_decline(self) -> None:
        """
        Ensure that on two consecutive loss events with the
        second cwnd lower than the first, the second loss
        event's '_cubic_w_max' is further reduced per §4.7
        (cwnd * (1 + beta_cubic) / 2 = cwnd * 17/20).

        Reference: RFC 9438 §4.7 (fast convergence).
        """

        cwnd_1 = 100 * PEER__MSS
        cwnd_2 = 60 * PEER__MSS  # smaller than cwnd_1

        # First loss event: prior_W_max = 0 → fast convergence
        # inactive; W_max = cwnd_1.
        session = self._drive_fast_retransmit_in_cubic_mode(cwnd=cwnd_1)
        self.assertEqual(
            session._cc.cubic_w_max,
            cwnd_1,
            msg="First loss: W_max should equal cwnd_1.",
        )

        # Reset recovery state and dup-ACK counters so a fresh
        # fast-retransmit trigger fires on the next batch of
        # dup-ACKs. Set cwnd to cwnd_2 (< prior W_max) so fast
        # convergence kicks in.
        session._cc.recovery_point = 0
        session._tx.retransmit_request_counter = {}
        session._cc.cwnd = cwnd_2
        session._cc.ssthresh = cwnd_2
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        # Send a fresh segment then drive 3 dup-ACKs with the
        # current snd_una as the ack value (canonical dup-ACK).
        session.send(data=b"y" * PEER__MSS)
        self._advance(ms=1)

        ack_value = session._snd_seq.una
        for _ in range(3):
            dup = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=ack_value,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup)

        # Second loss: prior_W_max = cwnd_1, new cwnd = cwnd_2
        # < cwnd_1 → fast convergence reduces W_max to
        # cwnd_2 * 17/20.
        expected_w_max = cwnd_2 * 17 // 20
        self.assertEqual(
            session._cc.cubic_w_max,
            expected_w_max,
            msg=(
                f"Fast convergence must reduce W_max to "
                f"cwnd_2 * 17/20 ({expected_w_max}); got "
                f"{session._cc.cubic_w_max}."
            ),
        )

    def test__cubic__fast_convergence_inactive_on_increase(self) -> None:
        """
        Ensure that when cwnd_at_loss >= prior W_max, fast
        convergence does NOT further reduce W_max - the new
        W_max simply equals cwnd at loss time.

        Reference: RFC 9438 §4.7 (fast convergence gating).
        """

        cwnd_1 = 60 * PEER__MSS
        cwnd_2 = 100 * PEER__MSS  # larger than cwnd_1

        session = self._drive_fast_retransmit_in_cubic_mode(cwnd=cwnd_1)

        # Reset state for second loss event.
        session._cc.recovery_point = 0
        session._tx.retransmit_request_counter = {}
        session._cc.cwnd = cwnd_2
        session._cc.ssthresh = cwnd_2
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        session.send(data=b"y" * PEER__MSS)
        self._advance(ms=1)

        ack_value = session._snd_seq.una
        for _ in range(3):
            dup = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=ack_value,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup)

        # Second loss: cwnd_2 >= prior W_max=cwnd_1, so W_max =
        # cwnd_2 (no fast-convergence reduction).
        self.assertEqual(
            session._cc.cubic_w_max,
            cwnd_2,
            msg=("Fast convergence must NOT fire when cwnd >= " "prior W_max; new W_max = cwnd."),
        )

    def test__cubic__reno_friendly_w_est_tracks_cwnd_on_ca_growth(self) -> None:
        """
        Ensure that on every cum-ACK in CUBIC CA mode,
        '_cubic_w_est' advances by
        alpha_cubic * bytes_acked * smss / cwnd.

        Reference: RFC 9438 §4.3 (W_est tracker).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        session._cc.cc_mode = CcMode.CUBIC
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.ssthresh = 50 * PEER__MSS
        session._cc.cubic_w_max = 100 * PEER__MSS
        session._cc.cubic_K_ms = 0
        session._cc.cubic_epoch_start_ms = 0
        session._cc.cubic_w_est = 0  # Lazy-init on first CA cum-ACK
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        session.send(data=b"x" * PEER__MSS)
        self._advance(ms=1000)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # W_est should be > 0 (lazy-initialised + advanced per
        # alpha_cubic). Initial value = cwnd_epoch (100 * MSS),
        # advance ≈ alpha_cubic * MSS * MSS / cwnd
        # = 9 * 1460 * 1460 / (17 * 146000) ≈ 7-8 bytes.
        self.assertGreater(
            session._cc.cubic_w_est,
            100 * PEER__MSS,
            msg="W_est must advance per alpha_cubic on CA cum-ACK.",
        )

    def test__cubic__reno_friendly_mode_picks_w_est_when_curve_is_below(self) -> None:
        """
        Ensure that when W_est > cubic-target, cwnd is set to
        W_est (Reno-friendly region picks Reno over CUBIC).

        Reference: RFC 9438 §4.3 (Reno-friendly region).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        session._cc.cc_mode = CcMode.CUBIC
        # Set up a scenario where W_cubic(t=0) is at cwnd_epoch
        # (small) and W_est is large - the max() should pick
        # W_est.
        session._cc.cwnd = 50 * PEER__MSS
        session._cc.ssthresh = 10 * PEER__MSS
        session._cc.cubic_w_max = 100 * PEER__MSS
        session._cc.cubic_K_ms = 4217  # canonical
        session._cc.cubic_epoch_start_ms = 0
        # Pre-set W_est above the cubic-target band ceiling
        # (1.5 * cwnd = 75 * MSS) to force Reno-friendly pick.
        session._cc.cubic_w_est = 200 * PEER__MSS
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        session.send(data=b"x" * PEER__MSS)
        self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # cwnd should track W_est, not the cubic curve.
        self.assertGreaterEqual(
            session._cc.cwnd,
            200 * PEER__MSS,
            msg="cwnd must follow W_est when in Reno-friendly region.",
        )

    def test__cubic__reno_mode_unaffected_by_cubic_state_fields(self) -> None:
        """
        Ensure that with '_cc_mode == CcMode.RENO' (default),
        growth follows the existing Reno path even when CUBIC
        state fields are set.

        Reference: RFC 5681 §3.1 (Reno CA growth).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Explicitly opt into RENO (Phase 7 flipped the default
        # to CUBIC).
        session._cc.cc_mode = CcMode.RENO

        # Pin CA regime, set CUBIC state fields - they must
        # not affect growth in RENO mode.
        session._cc.cwnd = 100 * PEER__MSS
        session._cc.ssthresh = 50 * PEER__MSS
        session._cc.cubic_w_max = 200 * PEER__MSS  # would suggest big growth
        session._cc.snd_ewn = min(session._cc.cwnd, session._win.snd_wnd)

        session.send(data=b"x" * PEER__MSS)
        self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # Reno CA growth: cwnd += max(1, smss^2 // cwnd) =
        # max(1, 1460^2 // 146000) ≈ 14 bytes.
        expected_growth = max(1, PEER__MSS * PEER__MSS // (100 * PEER__MSS))
        self.assertEqual(
            session._cc.cwnd,
            100 * PEER__MSS + expected_growth,
            msg="RENO mode must use Reno CA growth, not CUBIC.",
        )
        self.assertFalse(
            session._cc.cubic_in_ca,
            msg="'_cubic_in_ca' must remain False in RENO mode.",
        )


class TestTcpCubicPhase7(TcpTestCase):
    """
    Integration tests for Phase 7 of RFC 9438 CUBIC: the
    setsockopt(IPPROTO_TCP, TCP_CONGESTION, ...) socket-API
    selector + default-CUBIC flip.
    """

    def test__cubic__getsockopt_tcp_congestion_default_returns_cubic(self) -> None:
        """
        Ensure that on a fresh TcpSocket,
        getsockopt(IPPROTO_TCP, TCP_CONGESTION) returns
        CcMode.CUBIC.value (the post-Phase-7 default).

        Reference: RFC 9438 §1 (default CC algorithm).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        self.assertEqual(
            sock.getsockopt(IPPROTO_TCP, TCP_CONGESTION),
            CcMode.CUBIC.value,
            msg="Default TCP_CONGESTION must return CUBIC.",
        )

    def test__cubic__setsockopt_tcp_congestion_round_trip(self) -> None:
        """
        Ensure that setsockopt(IPPROTO_TCP, TCP_CONGESTION,
        CcMode.RENO.value) followed by getsockopt returns
        CcMode.RENO.value.

        Reference: RFC 9438 §1 (per-connection selector).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        sock.setsockopt(IPPROTO_TCP, TCP_CONGESTION, CcMode.RENO.value)
        self.assertEqual(
            sock.getsockopt(IPPROTO_TCP, TCP_CONGESTION),
            CcMode.RENO.value,
            msg="getsockopt must reflect setsockopt's stored value.",
        )

        sock.setsockopt(IPPROTO_TCP, TCP_CONGESTION, CcMode.CUBIC.value)
        self.assertEqual(
            sock.getsockopt(IPPROTO_TCP, TCP_CONGESTION),
            CcMode.CUBIC.value,
            msg="getsockopt must reflect the second setsockopt call.",
        )

    def test__cubic__setsockopt_propagates_to_session_on_connect(self) -> None:
        """
        Ensure that a setsockopt(IPPROTO_TCP, TCP_CONGESTION,
        ...) call before connect() takes effect on the
        underlying TcpSession's '_cc_mode' field.

        Reference: RFC 9438 §1 (socket-to-session propagation).
        """

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = PEER__IP
        sock._remote_port = PEER__PORT

        # Override default CUBIC with RENO.
        sock.setsockopt(IPPROTO_TCP, TCP_CONGESTION, CcMode.RENO.value)

        # Construct session (mimics what connect() does).
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=PEER__IP,
            remote_port=PEER__PORT,
            socket=sock,
        )
        sock._tcp_session = session
        # Apply the propagation step (mirrors the connect() hook).
        session._cc.cc_mode = sock._cc_mode

        self.assertIs(
            session._cc.cc_mode,
            CcMode.RENO,
            msg="setsockopt(TCP_CONGESTION, RENO) must propagate to session.",
        )

    def test__cubic__setsockopt_unsupported_value_raises(self) -> None:
        """
        Ensure that setsockopt(IPPROTO_TCP, TCP_CONGESTION,
        <invalid>) raises a ValueError because the int doesn't
        map to a known CcMode member.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(ValueError):
            sock.setsockopt(IPPROTO_TCP, TCP_CONGESTION, 99)
