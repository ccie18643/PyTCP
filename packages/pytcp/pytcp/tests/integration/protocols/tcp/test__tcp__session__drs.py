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
Integration tests for receive-buffer Dynamic Right-Sizing (Tier-3 Track
R, R2-R4). Once per receiver-RTT, when the application has drained more
than the previously-measured per-RTT bytes, the session grows
'rcv_wnd_max' toward the estimated BDP ('2 * copied + 16 * advmss' plus a
sender-rate term), clamped at 'tcp.rmem.max', mirroring Linux
'tcp_rcv_space_adjust'. Gated on 'tcp.moderate_rcvbuf' and disabled when
SO_RCVBUF is set (SOCK_RCVBUF_LOCK).

pytcp/tests/integration/protocols/tcp/test__tcp__session__drs.py

ver 3.0.10
"""

from typing import override

from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.session import TcpSession
from pytcp.runtime.socket import SO_RCVBUF, SOL_SOCKET
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL_ISS = 1000
_PEER_ISS = 5000


class TestTcpSessionDrs(TcpTestCase):
    """
    The receive-buffer Dynamic Right-Sizing grow-policy tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore any sysctl overridden by a clamp / disable test so the
        mutation cannot leak into a sibling test.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def _expected_target(self, *, copied: int, space: int, advmss: int, rcv_wsc: int) -> int:
        """
        Compute the DRS grow target the implementation must reproduce:
        '2*copied + 16*advmss', a sender-rate headroom term, clamped at
        'tcp.rmem.max' and the WSCALE ceiling.
        """

        rcvwin = 2 * copied + 16 * advmss
        rcvwin += 2 * (rcvwin * (copied - space) // space)
        return min(rcvwin, tcp__constants.TCP__RMEM__MAX, 0xFFFF << rcv_wsc)

    def _establish(self) -> TcpSession:
        """
        Drive an active-open handshake with WSCALE negotiated so the
        advertised-window shift ('rcv_wsc') is non-zero — DRS can only
        grow the window past 65535 when the peer supports scaling
        (RFC 7323), so the grow tests require it.
        """

        return self._drive_handshake_to_established(
            iss=_LOCAL_ISS,
            peer_iss=_PEER_ISS,
            peer_wscale=7,
        )

    def _prime(self, session: TcpSession, *, rtt_ms: int, copied_total: int) -> None:
        """
        Prime the DRS state for a direct '_maybe_adjust_rcv_space' call:
        seed the receiver RTT, the cumulative copied-bytes counter, and
        anchor the measurement window at time 0.
        """

        session._rcv_rtt.rtt_ms = rtt_ms
        session._rcv_copied_total = copied_total
        session._rcv_space.copied_anchor = 0
        session._rcv_space.time_ms = 0

    def test__drs__grows_rcv_wnd_max_on_high_throughput(self) -> None:
        """
        Ensure that when the application drains more than the previously
        measured per-RTT bytes, DRS grows 'rcv_wnd_max' toward the
        estimated bandwidth-delay product.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux tcp_rcv_space_adjust (BDP-driven receive-buffer
        growth).
        """

        session = self._establish()
        space = session._rcv_space.space
        self._prime(session, rtt_ms=40, copied_total=200_000)
        self._advance(ms=100)

        session._maybe_adjust_rcv_space()

        expected = self._expected_target(
            copied=200_000,
            space=space,
            advmss=session._win.rcv_mss,
            rcv_wsc=session._win.rcv_wsc,
        )
        self.assertEqual(
            session._win.rcv_wnd_max,
            expected,
            msg="DRS must grow rcv_wnd_max toward the BDP estimate.",
        )
        self.assertGreater(
            session._win.rcv_wnd_max,
            space,
            msg="The grown window must exceed the initial measurement.",
        )

    def test__drs__cadence_gate_blocks_within_one_rtt(self) -> None:
        """
        Ensure DRS measures at most once per receiver-RTT: an adjust
        attempted before a full RTT has elapsed since the last
        measurement is a no-op.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux tcp_rcv_space_adjust (per-RTT measurement
        cadence).
        """

        session = self._establish()
        before = session._win.rcv_wnd_max
        self._advance(ms=100)
        session._rcv_rtt.rtt_ms = 40
        session._rcv_copied_total = 500_000
        session._rcv_space.copied_anchor = 0
        # Last measurement only 10 ms ago (< the 40 ms RTT).
        session._rcv_space.time_ms = self._timer.now_ms - 10

        session._maybe_adjust_rcv_space()

        self.assertEqual(
            session._win.rcv_wnd_max,
            before,
            msg="DRS must not grow before one receiver-RTT has elapsed.",
        )

    def test__drs__no_receiver_rtt_skips_adjust(self) -> None:
        """
        Ensure DRS does nothing while the receiver RTT estimate is unset
        — there is no cadence to measure against yet.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux tcp_rcv_space_adjust (skips when rtt_est is 0).
        """

        session = self._establish()
        before = session._win.rcv_wnd_max
        session._rcv_rtt.rtt_ms = None
        session._rcv_copied_total = 500_000
        self._advance(ms=100)

        session._maybe_adjust_rcv_space()

        self.assertEqual(
            session._win.rcv_wnd_max,
            before,
            msg="DRS must not grow without a receiver RTT estimate.",
        )

    def test__drs__explicit_so_rcvbuf_disables_drs(self) -> None:
        """
        Ensure an explicit setsockopt(SO_RCVBUF) pins the window and
        disables DRS (SOCK_RCVBUF_LOCK), so throughput growth never
        moves 'rcv_wnd_max' past the operator's value.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux socket(7) SO_RCVBUF (explicit size disables
        auto-tuning).
        """

        session = self._establish()
        session._socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 131072)
        self._prime(session, rtt_ms=40, copied_total=500_000)
        self._advance(ms=100)

        session._maybe_adjust_rcv_space()

        self.assertEqual(
            session._win.rcv_wnd_max,
            131072,
            msg="An explicit SO_RCVBUF must pin rcv_wnd_max and disable DRS growth.",
        )

    def test__drs__moderate_rcvbuf_off_disables_drs(self) -> None:
        """
        Ensure DRS is disabled entirely when 'tcp.moderate_rcvbuf' is 0,
        matching the Linux global off-switch.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux net.ipv4.tcp_moderate_rcvbuf (DRS enable gate).
        """

        session = self._establish()
        before = session._win.rcv_wnd_max
        sysctl_module.set("tcp.moderate_rcvbuf", 0)
        self._prime(session, rtt_ms=40, copied_total=500_000)
        self._advance(ms=100)

        session._maybe_adjust_rcv_space()

        self.assertEqual(
            session._win.rcv_wnd_max,
            before,
            msg="DRS must not grow when tcp.moderate_rcvbuf is off.",
        )

    def test__drs__clamps_at_rmem_max(self) -> None:
        """
        Ensure the grow policy saturates at 'tcp.rmem.max' so a huge
        throughput burst cannot push the advertised window past the
        operator ceiling.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux net.ipv4.tcp_rmem (max bounds the auto window).
        """

        session = self._establish()
        self._prime(session, rtt_ms=40, copied_total=50_000_000)
        self._advance(ms=100)

        session._maybe_adjust_rcv_space()

        self.assertEqual(
            session._win.rcv_wnd_max,
            tcp__constants.TCP__RMEM__MAX,
            msg="DRS must saturate the grown window at tcp.rmem.max.",
        )

    def test__drs__receive_path_triggers_adjust(self) -> None:
        """
        Ensure draining the receive buffer via receive() bumps the
        cumulative copied-bytes counter and runs the DRS adjust, so the
        window grows without any direct call.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux tcp_rcv_space_adjust (fired from tcp_recvmsg).
        """

        session = self._establish()
        session._rcv_rtt.rtt_ms = 40
        session._rcv_space.space = 1000
        session._rcv_space.copied_anchor = 0
        session._rcv_space.time_ms = 0
        # Stuff the receive buffer directly (bypass the advertised-window
        # limit) so a single drain exceeds the low measurement baseline;
        # set the data-ready event the normal enqueue path would raise so
        # receive() does not block on it.
        session._rx_buffer.extend(b"X" * 5000)
        session._event__rx_buffer.set()
        self._advance(ms=100)

        drained = session.receive(byte_count=5000)

        self.assertEqual(len(drained), 5000, msg="Setup: receive() must drain the stuffed bytes.")
        self.assertEqual(
            session._rcv_copied_total,
            5000,
            msg="receive() must bump the cumulative copied-bytes counter.",
        )
        expected = self._expected_target(
            copied=5000,
            space=1000,
            advmss=session._win.rcv_mss,
            rcv_wsc=session._win.rcv_wsc,
        )
        self.assertEqual(
            session._win.rcv_wnd_max,
            expected,
            msg="Draining via receive() must trigger the DRS grow.",
        )
