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
Integration tests for TCP send-buffer auto-tuning (Tier-3 Track S,
docs/refactor/tcp_buffer_autotuning.md §5). On ACK processing the session
grows a grow-only auto send-buffer bound toward '2 * max(IW, cwnd) *
per_mss', clamped at 'tcp.wmem.max', mirroring Linux 'tcp_sndbuf_expand'.
An explicit SO_SNDBUF (SOCK_SNDBUF_LOCK) disables auto-tuning. The auto
bound feeds the Tier-1 SO_SNDBUF gate via '_effective_sndbuf()'.

pytcp/tests/integration/protocols/tcp/test__tcp__session__sndbuf_autotune.py

ver 3.0.8
"""

from typing import override

from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__cwnd import INITIAL_WINDOW_FACTOR
from pytcp.runtime.socket import (
    SO_SNDBUF,
    SOCKET__SO_SNDBUF__DEFAULT,
    SOL_SOCKET,
)
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL_PORT = 12345
_REMOTE_PORT = 80


class TestTcpSessionSndbufAutotune(TcpTestCase):
    """
    The send-buffer auto-tuning grow-policy tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore any sysctl overridden by a clamp test so the mutated
        'tcp.wmem.max' cannot leak into a sibling test.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def _expected_auto(self, session: TcpSession) -> int:
        """
        Compute the expected auto send-buffer bound for the session's
        current cwnd / snd_mss, clamped at 'tcp.wmem.max' — the policy
        the implementation must reproduce.
        """

        iw_floor = INITIAL_WINDOW_FACTOR * session._win.snd_mss
        target = 2 * max(iw_floor, session._cc.cwnd)
        return min(target, tcp__constants.TCP__WMEM__MAX)

    def test__sndbuf_autotune__ack_grows_auto_bound(self) -> None:
        """
        Ensure processing a cumulative ACK grows the auto send-buffer
        bound to '2 * max(IW, cwnd) * per_mss' for the current cwnd, so
        the send buffer tracks the congestion window.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux tcp_sndbuf_expand (send buffer grows with cwnd).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        session.send(data=b"A" * 1460)
        self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=_REMOTE_PORT,
            dport=_LOCAL_PORT,
            seq=5001,
            ack=1000 + 1 + 1460,
            flags=("ACK",),
            win=64240,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._socket._sndbuf_auto,
            self._expected_auto(session),
            msg="The ACK must grow the auto send-buffer bound to 2 * max(IW, cwnd).",
        )
        self.assertGreater(
            session._socket._sndbuf_auto,
            0,
            msg="Auto-tuning must have raised the bound above zero.",
        )

    def test__sndbuf_autotune__effective_reflects_grown_bound(self) -> None:
        """
        Ensure '_effective_sndbuf()' returns the auto bound once it
        exceeds the static default, so the Tier-1 send gate admits the
        larger queue.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux socket(7) SO_SNDBUF (auto-tuned buffer size).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        # A cwnd whose 2x exceeds the 208 KiB static default, so the
        # grown auto bound becomes the effective value.
        session._cc.cwnd = 200_000
        session._maybe_expand_sndbuf()

        expected = self._expected_auto(session)
        self.assertGreater(
            expected,
            SOCKET__SO_SNDBUF__DEFAULT,
            msg="Setup: the grown bound must exceed the static default to be observable.",
        )
        self.assertEqual(
            session._socket._effective_sndbuf(),
            expected,
            msg="'_effective_sndbuf()' must return the grown auto bound.",
        )

    def test__sndbuf_autotune__clamps_at_wmem_max(self) -> None:
        """
        Ensure the grow policy saturates at 'tcp.wmem.max' so a large
        cwnd cannot push the send buffer past the operator ceiling.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux net.ipv4.tcp_wmem (max bounds the auto buffer).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        sysctl_module.set("tcp.wmem.max", 50_000)
        session._cc.cwnd = 200_000
        session._maybe_expand_sndbuf()

        self.assertEqual(
            session._socket._sndbuf_auto,
            50_000,
            msg="The auto bound must saturate at 'tcp.wmem.max'.",
        )

    def test__sndbuf_autotune__grow_only(self) -> None:
        """
        Ensure the auto bound never shrinks — a later smaller cwnd
        leaves the previously-grown bound in place.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux tcp_sndbuf_expand (send buffer is grow-only).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        session._cc.cwnd = 200_000
        session._maybe_expand_sndbuf()
        grown = session._socket._sndbuf_auto

        # cwnd collapses (e.g. after loss) — the bound must not shrink.
        session._cc.cwnd = session._win.snd_mss
        session._maybe_expand_sndbuf()

        self.assertEqual(
            session._socket._sndbuf_auto,
            grown,
            msg="A smaller cwnd must not shrink the auto send-buffer bound.",
        )

    def test__sndbuf_autotune__explicit_sndbuf_disables_autotune(self) -> None:
        """
        Ensure an explicit setsockopt(SO_SNDBUF) pins the send-buffer
        bound and disables auto-tuning (SOCK_SNDBUF_LOCK), so cwnd
        growth never moves the effective bound.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux socket(7) SO_SNDBUF (explicit size disables
        auto-tuning).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        # The handshake ACK already ran the expand once, so capture the
        # current auto bound; the lock must freeze it from here.
        auto_before = session._socket._sndbuf_auto
        session._socket.setsockopt(SOL_SOCKET, SO_SNDBUF, 100_000)
        session._cc.cwnd = 200_000
        session._maybe_expand_sndbuf()

        self.assertEqual(
            session._socket._sndbuf_auto,
            auto_before,
            msg="Explicit SO_SNDBUF must freeze the auto bound (no further growth).",
        )
        self.assertEqual(
            session._socket._effective_sndbuf(),
            100_000,
            msg="An explicit SO_SNDBUF must remain the effective bound across cwnd growth.",
        )
