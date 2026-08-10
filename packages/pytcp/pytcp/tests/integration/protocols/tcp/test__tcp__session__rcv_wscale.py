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
Integration tests for the receive window-scale chosen at SYN from
'tcp.rmem.max' (Tier-3 Track R, step 6a / R0). Like Linux
'tcp_select_initial_window', PyTCP sizes 'rcv_wsc' so the negotiated
shift can express the whole DRS ceiling ('tcp.rmem.max'); the default
6 MiB rmem.max yields shift 7 (unchanged), while a raised rmem.max
yields a larger shift so DRS can advertise past 8 MiB.

pytcp/tests/integration/protocols/tcp/test__tcp__session__rcv_wscale.py

ver 3.0.10
"""

from typing import override

from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL_ISS = 1000
_PEER_ISS = 5000


class TestTcpSessionRcvWscale(TcpTestCase):
    """
    The SYN-time receive window-scale derivation tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore any sysctl overridden by a raised-rmem.max test so the
        mutation cannot leak into a sibling test.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__rcv_wscale__default_rmem_max_offers_shift_7(self) -> None:
        """
        Ensure the default 'tcp.rmem.max' (6 MiB) yields a receive
        window-scale shift of 7 — exactly what Linux picks for the
        default receive buffer, so the wiring changes no behaviour on
        the common path.

        Reference: RFC 7323 §2.2 (window scale option).
        Reference: Linux tcp_select_initial_window (shift sized for
        tcp_rmem[2]).
        """

        session = self._drive_handshake_to_established(iss=_LOCAL_ISS, peer_iss=_PEER_ISS, peer_wscale=7)
        self.assertEqual(
            session._win.rcv_wsc,
            7,
            msg="The default rmem.max must derive the canonical shift 7.",
        )

    def test__rcv_wscale__raised_rmem_max_offers_larger_shift(self) -> None:
        """
        Ensure raising 'tcp.rmem.max' above the shift-7 ceiling yields a
        larger receive window-scale shift, so the negotiated scaling can
        express the enlarged DRS ceiling.

        Reference: RFC 7323 §2.2 (window scale option).
        Reference: Linux tcp_select_initial_window (shift grows with
        tcp_rmem[2]).
        """

        sysctl_module.set("tcp.rmem.max", 10_000_000)
        session = self._drive_handshake_to_established(iss=_LOCAL_ISS, peer_iss=_PEER_ISS, peer_wscale=7)
        # 65535 << 7 = 8388480 < 10_000_000 <= 16776960 = 65535 << 8.
        self.assertEqual(
            session._win.rcv_wsc,
            8,
            msg="A 10 MB rmem.max must derive shift 8 so the ceiling is expressible.",
        )

    def test__rcv_wscale__drs_grows_past_8mib_with_raised_rmem_max(self) -> None:
        """
        Ensure that with a raised 'tcp.rmem.max' and the correspondingly
        larger shift, DRS can grow the advertised window past the 8 MiB
        that shift 7 would cap it at, up to the new ceiling.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: RFC 7323 §2.2 (window scale bounds the advertised
        window).
        """

        sysctl_module.set("tcp.rmem.max", 10_000_000)
        session = self._drive_handshake_to_established(iss=_LOCAL_ISS, peer_iss=_PEER_ISS, peer_wscale=7)
        # Prime a huge per-RTT throughput so the grow saturates the ceiling.
        session._rcv_rtt.rtt_ms = 40
        session._rcv_copied_total = 50_000_000
        session._rcv_space.copied_anchor = 0
        session._rcv_space.time_ms = 0
        self._advance(ms=100)

        session._maybe_adjust_rcv_space()

        self.assertEqual(
            session._win.rcv_wnd_max,
            10_000_000,
            msg="DRS must grow to the raised rmem.max once the shift can express it.",
        )
