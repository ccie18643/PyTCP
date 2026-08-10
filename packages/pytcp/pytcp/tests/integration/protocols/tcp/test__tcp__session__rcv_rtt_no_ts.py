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
Integration tests for the no-timestamps receiver-RTT fallback (Tier-3
Track R, step 6b). When a connection did not negotiate RFC 7323
timestamps, the receiver RTT (which DRS needs) is instead measured from
the wall-time to receive one advertised window of data — mirroring Linux
'tcp_rcv_rtt_measure' (win_dep=1, take the minimum). This keeps DRS
functional on a timestamp-less connection, which Linux autotunes by
default.

pytcp/tests/integration/protocols/tcp/test__tcp__session__rcv_rtt_no_ts.py

ver 3.0.9
"""

from pytcp.protocols.tcp.session import TcpSession
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL_ISS = 1000
_PEER_ISS = 5000
_LOCAL_PORT = 12345
_REMOTE_PORT = 80


class TestTcpSessionRcvRttNoTs(TcpTestCase):
    """
    The no-timestamps window-based receiver-RTT fallback tests.
    """

    def _establish_no_ts(self) -> TcpSession:
        """
        Drive an active-open handshake without timestamps and shrink the
        advertised window so a single window's worth of data crosses the
        RTT-measure anchor in a couple of small segments.
        """

        session = self._drive_handshake_to_established(iss=_LOCAL_ISS, peer_iss=_PEER_ISS)
        assert not session._ts.send_ts, "Setup: no bilateral TSopt without peer TSval."
        session._win.rcv_wnd_max = 1000
        return session

    def _peer_data(self, *, seq: int, payload: bytes) -> bytes:
        """
        Build an inbound data segment with no TSopt.
        """

        return build_tcp4(
            sport=_REMOTE_PORT,
            dport=_LOCAL_PORT,
            seq=seq,
            ack=_LOCAL_ISS + 1,
            flags=("ACK",),
            win=64240,
            payload=payload,
        )

    def test__no_ts_rtt__window_measure_seeds_estimate(self) -> None:
        """
        Ensure that on a timestamp-less connection the receiver RTT is
        seeded from the wall-time taken to receive one advertised window
        of data.

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux tcp_rcv_rtt_measure (window-time RTT without
        timestamps).
        """

        session = self._establish_no_ts()
        self._advance(ms=200)
        # First segment anchors the measure at 'rcv_nxt + rcv_wnd'.
        self._drive_rx(frame=self._peer_data(seq=_PEER_ISS + 1, payload=b"X" * 400))
        # One RTT later, the segment that fills the window crosses the
        # anchor and yields the sample.
        self._advance(ms=50)
        self._drive_rx(frame=self._peer_data(seq=_PEER_ISS + 401, payload=b"Y" * 600))

        self.assertIsNotNone(
            session._rcv_rtt.rtt_ms,
            msg="A no-timestamps connection must still produce a receiver RTT estimate.",
        )
        self.assertEqual(
            session._rcv_rtt.rtt_ms,
            50,
            msg="The window-based RTT must equal the wall-time to receive one window.",
        )

    def test__no_ts_rtt__enables_drs_growth(self) -> None:
        """
        Ensure the window-based estimate is sufficient to drive DRS, so a
        timestamp-less connection still auto-tunes its receive window
        (Linux autotunes such connections by default).

        Reference: RFC 9293 §3.8.6 (receive window management).
        Reference: Linux tcp_rcv_space_adjust (DRS runs without
        timestamps).
        """

        session = self._establish_no_ts()
        self._advance(ms=200)
        self._drive_rx(frame=self._peer_data(seq=_PEER_ISS + 1, payload=b"X" * 400))
        self._advance(ms=50)
        self._drive_rx(frame=self._peer_data(seq=_PEER_ISS + 401, payload=b"Y" * 600))
        self.assertIsNotNone(
            session._rcv_rtt.rtt_ms,
            msg="Setup: the window-based estimate must exist before DRS runs.",
        )

        # A high per-RTT throughput must now grow the window via DRS.
        before = session._win.rcv_wnd_max
        session._rcv_space.space = 1000
        session._rcv_space.copied_anchor = 0
        session._rcv_space.time_ms = 0
        session._rcv_copied_total = 200_000
        self._advance(ms=100)
        session._maybe_adjust_rcv_space()

        self.assertGreater(
            session._win.rcv_wnd_max,
            before,
            msg="DRS must grow the window on a no-timestamps connection.",
        )
