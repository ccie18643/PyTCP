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
Integration tests for SO_RCVBUF driving the TCP advertised receive
window. The window is 'max(0, rcv_wnd_max - len(rx_buffer))' (RFC
9293 §3.8.6) advertised scaled by 'rcv_wsc' (RFC 7323); the
'rcv_wnd_max' cap derives from the owning socket's SO_RCVBUF so an
application can size the receive window (unset keeps the
conservative 65535 default).

pytcp/tests/integration/protocols/tcp/test__tcp__session__so_rcvbuf.py

ver 3.0.9
"""

from pytcp.runtime.socket import SO_RCVBUF, SOCKET__SO_RCVBUF__DEFAULT, SOL_SOCKET
from pytcp.tests.lib.tcp_testcase import TcpTestCase


class TestTcpSessionSoRcvbuf(TcpTestCase):
    """
    The SO_RCVBUF-derived advertised-receive-window-cap tests.
    """

    def test__so_rcvbuf__sizes_rcv_wnd_max(self) -> None:
        """
        Ensure a session opened on a socket that set SO_RCVBUF caps
        the advertised receive window ('rcv_wnd_max') at that value,
        so the application can size the window.

        Reference: RFC 9293 §3.8.6 (receive window from buffer
        occupancy).
        Reference: Linux socket(7) SO_RCVBUF (receive-buffer size
        drives the advertised window).
        """

        session = self._make_active_session(iss=1000, so_rcvbuf=262144)

        self.assertEqual(
            session.rcv_wnd_max,
            262144,
            msg="rcv_wnd_max must derive from the socket's SO_RCVBUF.",
        )

    def test__so_rcvbuf__unset_keeps_default_cap(self) -> None:
        """
        Ensure a session opened on a socket that never set SO_RCVBUF
        keeps the conservative default receive-window cap, so the
        wiring changes no behaviour for the common case.

        Reference: RFC 9293 §3.8.6 (receive window from buffer
        occupancy).
        """

        session = self._make_active_session(iss=1000)

        self.assertEqual(
            session.rcv_wnd_max,
            SOCKET__SO_RCVBUF__DEFAULT,
            msg="rcv_wnd_max must keep the default cap when SO_RCVBUF is unset.",
        )

    def test__so_rcvbuf__window_shrinks_with_receive_buffer_occupancy(self) -> None:
        """
        Ensure the advertised receive window still shrinks as the
        receive buffer fills, measured against the SO_RCVBUF-derived
        cap rather than a fixed constant — the SWS / flow-control
        contract is preserved on top of the sized cap.

        Reference: RFC 9293 §3.8.6.2 (receiver SWS avoidance / window
        shrink with occupancy).
        """

        session = self._make_active_session(iss=1000, so_rcvbuf=262144)
        session._rx_buffer.extend(b"x" * 1000)

        self.assertEqual(
            session._rcv_wnd,
            262144 - 1000,
            msg="The advertised window must be the SO_RCVBUF cap minus buffered bytes.",
        )


class TestTcpSessionSoRcvbufMidConnection(TcpTestCase):
    """
    The mid-connection SO_RCVBUF grow-only tests (A3). Raising
    SO_RCVBUF on an established connection enlarges the advertised
    receive-window cap; lowering it is a no-op so the window's right
    edge is never retracted (RFC 9293 §3.8.6.2.1).
    """

    def test__so_rcvbuf__mid_connection_increase_grows_the_cap(self) -> None:
        """
        Ensure raising SO_RCVBUF on an established connection grows
        the advertised-receive-window cap — the receiver may open its
        window.

        Reference: RFC 9293 §3.8.6.2.1 (a receiver may enlarge the
        window).
        Reference: Linux socket(7) SO_RCVBUF (mid-connection resize).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        self.assertEqual(
            session.rcv_wnd_max,
            SOCKET__SO_RCVBUF__DEFAULT,
            msg="A connection opened without SO_RCVBUF starts at the default cap.",
        )

        session._socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 131072)

        self.assertEqual(
            session.rcv_wnd_max,
            131072,
            msg="Raising SO_RCVBUF mid-connection must grow the advertised-window cap.",
        )

    def test__so_rcvbuf__mid_connection_decrease_does_not_shrink_the_cap(self) -> None:
        """
        Ensure lowering SO_RCVBUF on an established connection does
        NOT shrink the advertised-window cap — a receiver must not
        retract the window's right edge.

        Reference: RFC 9293 §3.8.6.2.1 (a receiver SHOULD NOT shrink
        the window / retract the right edge).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)

        # 32768 < the 65535 default cap — a shrink request.
        session._socket.setsockopt(SOL_SOCKET, SO_RCVBUF, 32768)

        self.assertEqual(
            session.rcv_wnd_max,
            SOCKET__SO_RCVBUF__DEFAULT,
            msg="Lowering SO_RCVBUF mid-connection must not shrink the advertised-window cap.",
        )
