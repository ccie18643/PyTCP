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
This module contains integration tests for the SO_LINGER close-path
behaviour on a TCP socket: the three-way branch keyed on the socket's
'(l_onoff, l_linger)' linger pair — graceful FIN close (linger off),
lingering wait-for-close (l_onoff=1, l_linger>0), and abortive RST
close (l_onoff=1, l_linger=0).

pytcp/tests/integration/protocols/tcp/test__tcp__session__so_linger.py

ver 3.0.10
"""

import struct
from unittest.mock import patch

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.socket import SO_LINGER, SOL_SOCKET
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000


class TestTcpSoLinger(TcpTestCase):
    """
    Integration tests for the SO_LINGER close-path behaviour.
    """

    def test__so_linger__zero_linger_aborts_with_rst(self) -> None:
        """
        Ensure close() on an ESTABLISHED socket carrying SO_LINGER
        '{l_onoff=1, l_linger=0}' performs an abortive close — it emits
        a RST instead of the graceful FIN, the well-known
        "SO_LINGER zero -> RST" idiom.

        Reference: socket(7) SO_LINGER (l_linger=0 abortive close).
        Reference: RFC 9293 §3.10.7.4 (RST on abort).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        sock = session._socket
        assert isinstance(sock, TcpSocket)

        sock.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("@ii", 1, 0))

        before = len(self._frames_tx)
        sock.close()
        self._advance(ms=1)
        tx = [self._parse_tx(f) for f in self._frames_tx[before:]]
        rsts = [p for p in tx if "RST" in p.flags]
        fins = [p for p in tx if "FIN" in p.flags]

        self.assertGreaterEqual(
            len(rsts),
            1,
            msg="SO_LINGER {1, 0} close MUST emit a RST (abortive close).",
        )
        self.assertEqual(
            len(fins),
            0,
            msg="SO_LINGER {1, 0} close MUST NOT emit a graceful FIN.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="SO_LINGER {1, 0} close MUST leave the session CLOSED.",
        )

    def test__so_linger__disabled_closes_gracefully_with_fin(self) -> None:
        """
        Ensure close() on an ESTABLISHED socket with SO_LINGER disabled
        '{l_onoff=0}' performs the default graceful close — it emits a
        FIN and no RST. Regression guard against the abortive branch
        firing on the default path.

        Reference: socket(7) SO_LINGER (linger off -> graceful close).
        Reference: RFC 9293 §3.6 (closing a connection).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        sock = session._socket
        assert isinstance(sock, TcpSocket)

        sock.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("@ii", 0, 0))

        before = len(self._frames_tx)
        sock.close()
        # The FIN fires from the FIN_WAIT_1 handler a tick after the
        # ESTABLISHED -> FIN_WAIT_1 transition; flush two ticks.
        self._advance(ms=1)
        self._advance(ms=1)
        tx = [self._parse_tx(f) for f in self._frames_tx[before:]]
        rsts = [p for p in tx if "RST" in p.flags]
        fins = [p for p in tx if "FIN" in p.flags]

        self.assertGreaterEqual(
            len(fins),
            1,
            msg="SO_LINGER-disabled close MUST emit a graceful FIN.",
        )
        self.assertEqual(
            len(rsts),
            0,
            msg="SO_LINGER-disabled close MUST NOT emit a RST.",
        )

    def test__so_linger__positive_returns_when_close_signal_already_set(self) -> None:
        """
        Ensure close() on an ESTABLISHED socket carrying SO_LINGER
        '{l_onoff=1, l_linger>0}' takes the graceful FIN path and
        returns as soon as the session's close-complete signal is set,
        rather than aborting with a RST. Pins the lingering branch's
        wake-on-close behaviour.

        Reference: socket(7) SO_LINGER (l_linger>0 lingering close).
        Reference: RFC 9293 §3.6 (closing a connection).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        sock = session._socket
        assert isinstance(sock, TcpSocket)

        sock.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("@ii", 1, 30))

        # Pre-arm the close-complete signal so the lingering wait wakes
        # immediately instead of blocking for the full 30 s (in a live
        # stack the RX / timer threads set this on reaching CLOSED).
        session._event__closed.set()

        before = len(self._frames_tx)
        sock.close()  # MUST return promptly, not block on the deadline.
        self._advance(ms=1)
        self._advance(ms=1)
        tx = [self._parse_tx(f) for f in self._frames_tx[before:]]
        rsts = [p for p in tx if "RST" in p.flags]
        fins = [p for p in tx if "FIN" in p.flags]

        self.assertGreaterEqual(
            len(fins),
            1,
            msg="A lingering close MUST take the graceful FIN path.",
        )
        self.assertEqual(
            len(rsts),
            0,
            msg="A lingering close MUST NOT emit a RST.",
        )

    def test__so_linger__positive_returns_at_deadline_when_never_closed(self) -> None:
        """
        Ensure close() on an ESTABLISHED socket carrying SO_LINGER
        '{l_onoff=1, l_linger>0}' returns when the linger deadline
        elapses even though the session never reaches CLOSED (the peer
        never ACKs the FIN). The FIN is still emitted.

        Reference: socket(7) SO_LINGER (lingering close honours the timeout).
        Reference: RFC 9293 §3.6 (closing a connection).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        sock = session._socket
        assert isinstance(sock, TcpSocket)

        sock.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("@ii", 1, 30))

        # The close-complete signal is left unset (peer never ACKs).
        # A monotonic clock that leaps far forward on each read makes
        # the computed 'remaining' non-positive, so the lingering wait
        # short-circuits deterministically without a real sleep.
        clock = {"t": 1000.0}

        def _leaping_monotonic() -> float:
            clock["t"] += 1_000_000.0
            return clock["t"]

        before = len(self._frames_tx)
        with patch("pytcp.runtime.socket.tcp__socket.time.monotonic", side_effect=_leaping_monotonic):
            sock.close()  # MUST return at the (already-elapsed) deadline.
        self._advance(ms=1)
        self._advance(ms=1)
        tx = [self._parse_tx(f) for f in self._frames_tx[before:]]
        fins = [p for p in tx if "FIN" in p.flags]

        self.assertGreaterEqual(
            len(fins),
            1,
            msg="A lingering close that times out MUST still emit the graceful FIN.",
        )
