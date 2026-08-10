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
This module contains integration tests for the RFC 9293 §3.9.1
ABORT user/TCP interface call: 'TcpSocket.abort()' / 'TcpSession.
abort()' tears down the connection without graceful close.

Reference RFC:
    RFC 9293 §3.9.1   User/TCP Interface (ABORT)

pytcp/tests/integration/protocols/tcp/test__tcp__session__abort_api.py

ver 3.0.10
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000
PEER__WIN: int = 64240
PEER__MSS: int = 1460


class TestTcpAbortApi(TcpTestCase):
    """
    Integration tests for 'TcpSocket.abort()' per RFC 9293 §3.9.1.
    """

    def test__abort__in_established_emits_rst_and_transitions_to_closed(self) -> None:
        """
        Ensure ABORT in ESTABLISHED emits a RST + ACK at
        SND.NXT / RCV.NXT, transitions the FSM to CLOSED, and
        releases blocked recv() / connect() callers.

        Reference: RFC 9293 §3.9.1 (ABORT user call).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)

        before = len(self._frames_tx)
        sock.abort()
        self._advance(ms=1)
        tx = list(self._frames_tx[before:])
        all_tx = [self._parse_tx(f) for f in tx]
        rsts = [p for p in all_tx if "RST" in p.flags]

        self.assertGreaterEqual(
            len(rsts),
            1,
            msg=(
                "RFC 9293 §3.9.1 ABORT in ESTABLISHED MUST emit a "
                f"RST. Got {len(rsts)} RST frame(s) out of "
                f"{len(all_tx)} total."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="ABORT MUST transition the session to CLOSED.",
        )

    def test__abort__in_fin_wait_1_emits_rst(self) -> None:
        """
        Ensure ABORT in FIN_WAIT_1 emits a RST as a synchronized
        state.

        Reference: RFC 9293 §3.9.1 (ABORT user call, synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        # Drive into FIN_WAIT_1.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        assert session.state is FsmState.FIN_WAIT_1

        before = len(self._frames_tx)
        sock.abort()
        self._advance(ms=1)
        tx = list(self._frames_tx[before:])
        rsts = [self._parse_tx(f) for f in tx if "RST" in self._parse_tx(f).flags]

        self.assertGreaterEqual(
            len(rsts),
            1,
            msg="ABORT in FIN_WAIT_1 MUST emit a RST.",
        )
        self.assertIs(session.state, FsmState.CLOSED)

    def test__abort__in_time_wait_does_not_emit_rst(self) -> None:
        """
        Ensure ABORT in TIME_WAIT tears down the TCB WITHOUT
        emitting a RST.

        Reference: RFC 9293 §3.9.1 (ABORT in TIME_WAIT does not signal peer).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
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
        assert session.state is FsmState.TIME_WAIT

        before = len(self._frames_tx)
        sock.abort()
        self._advance(ms=1)
        tx = list(self._frames_tx[before:])
        rsts = [self._parse_tx(f) for f in tx if "RST" in self._parse_tx(f).flags]

        self.assertEqual(
            len(rsts),
            0,
            msg=("RFC 9293 §3.9.1 ABORT in TIME_WAIT MUST NOT emit a " f"RST. Got {len(rsts)} RST frame(s)."),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="ABORT MUST transition TIME_WAIT to CLOSED.",
        )

    def test__abort__on_fresh_socket_is_noop(self) -> None:
        """
        Ensure abort() on a TcpSocket with no associated session
        is a no-op (no exception, no TX).

        Reference: RFC 9293 §3.9.1 (ABORT on CLOSED endpoint).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        sock.abort()  # MUST NOT raise

        self.assertIsNone(
            sock.tcp_session,
            msg="No session should be created by abort() on a fresh socket.",
        )

    def test__abort__in_close_wait_emits_rst(self) -> None:
        """
        Ensure ABORT in CLOSE_WAIT (synchronized state) emits a
        RST. Pins the per-state RST gate.

        Reference: RFC 9293 §3.9.1 (ABORT user call, synchronized states).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        # Drive into CLOSE_WAIT: peer FIN.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        assert session.state is FsmState.CLOSE_WAIT

        before = len(self._frames_tx)
        sock.abort()
        self._advance(ms=1)
        tx = list(self._frames_tx[before:])
        rsts = [self._parse_tx(f) for f in tx if "RST" in self._parse_tx(f).flags]

        self.assertGreaterEqual(
            len(rsts),
            1,
            msg="ABORT in CLOSE_WAIT MUST emit a RST (synchronized state).",
        )
        self.assertIs(session.state, FsmState.CLOSED)

    def test__abort__in_syn_sent_does_not_emit_rst(self) -> None:
        """
        Ensure ABORT in SYN_SENT (unsynchronized state) tears
        down the TCB WITHOUT emitting a RST.

        Reference: RFC 9293 §3.9.1 (ABORT in unsynchronized states).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        sock = session._socket
        assert isinstance(sock, TcpSocket)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        assert session.state is FsmState.SYN_SENT

        before = len(self._frames_tx)
        sock.abort()
        self._advance(ms=1)
        tx = list(self._frames_tx[before:])
        rsts = [self._parse_tx(f) for f in tx if "RST" in self._parse_tx(f).flags]

        self.assertEqual(
            len(rsts),
            0,
            msg=(
                "RFC 9293 §3.9.1 ABORT in SYN_SENT MUST NOT emit a "
                f"RST (unsynchronized state). Got {len(rsts)} RST(s)."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="ABORT in SYN_SENT MUST transition to CLOSED.",
        )

    def test__abort__sets_connection_error_to_canceled(self) -> None:
        """
        Ensure ABORT marks '_connection_error = CANCELED' so
        any blocked recv() / connect() caller observes the
        cancellation via the standard error-propagation path.

        Reference: RFC 9293 §3.9.1 (ABORT signals "connection reset" to user).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)

        sock.abort()

        self.assertIs(
            session._connection_error,
            ConnError.CANCELED,
            msg=(
                "ABORT MUST set '_connection_error' to CANCELED so "
                f"blocked callers see the abort. Got {session._connection_error!r}."
            ),
        )

    def test__abort__releases_blocked_rx_buffer_event(self) -> None:
        """
        Ensure ABORT sets '_event__rx_buffer' so a thread blocked
        in recv() unblocks and the FSM-state check yields the
        connection-cancelled error.

        Reference: RFC 9293 §3.9.1 (ABORT releases pending RECEIVE).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        # Pre-clear the event to verify abort() sets it.
        session._event__rx_buffer.clear()

        sock.abort()

        self.assertTrue(
            session._event__rx_buffer.is_set(),
            msg=("ABORT MUST set '_event__rx_buffer' so blocked recv() " "callers unblock immediately."),
        )

    def test__abort__discards_pending_tx_buffer_data(self) -> None:
        """
        Ensure ABORT does NOT retransmit pending TX buffer data
        post-RST. The connection is gone; the application's
        unsent bytes are discarded per the "abandon all pending
        SENDs" semantics.

        Reference: RFC 9293 §3.9.1 (ABORT abandons pending SENDs).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        # Queue some bytes that haven't been sent yet.
        session.send(data=b"unsent payload")

        before = len(self._frames_tx)
        sock.abort()
        # Advance enough to fire any retransmit timers.
        self._advance(ms=2000)
        tx_post_abort = list(self._frames_tx[before:])
        data_segments = [self._parse_tx(f) for f in tx_post_abort if self._parse_tx(f).payload]

        self.assertEqual(
            len(data_segments),
            0,
            msg=(
                "RFC 9293 §3.9.1 ABORT MUST discard pending SENDs; the "
                "TX buffer's unsent payload MUST NOT be transmitted "
                f"post-RST. Got {len(data_segments)} data segment(s) "
                "after abort."
            ),
        )
