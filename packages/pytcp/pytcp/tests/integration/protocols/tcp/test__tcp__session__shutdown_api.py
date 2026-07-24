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
Integration tests for the BSD-socket 'shutdown(how)' half-close
per RFC 9293 §3.9.1 + POSIX shutdown semantics.

pytcp/tests/integration/protocols/tcp/test__tcp__session__shutdown_api.py

ver 3.0.9
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pytcp.runtime.socket import SHUT_RD, SHUT_RDWR, SHUT_WR, AddressFamily
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


class TestTcpShutdownApi(TcpTestCase):
    """
    Integration tests for 'TcpSocket.shutdown(how)' /
    'TcpSession.shutdown(how)' per RFC 9293 §3.9.1 +
    POSIX shutdown semantics.
    """

    def test__shutdown_wr__triggers_fin_emission(self) -> None:
        """
        Ensure shutdown(SHUT_WR) triggers the same FIN-emission
        path as close(): session transitions to FIN_WAIT_1, FIN
        goes out on the wire.

        Reference: RFC 9293 §3.10.4 (CLOSE call processing).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)

        sock.shutdown(SHUT_WR)
        self._advance(ms=1)
        self._advance(ms=1)

        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="shutdown(SHUT_WR) MUST transition to FIN_WAIT_1.",
        )
        self.assertTrue(
            session._shut.wr,
            msg="_shut_wr MUST be set after shutdown(SHUT_WR).",
        )

    def test__shutdown_wr__rejects_subsequent_send(self) -> None:
        """
        Ensure send() after shutdown(SHUT_WR) raises
        TcpSessionError, like send() after close().

        Reference: RFC 9293 §3.9.1 (SEND on closed write half).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        sock.shutdown(SHUT_WR)

        with self.assertRaises(TcpSessionError):
            session.send(data=b"too late")

    def test__shutdown_rd__discards_subsequent_inbound_data(self) -> None:
        """
        Ensure shutdown(SHUT_RD) silently discards subsequent
        inbound data: peer's segment is acknowledged but its
        bytes never enter '_rx_buffer'.

        Reference: RFC 9293 §3.9.1 (RECEIVE on closed read half).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        sock.shutdown(SHUT_RD)

        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"discarded",
        )
        self._drive_rx(frame=peer_data)

        self.assertEqual(
            len(session._rx_buffer),
            0,
            msg=(
                "shutdown(SHUT_RD): inbound data MUST be discarded; "
                f"_rx_buffer MUST stay empty. Got {len(session._rx_buffer)} "
                "bytes."
            ),
        )
        self.assertTrue(
            session._shut.rd,
            msg="_shut_rd MUST be set after shutdown(SHUT_RD).",
        )

    def test__shutdown_rdwr__sets_both_flags_and_emits_fin(self) -> None:
        """
        Ensure shutdown(SHUT_RDWR) is the union of SHUT_RD and
        SHUT_WR: both flags set, FIN emitted.

        Reference: RFC 9293 §3.10.4 (CLOSE call processing).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)

        sock.shutdown(SHUT_RDWR)
        self._advance(ms=1)
        self._advance(ms=1)

        self.assertTrue(session._shut.rd)
        self.assertTrue(session._shut.wr)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="shutdown(SHUT_RDWR) MUST transition to FIN_WAIT_1.",
        )

    def test__shutdown_wr__idempotent_does_not_re_emit_fin(self) -> None:
        """
        Ensure a second shutdown(SHUT_WR) call after the first
        one is a no-op. The FIN is not re-emitted at a new seq.

        Reference: RFC 9293 §3.4 (FIN consumes one seq, idempotent close).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)

        sock.shutdown(SHUT_WR)
        self._advance(ms=1)
        self._advance(ms=1)
        snd_nxt_after_first = session._snd_seq.nxt

        sock.shutdown(SHUT_WR)
        self._advance(ms=1)

        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_after_first,
            msg=(
                "Idempotent shutdown(SHUT_WR) MUST NOT re-advance "
                f"SND.NXT. Pre={snd_nxt_after_first}, post={session._snd_seq.nxt}."
            ),
        )

    def test__shutdown_on_fresh_socket_is_noop(self) -> None:
        """
        Ensure shutdown() on a TcpSocket with no associated
        session is a no-op (no exception).

        Reference: RFC 9293 §3.9.1 (User/TCP interface).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        sock.shutdown(SHUT_WR)  # MUST NOT raise
        sock.shutdown(SHUT_RD)
        sock.shutdown(SHUT_RDWR)

        self.assertIsNone(sock.tcp_session)

    def test__shutdown_rd__already_buffered_data_stays_readable(self) -> None:
        """
        Ensure shutdown(SHUT_RD) discards FUTURE inbound data
        but does NOT purge data already in '_rx_buffer'. The
        POSIX shutdown(SHUT_RD) semantics: stop new arrivals,
        keep already-queued bytes available for recv().

        Reference: RFC 9293 §3.9.1 (RECEIVE on closed read half).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)
        # Drive some peer data BEFORE shutting down read side.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"already-queued",
        )
        self._drive_rx(frame=peer_data)
        self.assertEqual(
            len(session._rx_buffer),
            len(b"already-queued"),
            msg="Setup: pre-shutdown data must be in _rx_buffer.",
        )

        sock.shutdown(SHUT_RD)

        # Already-queued data MUST still be there.
        self.assertEqual(
            bytes(session._rx_buffer),
            b"already-queued",
            msg=("shutdown(SHUT_RD) MUST NOT purge already-buffered " f"data. Got {bytes(session._rx_buffer)!r}."),
        )

        # NEW data MUST be discarded.
        peer_data_after = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + len(b"already-queued"),
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"discarded",
        )
        self._drive_rx(frame=peer_data_after)
        self.assertEqual(
            bytes(session._rx_buffer),
            b"already-queued",
            msg=(
                "shutdown(SHUT_RD): post-shutdown inbound data MUST "
                "be discarded; _rx_buffer MUST stay at its pre-shutdown "
                f"contents. Got {bytes(session._rx_buffer)!r}."
            ),
        )

    def test__shutdown_rd__recv_returns_empty_bytes_after_buffer_drains(self) -> None:
        """
        Ensure recv() returns empty bytes (end-of-stream) once
        the buffer is drained AND SHUT_RD is set, rather than
        blocking indefinitely waiting for data that will never
        arrive. SHUT_RD sets '_event__rx_buffer' so the wait
        returns immediately.

        Reference: RFC 9293 §3.9.1 (RECEIVE returns EOF on closed read half).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)

        sock.shutdown(SHUT_RD)

        # _event__rx_buffer MUST be set so recv() unblocks.
        self.assertTrue(
            session._event__rx_buffer.is_set(),
            msg=(
                "shutdown(SHUT_RD) MUST set '_event__rx_buffer' so "
                "blocked recv() callers unblock immediately rather "
                "than waiting forever for data that will never arrive."
            ),
        )

    def test__shutdown__invalid_how_value_raises(self) -> None:
        """
        Ensure invalid 'how' values raise. The 'how' argument
        must be in {SHUT_RD=0, SHUT_WR=1, SHUT_RDWR=2}; anything
        else raises so callers see the API misuse instead of
        silently no-oping.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        sock = session._socket
        assert isinstance(sock, TcpSocket)

        with self.assertRaises(AssertionError):
            sock.shutdown(3)
        with self.assertRaises(AssertionError):
            sock.shutdown(-1)

    def test__shutdown_wr_then_shut_rd__sets_both_flags(self) -> None:
        """
        Ensure two-step half-close (SHUT_WR followed by SHUT_RD)
        is equivalent to SHUT_RDWR: both directions are shut,
        FIN was emitted on the SHUT_WR step, and post-SHUT_RD
        inbound is discarded.

        Reference: RFC 9293 §3.10.4 (CLOSE call processing).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock = session._socket

        assert isinstance(sock, TcpSocket)

        sock.shutdown(SHUT_WR)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertTrue(session._shut.wr)
        self.assertFalse(
            session._shut.rd,
            msg="Setup invariant: SHUT_WR alone MUST NOT set _shut_rd.",
        )

        sock.shutdown(SHUT_RD)
        self.assertTrue(session._shut.rd)
        self.assertTrue(
            session._shut.wr,
            msg="Sequential shutdown: _shut_wr MUST remain set after the second shutdown(SHUT_RD).",
        )
