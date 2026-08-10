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
Integration tests for SO_SNDBUF bounding the TCP send buffer
(Track B). A send() that would overflow the SO_SNDBUF-derived
bound blocks (up to SO_SNDTIMEO), does a partial write, or fails
with EAGAIN, mirroring Linux 'tcp_sendmsg' send-buffer
backpressure (RFC 9293 §3.9 SEND). Send-buffer occupancy is
measured directly from the session TX buffer; the cum-ACK drain
and the close path wake a blocked writer.

pytcp/tests/integration/protocols/tcp/test__tcp__session__so_sndbuf.py

ver 3.0.10
"""

import threading

from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pytcp.runtime.socket import (
    SO_SNDBUF,
    SO_SNDTIMEO,
    SOCKET__SO_SNDBUF__DEFAULT,
    SOL_SOCKET,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL_PORT = 12345
_REMOTE_PORT = 80


class TestTcpSessionSoSndbuf(TcpTestCase):
    """
    The SO_SNDBUF send-buffer bound / partial-write tests.
    """

    def test__so_sndbuf__partial_write_when_buffer_nearly_full(self) -> None:
        """
        Ensure a send() that would overflow the SO_SNDBUF bound
        accepts only the bytes that fit and returns that short count,
        so the application re-sends the remainder (TCP byte-stream
        partial-write semantics).

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux socket(7) SO_SNDBUF (send-buffer size bounds
        queued data).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        session._socket.setsockopt(SOL_SOCKET, SO_SNDBUF, 100)

        # Fill 80 of the 100-byte bound (buffer was empty -> accepted).
        self.assertEqual(
            session.send(data=b"A" * 80),
            80,
            msg="A send into an empty buffer must accept the whole write.",
        )

        # 50 more bytes: only the 20 that fit under the bound are taken.
        self.assertEqual(
            session.send(data=b"B" * 50),
            20,
            msg="A send that overflows SO_SNDBUF must accept only the fitting prefix.",
        )

    def test__so_sndbuf__nonblocking_full_buffer_raises_eagain(self) -> None:
        """
        Ensure a non-blocking send() against a send buffer already at
        the SO_SNDBUF bound raises BlockingIOError(EAGAIN) rather than
        queueing more data.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux socket(7) SO_SNDBUF (non-blocking send returns
        EAGAIN when the send buffer is full).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        session._socket.setsockopt(SOL_SOCKET, SO_SNDBUF, 100)
        session._socket.setblocking(False)

        # Fill the buffer to the bound, then attempt to overflow it.
        session.send(data=b"A" * 100)

        with self.assertRaises(BlockingIOError) as error:
            session.send(data=b"B" * 10)

        self.assertEqual(
            error.exception.errno,
            11,
            msg="A full-buffer non-blocking send must raise EAGAIN (errno 11).",
        )

    def test__so_sndbuf__single_write_larger_than_bound_accepted_when_empty(self) -> None:
        """
        Ensure a single write larger than SO_SNDBUF is accepted whole
        when the send buffer is empty, so a large send is never
        wedged by a small buffer (matching the datagram
        'nothing-outstanding-is-always-allowed' rule).

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: Linux socket(7) SO_SNDBUF (a write larger than the
        buffer still proceeds when nothing is queued).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        session._socket.setsockopt(SOL_SOCKET, SO_SNDBUF, 100)

        self.assertEqual(
            session.send(data=b"A" * 250),
            250,
            msg="A single write larger than SO_SNDBUF must be accepted whole into an empty buffer.",
        )

    def test__so_sndbuf__getsockopt_reports_effective_value(self) -> None:
        """
        Ensure getsockopt(SO_SNDBUF) on a TCP socket reports the
        effective send-buffer bound (the value set, else the default),
        mirroring the SO_RCVBUF getsockopt parity.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        Reference: Linux socket(7) SO_SNDBUF (getsockopt reports the
        buffer size).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)

        self.assertEqual(
            session._socket.getsockopt(SOL_SOCKET, SO_SNDBUF),
            SOCKET__SO_SNDBUF__DEFAULT,
            msg="getsockopt(SO_SNDBUF) must report the default when unset.",
        )

        session._socket.setsockopt(SOL_SOCKET, SO_SNDBUF, 4096)

        self.assertEqual(
            session._socket.getsockopt(SOL_SOCKET, SO_SNDBUF),
            4096,
            msg="getsockopt(SO_SNDBUF) must report the value the application set.",
        )


class TestTcpSessionSoSndbufBlocking(TcpTestCase):
    """
    The SO_SNDBUF blocking-writer wake tests. A writer blocked on a
    full send buffer is woken by the cum-ACK drain (which frees
    send-buffer space) and by the close path.
    """

    def _fill_and_block_writer(self, session: TcpSession) -> tuple[threading.Thread, dict[str, object]]:
        """
        Fill the 100-byte send buffer, arm a SO_SNDTIMEO backstop so a
        wiring bug cannot wedge the suite, then start a writer thread
        that blocks trying to queue 50 more bytes. Returns the thread
        and a dict the thread stores its outcome into. Asserts the
        writer is actually parked before returning.
        """

        # Fill the buffer to the bound and transmit it so a later ACK
        # can drain it.
        session.send(data=b"A" * 100)
        self._advance(ms=1)
        # Blocking mode with a finite SO_SNDTIMEO: the writer blocks on
        # a full buffer but a broken wake cannot hang the suite.
        session._socket.setsockopt(SOL_SOCKET, SO_SNDTIMEO, 5.0)

        outcome: dict[str, object] = {}

        def _writer() -> None:
            try:
                outcome["accepted"] = session.send(data=b"B" * 50)
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                outcome["error"] = exc

        writer = threading.Thread(target=_writer, name="sndbuf-writer")
        writer.start()
        self.addCleanup(writer.join, 6.0)
        # The writer must be blocked on the full buffer: a quick join
        # returns only if it wrongly completed (no backpressure).
        writer.join(timeout=0.3)
        self.assertTrue(
            writer.is_alive(),
            msg="The writer must block on a send buffer already at the SO_SNDBUF bound.",
        )
        return writer, outcome

    def test__so_sndbuf__ack_drain_wakes_blocked_writer(self) -> None:
        """
        Ensure a writer blocked on a full send buffer is woken when a
        cumulative ACK drains the buffer, and then queues its data.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: RFC 9293 §3.4 (cumulative acknowledgment frees
        send-buffer space).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        session._socket.setsockopt(SOL_SOCKET, SO_SNDBUF, 100)

        writer, outcome = self._fill_and_block_writer(session)

        # Peer ACKs all 100 transmitted bytes -> the drain frees the
        # buffer and wakes the blocked writer.
        peer_ack = build_tcp4(
            sport=_REMOTE_PORT,
            dport=_LOCAL_PORT,
            seq=5001,
            ack=1000 + 1 + 100,
            flags=("ACK",),
            win=64240,
        )
        self._drive_rx(frame=peer_ack)

        writer.join(timeout=6.0)
        self.assertFalse(
            writer.is_alive(),
            msg="The ACK drain must wake the blocked writer.",
        )
        self.assertEqual(
            outcome.get("accepted"),
            50,
            msg="The woken writer must queue its 50 bytes into the freed buffer.",
        )

    def test__so_sndbuf__close_wakes_blocked_writer(self) -> None:
        """
        Ensure a writer blocked on a full send buffer is woken when
        the session is closed, and observes the closing state with an
        error rather than hanging.

        Reference: RFC 9293 §3.9 (SEND — send-buffer flow control).
        Reference: RFC 9293 §3.10.6 (SEND after CLOSE is an error).
        """

        session = self._drive_handshake_to_established(iss=1000, peer_iss=5000)
        session._socket.setsockopt(SOL_SOCKET, SO_SNDBUF, 100)

        writer, outcome = self._fill_and_block_writer(session)

        session.close()

        writer.join(timeout=6.0)
        self.assertFalse(
            writer.is_alive(),
            msg="Closing the session must wake the blocked writer.",
        )
        self.assertIsInstance(
            outcome.get("error"),
            TcpSessionError,
            msg="A writer woken by close() must fail with a closing error.",
        )
