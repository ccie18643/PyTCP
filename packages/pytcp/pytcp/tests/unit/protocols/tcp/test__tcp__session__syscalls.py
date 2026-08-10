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


"""
This module contains tests for the 'TcpSession' LISTEN / CONNECT /
SEND / RECEIVE / CLOSE syscall handlers.

pytcp/tests/unit/protocols/tcp/test__tcp__session__syscalls.py

ver 3.0.10
"""

from types import SimpleNamespace
from typing import override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pytcp.runtime.socket.socket_table import SocketTable


class _TcpSessionSyscallFixture(TestCase):
    """
    Shared fixture for the syscall-handler tests. Patches the timer,
    interface MTU, and logging, and provides a factory that returns a
    constructed session ready to exercise syscalls.
    """

    @override
    def setUp(self) -> None:
        """
        Stub every stack dependency that the session touches.
        """

        self._timer = SimpleNamespace(
            call_periodic=MagicMock(),
            cancel=MagicMock(),
            call_later=MagicMock(),
            now_ms=0,
        )
        self._timer_patch = patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.timer",
            self._timer,
            create=True,
        )
        self._timer_patch.start()

        self._mtu_patch = patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.egress_interface_mtu",
            return_value=1500,
        )
        self._mtu_patch.start()

        self._sockets = SocketTable()
        self._sockets_patch = patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.sockets",
            self._sockets,
        )
        self._sockets_patch.start()

        self._log_patch = patch("pytcp.protocols.tcp.session.tcp__session.log")
        self._log_patch.start()

    @override
    def tearDown(self) -> None:
        """
        Remove the stack patches.
        """

        self._timer_patch.stop()
        self._mtu_patch.stop()
        self._sockets_patch.stop()
        self._log_patch.stop()

    def _make_session(self) -> TcpSession:
        """
        Build a canonical IPv4 'TcpSession' against a MagicMock socket.
        """

        mock_socket = MagicMock()
        # rcv_wnd_max derives from the socket's SO_RCVBUF at session
        # construction; give the mock an int so window arithmetic works.
        mock_socket._effective_rcvbuf.return_value = 65535
        session = TcpSession(
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            remote_ip_address=Ip4Address("10.0.0.2"),
            remote_port=44444,
            socket=mock_socket,
        )
        return session


class TestTcpSessionListenSyscall(_TcpSessionSyscallFixture):
    """
    The 'TcpSession.listen()' syscall tests.
    """

    def test__tcp_session__listen_transitions_to_listen(self) -> None:
        """
        Ensure LISTEN from CLOSED transitions the FSM to 'LISTEN'.
        The canonical passive-open path for servers.

        Reference: RFC 9293 §3.10.1 (OPEN call processing, passive).
        """

        session = self._make_session()
        session.listen()
        self.assertIs(
            session.state,
            FsmState.LISTEN,
            msg="LISTEN from CLOSED must transition to FsmState.LISTEN.",
        )

    def test__tcp_session__listen_invokes_tcp_fsm(self) -> None:
        """
        Ensure listen() routes through 'tcp_fsm' rather than mutating
        '_state' directly — the FSM dispatch is the single source of
        truth for state transitions.

        Reference: RFC 9293 §3.10.1 (OPEN call processing).
        """

        session = self._make_session()
        with patch.object(session, "tcp_fsm") as mock_fsm:
            session.listen()
        mock_fsm.assert_called_once_with(syscall=SysCall.LISTEN)


class TestTcpSessionConnectSyscall(_TcpSessionSyscallFixture):
    """
    The 'TcpSession.connect()' syscall tests.
    """

    def test__tcp_session__connect_raises_on_refused(self) -> None:
        """
        Ensure connect() raises 'TcpSessionError("Connection refused")'
        when the FSM ends up in a non-ESTABLISHED state with the
        'REFUSED' error code (peer sent RST).

        Reference: RFC 9293 §3.10.7.3 (RST in SYN-SENT triggers connection refused).
        """

        session = self._make_session()
        with patch.object(session, "tcp_fsm") as mock_fsm:

            def fsm_side_effect(**_: object) -> None:
                """
                Simulate the FSM: acknowledge the CONNECT syscall by
                signaling the connect semaphore with the REFUSED error
                code, leaving the session in CLOSED.
                """

                session._connection_error = ConnError.REFUSED
                session._event__connect.release()

            mock_fsm.side_effect = fsm_side_effect

            with self.assertRaises(TcpSessionError) as context:
                session.connect()

        self.assertEqual(
            str(context.exception),
            "Connection refused",
            msg="connect() must raise TcpSessionError('Connection refused') on ConnError.REFUSED.",
        )

    def test__tcp_session__connect_raises_on_timeout(self) -> None:
        """
        Ensure connect() raises 'TcpSessionError("Connection timeout")'
        when the FSM ends up non-ESTABLISHED with the 'TIMEOUT' error
        code (retransmit budget exhausted).

        Reference: RFC 1122 §4.2.3.5 (R2 abort floor).
        Reference: RFC 9293 §3.10.1 (OPEN call processing).
        """

        session = self._make_session()
        with patch.object(session, "tcp_fsm") as mock_fsm:

            def fsm_side_effect(**_: object) -> None:
                """
                Simulate the FSM: acknowledge the CONNECT syscall by
                signaling the connect semaphore with the TIMEOUT error
                code, leaving the session in CLOSED.
                """

                session._connection_error = ConnError.TIMEOUT
                session._event__connect.release()

            mock_fsm.side_effect = fsm_side_effect

            with self.assertRaises(TcpSessionError) as context:
                session.connect()

        self.assertEqual(
            str(context.exception),
            "Connection timeout",
            msg="connect() must raise TcpSessionError('Connection timeout') on ConnError.TIMEOUT.",
        )

    def test__tcp_session__connect_returns_on_established(self) -> None:
        """
        Ensure connect() returns cleanly when the FSM reaches
        'ESTABLISHED' before the connect semaphore is signaled.

        Reference: RFC 9293 §3.10.1 (OPEN call returns on ESTABLISHED).
        """

        session = self._make_session()
        with patch.object(session, "tcp_fsm") as mock_fsm:

            def fsm_side_effect(**_: object) -> None:
                """
                Simulate a successful three-way handshake by flipping
                the session into ESTABLISHED and releasing the
                connect semaphore.
                """

                session._state = FsmState.ESTABLISHED
                session._event__connect.release()

            mock_fsm.side_effect = fsm_side_effect
            session.connect()


class TestTcpSessionSendSyscall(_TcpSessionSyscallFixture):
    """
    The 'TcpSession.send()' syscall tests.
    """

    def test__tcp_session__send_appends_to_tx_buffer_in_established(self) -> None:
        """
        Ensure send() in 'ESTABLISHED' appends the data to the TX
        buffer and returns 'len(data)' unchanged.

        Reference: RFC 9293 §3.9.1 (SEND call from ESTABLISHED).
        """

        session = self._make_session()
        session._state = FsmState.ESTABLISHED

        result = session.send(data=b"hello")

        self.assertEqual(
            result,
            5,
            msg="send() must return the length of the supplied data.",
        )
        self.assertEqual(
            bytes(session._tx.buffer),
            b"hello",
            msg="send() must append the data to _tx_buffer.",
        )

    def test__tcp_session__send_appends_to_tx_buffer_in_close_wait(self) -> None:
        """
        Ensure send() also works in 'CLOSE_WAIT' — the local half of
        the connection is still open there.

        Reference: RFC 9293 §3.9.1 (SEND call from CLOSE-WAIT).
        """

        session = self._make_session()
        session._state = FsmState.CLOSE_WAIT

        result = session.send(data=b"world")

        self.assertEqual(
            result,
            5,
            msg="send() must return len(data) in CLOSE_WAIT.",
        )
        self.assertEqual(
            bytes(session._tx.buffer),
            b"world",
            msg="send() must append the data to _tx_buffer in CLOSE_WAIT.",
        )

    def test__tcp_session__send_raises_outside_established_or_close_wait(self) -> None:
        """
        Ensure send() raises 'TcpSessionError' when the session is not
        in 'ESTABLISHED' or 'CLOSE_WAIT'. BSD stream-socket semantics
        do not allow writes once the local half is closed.

        Reference: RFC 9293 §3.9.1 (SEND in non-synchronized states returns error).
        """

        session = self._make_session()
        session._state = FsmState.CLOSED

        with self.assertRaises(TcpSessionError):
            session.send(data=b"data")


class TestTcpSessionReceiveSyscall(_TcpSessionSyscallFixture):
    """
    The 'TcpSession.receive()' syscall tests.
    """

    def test__tcp_session__receive_returns_all_buffered_bytes(self) -> None:
        """
        Ensure receive() with no byte_count drains the entire RX
        buffer and returns it as 'bytes'.

        Reference: RFC 9293 §3.9.1 (RECEIVE call).
        """

        session = self._make_session()
        session._rx_buffer.extend(b"hello world")
        session._event__rx_buffer.set()

        self.assertEqual(
            session.receive(),
            b"hello world",
            msg="receive() with no byte_count must return the entire RX buffer.",
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg="receive() must drain the RX buffer after reading.",
        )

    def test__tcp_session__receive_honors_byte_count(self) -> None:
        """
        Ensure receive(byte_count=N) returns at most N bytes and
        leaves the rest in the buffer for the next call.

        Reference: RFC 9293 §3.9.1 (RECEIVE byte-count parameter).
        """

        session = self._make_session()
        session._rx_buffer.extend(b"hello world")
        session._event__rx_buffer.set()

        first = session.receive(byte_count=5)
        self.assertEqual(
            first,
            b"hello",
            msg="receive(byte_count=5) must return the first 5 bytes.",
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            b" world",
            msg="receive(byte_count=5) must leave the remaining bytes buffered.",
        )

    def test__tcp_session__receive_empty_buffer_in_close_wait_returns_empty(self) -> None:
        """
        Ensure receive() on an empty buffer while in 'CLOSE_WAIT'
        returns an empty bytes object to signal remote-end EOF — the
        BSD 'recv returned 0' convention.

        Reference: RFC 9293 §3.9.1 (RECEIVE on closed remote half).
        """

        session = self._make_session()
        session._state = FsmState.CLOSE_WAIT
        session._event__rx_buffer.set()

        self.assertEqual(
            session.receive(),
            b"",
            msg="receive() on an empty buffer in CLOSE_WAIT must signal EOF with an empty bytes object.",
        )

    def test__tcp_session__receive_timeout_raises(self) -> None:
        """
        Ensure receive() with a finite timeout raises 'TimeoutError'
        when no data arrives in the window.

        Reference: RFC 9293 §3.9.1 (RECEIVE timeout signalling).
        """

        session = self._make_session()
        with self.assertRaises(TimeoutError):
            session.receive(timeout=0.01)

    def test__tcp_session__receive_leaves_event_set_when_buffer_nonempty(self) -> None:
        """
        Ensure receive() leaves the '_event__rx_buffer' event set
        when the buffer still has data after the read, so the next
        call does not block unnecessarily.

        Reference: RFC 9293 §3.9.1 (RECEIVE call delivers buffered data).
        """

        session = self._make_session()
        session._rx_buffer.extend(b"hello world")
        session._event__rx_buffer.set()

        session.receive(byte_count=5)

        # Second receive must not block because the event is still set.
        self.assertEqual(
            session.receive(byte_count=6, timeout=0.01),
            b" world",
            msg="receive() must leave the rx event set when leftover data remains.",
        )

    def test__tcp_session__rx_buffer_event_does_not_over_release(self) -> None:
        """
        Ensure the rx-buffer signal is not over-released when an FSM
        handler signals 'data available' on top of '_enqueue_rx_buffer'
        already having signalled. Over-release would leave a phantom
        permit on the rx event so a subsequent 'receive()' on an empty
        buffer would 'succeed' and return b"" -- masking the no-data
        condition as a legitimate remote-end EOF.

        Reference: RFC 9293 §3.9.1 (RECEIVE EOF semantics).
        """

        session = self._make_session()
        session._state = FsmState.ESTABLISHED  # so empty buffer is not interpreted as EOF

        # Data arrives via _enqueue_rx_buffer (signals once on empty -> has-data).
        session._enqueue_rx_buffer(memoryview(b"data"))
        # FSM handler also signals (mirrors the .release() / .set() on lines 663,
        # 1121, 1136 of tcp__session.py).
        session._event__rx_buffer.set()

        # Drain the legitimate data.
        self.assertEqual(
            session.receive(),
            b"data",
            msg="receive() must drain the buffer that _enqueue_rx_buffer wrote.",
        )

        # Buffer is now empty and state is ESTABLISHED. A correctly-handled
        # rx event must NOT have a phantom permit; receive() must time out.
        with self.assertRaises(
            TimeoutError,
            msg="receive() on an empty buffer in ESTABLISHED must time out, not return phantom EOF.",
        ):
            session.receive(timeout=0.01)


class TestTcpSessionCloseSyscall(_TcpSessionSyscallFixture):
    """
    The 'TcpSession.close()' syscall tests.
    """

    def test__tcp_session__close_routes_via_tcp_fsm(self) -> None:
        """
        Ensure close() routes through 'tcp_fsm' with 'SysCall.CLOSE'
        rather than mutating the state directly.

        Reference: RFC 9293 §3.10.4 (CLOSE call processing).
        """

        session = self._make_session()
        with patch.object(session, "tcp_fsm") as mock_fsm:
            session.close()
        mock_fsm.assert_called_once_with(syscall=SysCall.CLOSE)
