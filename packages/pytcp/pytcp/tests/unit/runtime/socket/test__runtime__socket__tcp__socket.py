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
This module contains tests for the 'TcpSocket' BSD-like TCP socket
implementation. The 'TcpSession' dependency is mocked — its own
behavior lives in the 'test__tcp__session__*.py' files.

pytcp/tests/unit/runtime/socket/test__runtime__socket__tcp__socket.py

ver 3.0.8
"""

import errno
import fcntl
import select
import struct
from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip6Address
from net_proto.lib.enums import IpProto
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pytcp.runtime.socket import (
    IPPROTO_TCP,
    SO_KEEPALIVE,
    SO_LINGER,
    SO_REUSEPORT,
    SOL_SOCKET,
    TCP_FASTOPEN,
    TCP_KEEPCNT,
    TCP_KEEPIDLE,
    TCP_KEEPINTVL,
    TCP_NODELAY,
    AddressFamily,
    SocketType,
    gaierror,
)
from pytcp.runtime.socket.socket_table import SocketTable
from pytcp.runtime.socket.tcp__socket import TcpSocket


def _make_packet_handler(
    *,
    ip4_unicast: list[Ip4Address] | None = None,
    ip6_unicast: list[Ip6Address] | None = None,
) -> SimpleNamespace:
    """
    Build a minimal 'packet_handler' stub exposing only the unicast
    address iterables that 'TcpSocket.bind' reads.
    """

    return SimpleNamespace(
        ip4_unicast=ip4_unicast or [Ip4Address("10.0.0.1")],
        ip6_unicast=ip6_unicast or [Ip6Address("2001:db8::1")],
    )


class _TcpSocketTestCase(TestCase):
    """
    Shared fixture that patches the module-level stack globals and the
    'TcpSession' constructor so no real FSM thread is spun up.
    """

    def setUp(self) -> None:
        """
        Install per-test patches on logging, 'stack.sockets', the
        cross-interface source-address introspection helpers, and the
        'TcpSession' class.
        """

        self._log_patch = patch("pytcp.runtime.socket.tcp__socket.log")
        self._log_patch.start()

        self._sockets = SocketTable()
        self._sockets_patch = patch(
            "pytcp.runtime.socket.tcp__socket.stack.sockets",
            self._sockets,
        )
        self._sockets_patch.start()

        self._helper_sockets_patch = patch(
            "pytcp.runtime.socket.socket__bind_helpers.stack.sockets",
            self._sockets,
        )
        self._helper_sockets_patch.start()

        self._handler = _make_packet_handler()

        # Phase-6 seam: source-address validation spans all interfaces via
        # 'stack.local_ip{4,6}_unicast()'. Make them read this fixture's
        # local stub handler.
        for _helper, _attr in (("local_ip4_unicast", "ip4_unicast"), ("local_ip6_unicast", "ip6_unicast")):
            _p = patch(
                f"pytcp.runtime.socket.tcp__socket.stack.{_helper}",
                side_effect=lambda attr=_attr: tuple(getattr(self._handler, attr)),
            )
            _p.start()
            self.addCleanup(_p.stop)

        self._session_cls_patch = patch(
            "pytcp.runtime.socket.tcp__socket.TcpSession",
        )
        self._session_cls = self._session_cls_patch.start()
        self._session_cls.return_value = MagicMock()

    def tearDown(self) -> None:
        """
        Tear down every per-test patch.
        """

        self._log_patch.stop()
        self._sockets_patch.stop()
        self._helper_sockets_patch.stop()
        self._session_cls_patch.stop()


class TestTcpSocketInit(_TcpSocketTestCase):
    """
    The 'TcpSocket.__init__' fresh-socket initialization tests.
    """

    def test__tcp_socket__init_ip4_defaults(self) -> None:
        """
        Ensure a fresh IPv4 TCP socket starts with unspecified
        addresses, both ports at 0, and no session attached. The
        'state' property must report 'FsmState.CLOSED' in this state.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.assertIs(s.socket_type, SocketType.STREAM, msg="socket_type must be STREAM.")
        self.assertIs(s.ip_proto, IpProto.TCP, msg="ip_proto must be TCP.")
        self.assertEqual(s.local_ip_address, Ip4Address(), msg="local_ip_address must start unspecified.")
        self.assertEqual(s.remote_ip_address, Ip4Address(), msg="remote_ip_address must start unspecified.")
        self.assertEqual(s.local_port, 0, msg="local_port must start at 0.")
        self.assertEqual(s.remote_port, 0, msg="remote_port must start at 0.")
        self.assertIsNone(s.tcp_session, msg="A fresh socket must have no TcpSession attached.")
        self.assertIsNone(s.parent_socket, msg="A fresh socket must have no parent socket attached.")
        self.assertIs(
            s.state,
            FsmState.CLOSED,
            msg="A fresh socket must report FsmState.CLOSED (no session attached).",
        )

    def test__tcp_socket__init_ip6_defaults(self) -> None:
        """
        Ensure a fresh IPv6 TCP socket starts with the '::' unspecified
        addresses.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET6)
        self.assertEqual(s.local_ip_address, Ip6Address(), msg="IPv6 local must start unspecified.")
        self.assertEqual(s.remote_ip_address, Ip6Address(), msg="IPv6 remote must start unspecified.")

    def test__tcp_socket__init_rejects_non_stream(self) -> None:
        """
        Ensure the 'assert type is SocketType.STREAM' guard fires for
        a non-STREAM socket type.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        with self.assertRaises(AssertionError):
            TcpSocket(family=AddressFamily.INET4, type=SocketType.DGRAM)

    def test__tcp_socket__init_rejects_non_tcp_protocol(self) -> None:
        """
        Ensure the 'assert protocol is IpProto.TCP' guard fires for a
        non-TCP protocol argument.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        with self.assertRaises(AssertionError):
            TcpSocket(family=AddressFamily.INET4, protocol=IpProto.UDP)

    def test__tcp_socket__init_with_session_binds_remote(self) -> None:
        """
        Ensure constructing a 'TcpSocket' with an existing
        'tcp_session' adopts the session's local/remote state and
        registers the socket on 'stack.sockets' immediately. This is
        the path taken when a listening socket spawns an accepted
        child.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        session = MagicMock()
        session.local_ip_address = Ip4Address("10.0.0.1")
        session.remote_ip_address = Ip4Address("10.0.0.2")
        session.local_port = 8080
        session.remote_port = 44444
        session.socket = MagicMock()

        s = TcpSocket(family=AddressFamily.INET4, tcp_session=session)

        self.assertIs(s.tcp_session, session, msg="A TcpSocket constructed with a session must keep it attached.")
        self.assertEqual(s.local_ip_address, Ip4Address("10.0.0.1"), msg="Socket must adopt session.local_ip_address.")
        self.assertEqual(
            s.remote_ip_address,
            Ip4Address("10.0.0.2"),
            msg="Socket must adopt session.remote_ip_address.",
        )
        self.assertEqual(s.local_port, 8080, msg="Socket must adopt session.local_port.")
        self.assertEqual(s.remote_port, 44444, msg="Socket must adopt session.remote_port.")
        self.assertIs(
            s.parent_socket,
            session.socket,
            msg="Socket must adopt session.socket as its parent_socket.",
        )
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="An accepted TcpSocket must register itself on stack.sockets immediately.",
        )


class TestTcpSocketBind(_TcpSocketTestCase):
    """
    The 'TcpSocket.bind' tests.
    """

    def test__tcp_socket__bind_accepts_stack_owned_address(self) -> None:
        """
        Ensure bind() with a stack-owned address and a specific port
        registers the socket on 'stack.sockets'.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="bind() must register the socket on stack.sockets.",
        )

    def test__tcp_socket__bind_rejects_rebinding(self) -> None:
        """
        Ensure calling bind() twice raises 'OSError' with Errno 22 —
        the socket can be bound to a specific port exactly once.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        with self.assertRaises(OSError) as context:
            s.bind(("10.0.0.1", 8081))
        self.assertIn(
            "[Errno 22]",
            str(context.exception),
            msg="bind() must raise Errno 22 when called a second time.",
        )

    def test__tcp_socket__bind_rejects_foreign_ip(self) -> None:
        """
        Ensure bind() to a specific IP not owned by the stack raises
        'OSError' with Errno 99.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            s.bind(("192.168.99.99", 0))
        self.assertIn(
            "[Errno 99]",
            str(context.exception),
            msg="bind() must raise Errno 99 for a foreign local IP.",
        )

    def test__tcp_socket__bind_rejects_malformed_ip(self) -> None:
        """
        Ensure a malformed IPv4 literal raises 'gaierror'.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(gaierror):
            s.bind(("garbage", 0))

    def test__tcp_socket__bind_rejects_out_of_range_port(self) -> None:
        """
        Ensure bind() raises 'OverflowError' for a port outside the
        0-65535 range.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.bind(("10.0.0.1", 70000))

    def test__tcp_socket__bind_picks_port_when_zero(self) -> None:
        """
        Ensure bind() with a local port of 0 defers to
        'pick_local_port' for ephemeral assignment.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with patch(
            "pytcp.runtime.socket.tcp__socket.pick_local_port",
            return_value=40000,
        ):
            s.bind(("10.0.0.1", 0))
        self.assertEqual(
            s.local_port,
            40000,
            msg="bind() with port 0 must assign the value returned by pick_local_port.",
        )

    def test__tcp_socket__bind_rejects_port_in_use(self) -> None:
        """
        Ensure bind() raises 'OSError' with Errno 98 when another
        socket has already claimed the port.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        first = TcpSocket(family=AddressFamily.INET4)
        first.bind(("10.0.0.1", 8080))

        second = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            second.bind(("10.0.0.1", 8080))
        self.assertIn(
            "[Errno 98]",
            str(context.exception),
            msg="bind() must raise Errno 98 when the (IP, port) is already in use.",
        )

    def test__tcp_socket__so_reuseport_allows_duplicate_bind_into_cohort(self) -> None:
        """
        Ensure two SO_REUSEPORT listening sockets bind the identical
        (ip, port) and both land in the registry cohort.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        first = TcpSocket(family=AddressFamily.INET4)
        first.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        first.bind(("10.0.0.1", 8080))

        second = TcpSocket(family=AddressFamily.INET4)
        second.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
        second.bind(("10.0.0.1", 8080))  # must not raise.

        self.assertCountEqual(
            self._sockets.values(),
            [first, second],
            msg="both SO_REUSEPORT sockets must coexist in the registry cohort.",
        )

    def test__tcp_socket__so_reuseport_mixed_with_plain_raises(self) -> None:
        """
        Ensure a SO_REUSEPORT bind conflicts with a plain socket
        already bound to the same (ip, port) — every cohort member
        must set the flag.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        first = TcpSocket(family=AddressFamily.INET4)
        first.bind(("10.0.0.1", 8080))  # plain, no SO_REUSEPORT.

        second = TcpSocket(family=AddressFamily.INET4)
        second.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)

        with self.assertRaises(OSError) as context:
            second.bind(("10.0.0.1", 8080))
        self.assertEqual(
            context.exception.errno,
            errno.EADDRINUSE,
            msg="SO_REUSEPORT must not join a cohort with a non-REUSEPORT socket.",
        )

    def test__tcp_socket__bind_ip6_rejects_malformed(self) -> None:
        """
        Ensure the IPv6 bind() path raises 'gaierror' for malformed
        IPv6 literals.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET6)
        with self.assertRaises(gaierror):
            s.bind(("not-a-v6", 0))


class TestTcpSocketConnect(_TcpSocketTestCase):
    """
    The 'TcpSocket.connect' tests.
    """

    def test__tcp_socket__connect_creates_session_and_calls_connect(self) -> None:
        """
        Ensure connect() instantiates a 'TcpSession' with the
        resolved addresses and delegates to its 'connect()' method.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            s.connect(("10.0.0.5", 80))

        self._session_cls.assert_called_once()
        self._session_cls.return_value.connect.assert_called_once_with()
        self.assertEqual(s.remote_ip_address, Ip4Address("10.0.0.5"), msg="connect() must set remote IP.")
        self.assertEqual(s.remote_port, 80, msg="connect() must set remote port.")

    def test__tcp_socket__connect_translates_refused(self) -> None:
        """
        Ensure a 'TcpSessionError("Connection refused")' raised by the
        session is translated into 'ConnectionRefusedError' with the
        Errno 111 message.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        self._session_cls.return_value.connect.side_effect = TcpSessionError("Connection refused")

        s = TcpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.runtime.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            with self.assertRaises(ConnectionRefusedError) as context:
                s.connect(("10.0.0.5", 80))
        self.assertIn(
            "[Errno 111]",
            str(context.exception),
            msg="TcpSessionError('Connection refused') must translate to Errno 111.",
        )

    def test__tcp_socket__connect_translates_timeout(self) -> None:
        """
        Ensure a 'TcpSessionError("Connection timeout")' raised by the
        session is translated into 'TimeoutError' with the Errno 110
        message.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        self._session_cls.return_value.connect.side_effect = TcpSessionError("Connection timeout")

        s = TcpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.runtime.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            with self.assertRaises(TimeoutError) as context:
                s.connect(("10.0.0.5", 80))
        self.assertIn(
            "[Errno 110]",
            str(context.exception),
            msg="TcpSessionError('Connection timeout') must translate to Errno 110.",
        )

    def test__tcp_socket__connect_rejects_unspecified_remote(self) -> None:
        """
        Ensure connecting to '0.0.0.0' raises 'ConnectionRefusedError'
        with the '[Errno 111]' message — unspecified remote is not a
        valid destination for a stream socket.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(ConnectionRefusedError):
            s.connect(("0.0.0.0", 80))

    def test__tcp_socket__connect_rejects_out_of_range_port(self) -> None:
        """
        Ensure connect() raises 'OverflowError' for a port outside
        the 0-65535 range.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.connect(("10.0.0.5", 70000))

    def test__tcp_socket__connect_rejects_malformed_address(self) -> None:
        """
        Ensure a malformed remote-address literal raises 'gaierror'.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(gaierror):
            s.connect(("garbage", 80))


class TestTcpSocketListenAccept(_TcpSocketTestCase):
    """
    The 'TcpSocket.listen' / 'TcpSocket.accept' tests.
    """

    def test__tcp_socket__listen_registers_and_starts_session(self) -> None:
        """
        Ensure listen() creates a 'TcpSession', registers the listening
        socket on 'stack.sockets' under the unspecified key, and
        delegates to the session's 'listen()' method.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._local_port = 80
        s.listen()

        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="listen() must register the listening socket on stack.sockets.",
        )
        self._session_cls.return_value.listen.assert_called_once_with()

    def test__tcp_socket__accept_returns_socket_and_address(self) -> None:
        """
        Ensure accept() returns a '(socket, (remote_ip_str, port))'
        tuple once the semaphore is signaled.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        # Pre-populate the accept queue with a child socket, then
        # release the semaphore so accept() does not block.
        child = MagicMock()
        child.remote_ip_address = Ip4Address("10.0.0.5")
        child.remote_port = 12345
        s._tcp_accept.append(child)
        s._event__tcp_session_established.release()

        result_socket, result_addr = s.accept()

        self.assertIs(
            result_socket,
            child,
            msg="accept() must return the socket popped from the accept queue.",
        )
        self.assertEqual(
            result_addr,
            ("10.0.0.5", 12345),
            msg="accept() must return (remote_ip_str, remote_port) as the address tuple.",
        )

    def test__tcp_socket__accept_timeout_raises(self) -> None:
        """
        Ensure accept() raises 'TimeoutError' when the semaphore is
        not signaled within the supplied timeout window.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(TimeoutError):
            s.accept(timeout=0.01)


class TestTcpSocketSendRecvClose(_TcpSocketTestCase):
    """
    The 'TcpSocket.send' / 'TcpSocket.recv' / 'TcpSocket.close' tests.
    """

    def _connected_socket(self) -> tuple[TcpSocket, MagicMock]:
        """
        Build a 'TcpSocket' with a mocked, attached session — the
        minimum state send() / recv() / close() require. Returns both
        the socket and the bound session mock so tests can configure
        return values / side effects without fighting the 'TcpSession |
        None' static type on the socket's '_tcp_session' slot.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._local_ip_address = Ip4Address("10.0.0.1")
        s._remote_ip_address = Ip4Address("10.0.0.5")
        s._local_port = 40000
        s._remote_port = 80
        session = MagicMock()
        s._tcp_session = session
        return s, session

    def test__tcp_socket__send_requires_destination(self) -> None:
        """
        Ensure send() on a socket with no remote IP raises
        'BrokenPipeError' (matching the CPython EPIPE shape) so the
        caller sees the same exception as a normal TCP send-after-FIN.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._tcp_session = MagicMock()
        with self.assertRaises(BrokenPipeError):
            s.send(b"data")

    def test__tcp_socket__send_returns_bytes_sent(self) -> None:
        """
        Ensure send() delegates to the session's send() and returns
        the byte count the session reports.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s, session = self._connected_socket()
        session.send.return_value = 5

        self.assertEqual(
            s.send(b"hello"),
            5,
            msg="send() must return the byte count reported by the underlying TcpSession.",
        )
        session.send.assert_called_once_with(data=b"hello")

    def test__tcp_socket__send_translates_session_error(self) -> None:
        """
        Ensure a 'TcpSessionError' from the session surfaces as a
        'BrokenPipeError' with the Errno 32 message, matching the
        BSD stream-socket contract.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s, session = self._connected_socket()
        session.send.side_effect = TcpSessionError("boom")

        with self.assertRaises(BrokenPipeError) as context:
            s.send(b"data")
        self.assertIn(
            "[Errno 32]",
            str(context.exception),
            msg="send() must translate TcpSessionError into BrokenPipeError with Errno 32.",
        )

    def test__tcp_socket__recv_returns_session_data(self) -> None:
        """
        Ensure recv() delegates to 'TcpSession.receive()' and returns
        its byte payload verbatim.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s, session = self._connected_socket()
        session.receive.return_value = b"payload"

        self.assertEqual(
            s.recv(),
            b"payload",
            msg="recv() must return the bytes returned by TcpSession.receive().",
        )

    def test__tcp_socket__recv_translates_timeout(self) -> None:
        """
        Ensure a 'TimeoutError' raised by the session is re-raised as
        a new 'TimeoutError' with the socket-level message.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s, session = self._connected_socket()
        session.receive.side_effect = TimeoutError("session")

        with self.assertRaises(TimeoutError) as context:
            s.recv(timeout=0.01)
        self.assertIn(
            "TCP Socket",
            str(context.exception),
            msg="recv() must re-raise TimeoutError with the socket-level prefix.",
        )

    def test__tcp_socket__close_delegates_to_session(self) -> None:
        """
        Ensure close() delegates to 'TcpSession.close()' unconditionally.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s, session = self._connected_socket()
        s.close()
        session.close.assert_called_once_with()

    def test__tcp_socket__process_tcp_packet_delegates_to_session(self) -> None:
        """
        Ensure 'process_tcp_packet' forwards the received metadata to
        'TcpSession.tcp_fsm'. If there is no session attached, the call
        must be a no-op.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s, session = self._connected_socket()
        md = MagicMock()
        s.process_tcp_packet(md)
        session.tcp_fsm.assert_called_once_with(md)

    def test__tcp_socket__process_tcp_packet_without_session_is_noop(self) -> None:
        """
        Ensure 'process_tcp_packet' on a socket with no session simply
        returns — it must not raise.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.process_tcp_packet(MagicMock())  # must not raise


class TestTcpSocketSendmsg(_TcpSocketTestCase):
    """
    The 'TcpSocket.sendmsg' tests.
    """

    def _connected_socket(self) -> tuple[TcpSocket, MagicMock]:
        """
        Build a 'TcpSocket' with a mocked, attached session ready for
        sendmsg(). Returns both the socket and its session mock.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._local_ip_address = Ip4Address("10.0.0.1")
        s._remote_ip_address = Ip4Address("10.0.0.5")
        s._local_port = 40000
        s._remote_port = 80
        session = MagicMock()
        s._tcp_session = session
        return s, session

    def test__tcp_socket__sendmsg_concatenates_buffers(self) -> None:
        """
        Ensure sendmsg() concatenates the scatter-gather 'buffers'
        iterable into one byte string, hands it to the session's
        send(), and returns the byte count, matching stdlib
        'socket.sendmsg' semantics on a stream socket.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s, session = self._connected_socket()
        session.send.return_value = 4

        self.assertEqual(
            s.sendmsg([b"AB", b"CD"]),
            4,
            msg="sendmsg() must return the byte count reported by the session.",
        )
        session.send.assert_called_once_with(data=b"ABCD")

    def test__tcp_socket__sendmsg_with_address_raises(self) -> None:
        """
        Ensure sendmsg() with a non-None 'address' on a connected
        stream socket raises 'OSError(EISCONN)' — a destination
        address is invalid on an already-connected TCP socket.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s, _session = self._connected_socket()

        with self.assertRaises(OSError) as context:
            s.sendmsg([b"x"], address=("10.0.0.9", 80))
        self.assertEqual(
            context.exception.errno,
            errno.EISCONN,
            msg="sendmsg(address=...) on a connected TCP socket must raise EISCONN.",
        )

    def test__tcp_socket__sendmsg_accepts_and_ignores_ancdata(self) -> None:
        """
        Ensure sendmsg() accepts a well-formed ancillary-data list and
        silently ignores it (Phase-1 honours no send-side cmsg type).

        Reference: socket(7) sendmsg (ancillary-data ignore).
        """

        s, session = self._connected_socket()
        session.send.return_value = 1

        self.assertEqual(
            s.sendmsg([b"x"], [(0, 0, b"\x00")]),
            1,
            msg="sendmsg() must accept a valid cmsg 3-tuple and send the payload regardless.",
        )

    def test__tcp_socket__sendmsg_rejects_malformed_ancdata(self) -> None:
        """
        Ensure sendmsg() rejects an ancillary-data entry that is not a
        3-tuple with a TypeError, matching the stdlib structural
        contract.

        Reference: socket(7) sendmsg (ancillary-data structure).
        """

        s, _session = self._connected_socket()

        bad_ancdata: list[Any] = [(1, 2)]
        with self.assertRaises(TypeError):
            s.sendmsg([b"x"], bad_ancdata)


class TestTcpSocketSoLinger(_TcpSocketTestCase):
    """
    The 'SO_LINGER' setsockopt / getsockopt option-storage tests.
    """

    def test__tcp_socket__so_linger__round_trips_struct_linger_bytes(self) -> None:
        """
        Ensure setsockopt(SOL_SOCKET, SO_LINGER, struct linger) stores
        the (l_onoff, l_linger) pair and getsockopt returns the same
        packed 'struct linger' bytes.

        Reference: socket(7) SO_LINGER (struct linger {l_onoff, l_linger}).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("@ii", 1, 30))

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_LINGER),
            struct.pack("@ii", 1, 30),
            msg="getsockopt(SO_LINGER) must round-trip the packed struct linger bytes.",
        )

    def test__tcp_socket__so_linger__defaults_to_zero_pair(self) -> None:
        """
        Ensure a fresh socket reads SO_LINGER as a zeroed 'struct
        linger' (l_onoff=0, l_linger=0) — linger disabled by default,
        matching Linux.

        Reference: socket(7) SO_LINGER (default disabled).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_LINGER),
            struct.pack("@ii", 0, 0),
            msg="Default SO_LINGER must read as a zeroed struct linger.",
        )

    def test__tcp_socket__so_linger__wrong_length_raises_einval(self) -> None:
        """
        Ensure setsockopt(SOL_SOCKET, SO_LINGER, value) rejects a
        buffer that is not exactly 'struct linger' sized with
        OSError(EINVAL).

        Reference: socket(7) SO_LINGER (optlen == sizeof(struct linger)).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(OSError) as context:
            s.setsockopt(SOL_SOCKET, SO_LINGER, b"\x00\x00\x00")
        self.assertEqual(
            context.exception.errno,
            errno.EINVAL,
            msg="A wrong-length SO_LINGER buffer must raise OSError(EINVAL).",
        )


class TestTcpSocketStateProperty(_TcpSocketTestCase):
    """
    The 'TcpSocket.state' property tests.
    """

    def test__tcp_socket__state_reflects_session(self) -> None:
        """
        Ensure the 'state' property reads through to
        'tcp_session.state' when a session is attached.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        session = MagicMock()
        session.state = FsmState.ESTABLISHED
        s._tcp_session = session

        self.assertIs(
            s.state,
            FsmState.ESTABLISHED,
            msg="TcpSocket.state must return tcp_session.state when a session is attached.",
        )

    def test__tcp_socket__state_closed_without_session(self) -> None:
        """
        Ensure the 'state' property returns 'FsmState.CLOSED' when no
        session is attached.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.assertIs(
            s.state,
            FsmState.CLOSED,
            msg="TcpSocket.state must return CLOSED when tcp_session is None.",
        )


class TestTcpSocketOptions(_TcpSocketTestCase):
    """
    The 'TcpSocket.setsockopt' / 'getsockopt' BSD-API tests, per
    RFC 1122 §4.2.3.6 (keep-alive must be application-controllable
    per connection) and POSIX 'setsockopt' / 'getsockopt' shape.
    """

    def test__tcp_socket__getsockopt__so_keepalive_default_zero(self) -> None:
        """
        Ensure a freshly-constructed 'TcpSocket' reports
        'SO_KEEPALIVE = 0' from 'getsockopt' — the default-off
        invariant at the socket-API layer.

        Reference: RFC 1122 §4.2.3.6 (SO_KEEPALIVE MUST default to off).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            0,
            msg=("RFC 1122 §4.2.3.6: 'SO_KEEPALIVE' MUST default to 0 on a " "freshly-constructed socket."),
        )

    def test__tcp_socket__setsockopt__so_keepalive_stores_one(self) -> None:
        """
        Ensure 'setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)' stores the
        flag and a subsequent 'getsockopt' round-trips it as 1.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            1,
            msg=("setsockopt(SO_KEEPALIVE, 1) followed by getsockopt(SO_KEEPALIVE) " "must round-trip as 1."),
        )

    def test__tcp_socket__setsockopt__so_keepalive_zero_disables(self) -> None:
        """
        Ensure 'setsockopt(SOL_SOCKET, SO_KEEPALIVE, 0)' after a
        previous '..., 1)' clears the flag. The application must be
        able to disable keep-alive, not just enable it.

        Reference: RFC 1122 §4.2.3.6 (application MUST be able to turn keep-alive on or off per connection).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 0)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            0,
            msg="setsockopt(SO_KEEPALIVE, 0) after a prior enable must clear the flag.",
        )

    def test__tcp_socket__setsockopt__nonzero_value_normalises_to_one(self) -> None:
        """
        Ensure boolean-shaped options collapse any non-zero integer
        to 1 on storage, matching Linux 'setsockopt(SO_KEEPALIVE,
        42, ...)' semantics. Without this, a later 'getsockopt'
        would surface a value the application never directly stored.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 42)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            1,
            msg="Boolean options (SO_KEEPALIVE) must normalise any non-zero value to 1.",
        )

    def test__tcp_socket__setsockopt__unknown_level_raises(self) -> None:
        """
        Ensure 'setsockopt' on an unknown 'level' parameter raises
        rather than silently dropping the call. POSIX dictates
        'OSError(ENOPROTOOPT)' / 'OSError(EINVAL)'; PyTCP uses
        'OSError' so the failure shape is greppable across the
        stdlib-compatible boundary.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(
            OSError,
            msg="setsockopt on an unknown 'level' must raise OSError.",
        ):
            s.setsockopt(0xDEAD, SO_KEEPALIVE, 1)

    def test__tcp_socket__setsockopt__unknown_optname_raises(self) -> None:
        """
        Ensure 'setsockopt' on a known level but unknown 'optname'
        parameter raises. Same POSIX semantics as the unknown-level
        case.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(
            OSError,
            msg="setsockopt on an unknown 'optname' must raise OSError.",
        ):
            s.setsockopt(SOL_SOCKET, 0xBEEF, 1)

    def test__tcp_socket__setsockopt__so_keepalive_at_tcp_level_raises(self) -> None:
        """
        Ensure that 'setsockopt(IPPROTO_TCP, SO_KEEPALIVE, 1)'
        (wrong level for SO_KEEPALIVE) raises rather than silently
        succeeding. SO_KEEPALIVE is an SOL_SOCKET-level option;
        applying it at IPPROTO_TCP is a programmer error worth
        flagging at the boundary.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(
            OSError,
            msg="setsockopt with SO_KEEPALIVE at IPPROTO_TCP level must raise.",
        ):
            s.setsockopt(IPPROTO_TCP, SO_KEEPALIVE, 1)

    def test__tcp_socket__getsockopt__unknown_level_raises(self) -> None:
        """
        Ensure 'getsockopt' raises symmetrically for unknown
        '(level, optname)' pairs.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(
            OSError,
            msg="getsockopt on an unknown (level, optname) pair must raise OSError.",
        ):
            s.getsockopt(0xDEAD, SO_KEEPALIVE)

    def test__tcp_socket__connect_propagates_so_keepalive_to_session(self) -> None:
        """
        Ensure 'setsockopt(SO_KEEPALIVE, 1)' followed by 'connect()'
        propagates the flag to the freshly-constructed TcpSession's
        '_keepalive_enabled' attribute. Without this propagation,
        the keep-alive feature has no path from the BSD-socket API
        to the protocol runtime.

        The test uses 'assertIs(..., True)' rather than 'assertTrue'
        because the mocked TcpSession is a MagicMock - reading any
        previously-unset attribute returns a new MagicMock, which
        is truthy. Identity-checking against the literal 'True'
        catches both cases.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.runtime.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertIs(
            self._session_cls.return_value._keepalive.enabled,
            True,
            msg=(
                "connect() must propagate '_so_keepalive' to the new TcpSession's "
                "'_keepalive_enabled' so RFC 1122 §4.2.3.6 keep-alive arms."
            ),
        )

    def test__tcp_socket__connect_propagates_default_disable_to_session(self) -> None:
        """
        Ensure connect() without setsockopt sets the new
        TcpSession's '_keepalive_enabled' to False explicitly
        (not "leave unset"), preserving the "MUST default to off"
        invariant via the BSD-socket API.

        Reference: RFC 1122 §4.2.3.6 (SO_KEEPALIVE MUST default to off).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.runtime.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertIs(
            self._session_cls.return_value._keepalive.enabled,
            False,
            msg=(
                "connect() without setsockopt(SO_KEEPALIVE, 1) must explicitly "
                "set '_keepalive_enabled = False' on the session."
            ),
        )

    def test__tcp_socket__listen_propagates_so_keepalive_to_session(self) -> None:
        """
        Ensure 'setsockopt(SO_KEEPALIVE, 1)' followed by 'listen()'
        propagates the flag to the freshly-constructed listening
        TcpSession's '_keepalive_enabled'. Listener-fork children
        inherit through the listening session's flag, so a
        listening socket that opted in via setsockopt produces
        keep-alive-enabled child sessions for every incoming SYN.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        s._local_ip_address = Ip4Address("10.0.0.1")
        s._local_port = 80
        s.listen()

        self.assertIs(
            self._session_cls.return_value._keepalive.enabled,
            True,
            msg=(
                "listen() must propagate '_so_keepalive' to the new listening "
                "TcpSession's '_keepalive_enabled' so accepted children inherit."
            ),
        )

    def test__tcp_socket__setsockopt__tcp_keepidle_round_trip(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, N)' stores
        the per-connection idle override and a subsequent
        'getsockopt' returns the same N.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 600)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_KEEPIDLE),
            600,
            msg="TCP_KEEPIDLE must round-trip via setsockopt / getsockopt.",
        )

    def test__tcp_socket__setsockopt__tcp_keepintvl_round_trip(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, N)' stores
        the per-connection probe-interval override and a subsequent
        'getsockopt' returns the same N.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 75)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_KEEPINTVL),
            75,
            msg="TCP_KEEPINTVL must round-trip via setsockopt / getsockopt.",
        )

    def test__tcp_socket__setsockopt__tcp_keepcnt_round_trip(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_KEEPCNT, N)' stores
        the per-connection probe-count override and a subsequent
        'getsockopt' returns the same N.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, 5)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_KEEPCNT),
            5,
            msg="TCP_KEEPCNT must round-trip via setsockopt / getsockopt.",
        )

    def test__tcp_socket__getsockopt__tcp_keep_overrides_default_zero(self) -> None:
        """
        Ensure getsockopt for the three TCP_KEEP* overrides
        returns 0 on a fresh socket - the sentinel meaning "no
        override; the session falls back to the global
        'tcp__constants.KEEPALIVE_*' default at runtime."

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.assertEqual(s.getsockopt(IPPROTO_TCP, TCP_KEEPIDLE), 0)
        self.assertEqual(s.getsockopt(IPPROTO_TCP, TCP_KEEPINTVL), 0)
        self.assertEqual(s.getsockopt(IPPROTO_TCP, TCP_KEEPCNT), 0)

    def test__tcp_socket__connect_propagates_keep_overrides_to_session(self) -> None:
        """
        Ensure setsockopt(IPPROTO_TCP, TCP_KEEP*, ...) followed by
        connect() propagates each override onto the freshly-
        constructed TcpSession's matching field. Without this, the
        per-connection override has no path into the protocol
        runtime.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 600)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 75)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, 5)
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.runtime.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertEqual(
            self._session_cls.return_value._keepalive.idle_override,
            600,
            msg="connect() must propagate TCP_KEEPIDLE override to session.",
        )
        self.assertEqual(
            self._session_cls.return_value._keepalive.interval_override,
            75,
            msg="connect() must propagate TCP_KEEPINTVL override to session.",
        )
        self.assertEqual(
            self._session_cls.return_value._keepalive.max_count_override,
            5,
            msg="connect() must propagate TCP_KEEPCNT override to session.",
        )

    def test__tcp_socket__connect_with_data_pre_loads_session_tx_buffer(self) -> None:
        """
        Ensure 'TcpSocket.connect(remote, data=b"...")'
        accepts a 'data' kwarg and pre-loads the freshly-
        constructed 'TcpSession' TX buffer with that data
        before driving the FSM into SYN_SENT. This is the
        ergonomic entry path for client-side TCP Fast Open:
        the application supplies data alongside the connect
        call, and (when a TFO cookie is cached for the
        peer) the SYN itself carries the data on the wire,
        eliminating the data RTT of a vanilla 3WHS-then-
        send sequence.

        Reference: RFC 7413 §3.1 (client connect-with-data API).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        early_data = b"GET / HTTP/1.1\r\n"
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.runtime.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80), data=early_data)

        self._session_cls.return_value._tx.buffer.extend.assert_called_with(early_data)

    def test__tcp_socket__getsockopt__tcp_fastopen_default_zero(self) -> None:
        """
        Ensure a freshly-constructed 'TcpSocket' reports
        'TCP_FASTOPEN = 0' from 'getsockopt'. The Linux
        convention treats the value as the TFO accept queue
        depth, with 0 meaning "TFO disabled" - the default
        for a socket that has not opted in via
        'setsockopt'.

        Reference: RFC 7413 §3.1 (server opts in to TFO via setsockopt).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_FASTOPEN),
            0,
            msg=(
                "TCP_FASTOPEN MUST default to 0 (TFO disabled) "
                "on a freshly-constructed socket; the application "
                "explicitly opts in by calling 'setsockopt"
                "(IPPROTO_TCP, TCP_FASTOPEN, qlen)' with a "
                "positive queue depth."
            ),
        )

    def test__tcp_socket__setsockopt__tcp_fastopen_round_trips(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_FASTOPEN, qlen)'
        stores the queue depth and a subsequent 'getsockopt'
        returns the same value.

        Reference: RFC 7413 §3.1 (server-side TFO enable via setsockopt).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_FASTOPEN, 16)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_FASTOPEN),
            16,
            msg=("setsockopt(TCP_FASTOPEN, 16) followed by " "getsockopt must round-trip as 16."),
        )

    def test__tcp_socket__setsockopt__tcp_fastopen_zero_disables(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_FASTOPEN, 0)'
        after a previous '..., qlen)' clears the option. The
        application MUST be able to disable TFO on a
        previously-enabled socket.

        Reference: RFC 7413 §3.1 (server opt-out via setsockopt qlen=0).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_FASTOPEN, 16)
        s.setsockopt(IPPROTO_TCP, TCP_FASTOPEN, 0)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_FASTOPEN),
            0,
            msg=("setsockopt(TCP_FASTOPEN, 0) after a prior " "enable must clear the option."),
        )

    def test__tcp_socket__getsockopt__tcp_nodelay_default_zero(self) -> None:
        """
        Ensure a freshly-constructed TcpSocket reports
        TCP_NODELAY = 0 (Nagle enabled by default).

        Reference: RFC 1122 §4.2.3.4 (Nagle SHOULD be implemented).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_NODELAY),
            0,
            msg="TCP_NODELAY must default to 0 (Nagle enabled).",
        )

    def test__tcp_socket__setsockopt__tcp_nodelay_round_trip(self) -> None:
        """
        Ensure setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        followed by getsockopt round-trips as 1.

        Reference: RFC 1122 §4.2.3.4 (application disable of Nagle).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_NODELAY),
            1,
            msg="setsockopt(TCP_NODELAY, 1) must round-trip via getsockopt.",
        )

    def test__tcp_socket__setsockopt__tcp_nodelay_zero_re_enables_nagle(self) -> None:
        """
        Ensure setsockopt(IPPROTO_TCP, TCP_NODELAY, 0) after
        a prior enable re-enables Nagle. The application MUST
        be able to toggle the flag in either direction.

        Reference: RFC 1122 §4.2.3.4 (application toggle).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 0)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_NODELAY),
            0,
            msg="setsockopt(TCP_NODELAY, 0) after a prior enable must clear.",
        )

    def test__tcp_socket__setsockopt__tcp_nodelay_normalises_nonzero_to_one(self) -> None:
        """
        Ensure setsockopt(IPPROTO_TCP, TCP_NODELAY, 42)
        normalises any non-zero integer to 1 on round-trip,
        matching boolean-option semantics.

        Reference: RFC 1122 §4.2.3.4 (boolean toggle).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 42)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_NODELAY),
            1,
            msg="Non-zero TCP_NODELAY value must normalise to 1.",
        )

    def test__tcp_socket__connect_propagates_tcp_nodelay_to_session(self) -> None:
        """
        Ensure setsockopt(TCP_NODELAY, 1) followed by connect()
        propagates the flag to the freshly-constructed
        TcpSession's '_tcp_nodelay' attribute.

        Reference: RFC 1122 §4.2.3.4 (TCP_NODELAY socket-API path).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.runtime.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertIs(
            self._session_cls.return_value._tcp_nodelay,
            True,
            msg=("connect() must propagate '_tcp_nodelay' to the new " "TcpSession so the Nagle gate can read it."),
        )

    def test__tcp_socket__getsockopt__tcp_user_timeout_default_zero(self) -> None:
        """
        Ensure a freshly-constructed 'TcpSocket' reports
        'TCP_USER_TIMEOUT = 0' from 'getsockopt' — the "no
        override" sentinel matching Linux.

        Reference: Linux net.ipv4.tcp_user_timeout (0 = no override).
        """

        from pytcp.runtime.socket import TCP_USER_TIMEOUT

        s = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_USER_TIMEOUT),
            0,
            msg="TCP_USER_TIMEOUT must default to 0 on a freshly-constructed socket.",
        )

    def test__tcp_socket__setsockopt__tcp_user_timeout_round_trip(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_USER_TIMEOUT,
        30000)' stores the value and 'getsockopt' round-trips
        it.

        Reference: Linux net.ipv4.tcp_user_timeout.
        """

        from pytcp.runtime.socket import TCP_USER_TIMEOUT

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_USER_TIMEOUT, 30000)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_USER_TIMEOUT),
            30000,
            msg="TCP_USER_TIMEOUT setsockopt → getsockopt must round-trip the ms budget.",
        )

    def test__tcp_socket__setsockopt__tcp_user_timeout_rejects_negative(self) -> None:
        """
        Ensure 'setsockopt(TCP_USER_TIMEOUT, -1)' raises
        'OSError(EINVAL)' — a negative budget is meaningless.

        Reference: Linux net.ipv4.tcp_user_timeout (rejects negative).
        """

        from pytcp.runtime.socket import TCP_USER_TIMEOUT

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(OSError) as ctx:
            s.setsockopt(IPPROTO_TCP, TCP_USER_TIMEOUT, -1)
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="setsockopt(TCP_USER_TIMEOUT, -1) must raise OSError(EINVAL).",
        )

    def test__tcp_socket__connect_propagates_tcp_user_timeout_to_session(self) -> None:
        """
        Ensure 'setsockopt(TCP_USER_TIMEOUT, 30000)' followed
        by 'connect()' propagates onto the freshly-constructed
        'TcpSession._user_timeout_ms' so the R2-abort site
        can consult it.

        Reference: Linux net.ipv4.tcp_user_timeout (R2-abort override).
        """

        from pytcp.runtime.socket import TCP_USER_TIMEOUT

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_USER_TIMEOUT, 30000)
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.runtime.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertEqual(
            self._session_cls.return_value._user_timeout_ms,
            30000,
            msg="connect() must propagate '_tcp_user_timeout' to TcpSession._user_timeout_ms.",
        )

    def test__tcp_socket__listen_propagates_tcp_user_timeout_to_session(self) -> None:
        """
        Ensure 'setsockopt(TCP_USER_TIMEOUT, 30000)' followed
        by 'listen()' propagates onto the listening session's
        '_user_timeout_ms' so accepted children inherit it
        through the listener-fork pivot.

        Reference: Linux net.ipv4.tcp_user_timeout (R2-abort override).
        """

        from pytcp.runtime.socket import TCP_USER_TIMEOUT

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_USER_TIMEOUT, 30000)
        s._local_ip_address = Ip4Address("10.0.0.1")
        s._local_port = 40000
        s.listen()

        self.assertEqual(
            self._session_cls.return_value._user_timeout_ms,
            30000,
            msg="listen() must propagate '_tcp_user_timeout' to TcpSession._user_timeout_ms.",
        )

    def test__tcp_socket__getsockopt__tcp_maxseg_default_zero(self) -> None:
        """
        Ensure a freshly-constructed 'TcpSocket' (no session)
        reports 'TCP_MAXSEG = 0' from 'getsockopt' — the
        "no clamp" sentinel matching Linux's pre-connect
        behaviour.

        Reference: Linux TCP_MAXSEG (0 = no clamp, pre-connect).
        """

        from pytcp.runtime.socket import TCP_MAXSEG

        s = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_MAXSEG),
            0,
            msg="TCP_MAXSEG must default to 0 pre-connect (no clamp).",
        )

    def test__tcp_socket__setsockopt__tcp_maxseg_round_trip(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_MAXSEG, 1200)'
        stores the value and 'getsockopt' round-trips it
        pre-connect (no session yet to defer to).

        Reference: Linux TCP_MAXSEG.
        """

        from pytcp.runtime.socket import TCP_MAXSEG

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_MAXSEG, 1200)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_MAXSEG),
            1200,
            msg="TCP_MAXSEG setsockopt → getsockopt must round-trip pre-connect.",
        )

    def test__tcp_socket__setsockopt__tcp_maxseg_rejects_below_min_mss(self) -> None:
        """
        Ensure 'setsockopt(TCP_MAXSEG, 87)' raises
        'OSError(EINVAL)' — Linux's 'include/net/tcp.h'
        'TCP_MIN_MSS = 88' is the acceptance floor; values
        below are rejected.

        Reference: Linux include/net/tcp.h TCP_MIN_MSS=88.
        """

        from pytcp.runtime.socket import TCP_MAXSEG

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(OSError) as ctx:
            s.setsockopt(IPPROTO_TCP, TCP_MAXSEG, 87)
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="setsockopt(TCP_MAXSEG, 87) must raise OSError(EINVAL) below 88 floor.",
        )

    def test__tcp_socket__setsockopt__tcp_maxseg_zero_clears_clamp(self) -> None:
        """
        Ensure 'setsockopt(TCP_MAXSEG, 0)' is accepted — the
        Linux convention for "remove the clamp" matches the
        default-off behaviour.

        Reference: Linux TCP_MAXSEG (0 = no clamp).
        """

        from pytcp.runtime.socket import TCP_MAXSEG

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_MAXSEG, 1200)
        s.setsockopt(IPPROTO_TCP, TCP_MAXSEG, 0)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_MAXSEG),
            0,
            msg="setsockopt(TCP_MAXSEG, 0) after an earlier clamp must clear the clamp.",
        )

    def test__tcp_socket__connect_propagates_tcp_maxseg_to_session(self) -> None:
        """
        Ensure 'setsockopt(TCP_MAXSEG, 1200)' followed by
        'connect()' propagates onto the freshly-constructed
        'TcpSession._maxseg_override' so the SYN-options
        clamp can consult it.

        Reference: Linux TCP_MAXSEG (per-connection SYN MSS clamp).
        """

        from pytcp.runtime.socket import TCP_MAXSEG

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_MAXSEG, 1200)
        with (
            patch(
                "pytcp.runtime.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.runtime.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertEqual(
            self._session_cls.return_value._maxseg_override,
            1200,
            msg="connect() must propagate '_tcp_maxseg' to TcpSession._maxseg_override.",
        )

    def test__tcp_socket__getsockopt__ipv6_v6only_default_one(self) -> None:
        """
        Ensure a freshly-constructed AF_INET6 'TcpSocket'
        reports 'IPV6_V6ONLY = 1' from 'getsockopt' — the
        default-on invariant matching Python's stdlib socket
        behaviour and the Linux 'net.ipv6.bindv6only' kernel
        default.

        Reference: Linux net.ipv6.bindv6only (default 1).
        Reference: Python socket.has_dualstack_ipv6 (default off).
        """

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_V6ONLY

        s = TcpSocket(family=AddressFamily.INET6)

        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_V6ONLY),
            1,
            msg="IPV6_V6ONLY must default to 1 on a freshly-constructed AF_INET6 socket.",
        )

    def test__tcp_socket__setsockopt__ipv6_v6only_zero_enables_dual_stack(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)'
        stores the flag and 'getsockopt' round-trips it — the
        Phase 3 dual-stack listener-fork will key off this
        flag to decide whether to accept inbound IPv4 peers.

        Reference: Linux IPV6_V6ONLY (0 = dual-stack mode).
        """

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_V6ONLY

        s = TcpSocket(family=AddressFamily.INET6)
        s.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)

        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_V6ONLY),
            0,
            msg="IPV6_V6ONLY=0 setsockopt → getsockopt must round-trip as 0.",
        )

    def test__tcp_socket__setsockopt__ipv6_v6only_one_re_enables_strict_ipv6(self) -> None:
        """
        Ensure 'setsockopt(IPV6_V6ONLY, 1)' after an earlier
        '..., 0)' re-enables strict-IPv6 mode — the application
        must be able to switch the flag both directions before
        bind() commits the socket's family scope.

        Reference: Linux IPV6_V6ONLY (1 = strict IPv6 only).
        """

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_V6ONLY

        s = TcpSocket(family=AddressFamily.INET6)
        s.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 0)
        s.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 1)

        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_V6ONLY),
            1,
            msg="setsockopt(IPV6_V6ONLY, 1) after a prior 0 must re-enable strict mode.",
        )

    def test__tcp_socket__setsockopt__ipv6_v6only_nonzero_normalises_to_one(self) -> None:
        """
        Ensure boolean-shaped 'IPV6_V6ONLY' setsockopt
        collapses any non-zero integer to 1 on storage,
        matching Linux's behaviour where the kernel reads
        the value via 'sockptr_t' and stores
        '!!val' (boolean coercion).

        Reference: Linux IPV6_V6ONLY (boolean storage).
        """

        from pytcp.runtime.socket import IPPROTO_IPV6, IPV6_V6ONLY

        s = TcpSocket(family=AddressFamily.INET6)
        s.setsockopt(IPPROTO_IPV6, IPV6_V6ONLY, 42)

        self.assertEqual(
            s.getsockopt(IPPROTO_IPV6, IPV6_V6ONLY),
            1,
            msg="Boolean IPV6_V6ONLY must normalise any non-zero value to 1.",
        )

    def test__tcp_socket__listen_propagates_tcp_maxseg_to_session(self) -> None:
        """
        Ensure 'setsockopt(TCP_MAXSEG, 1200)' followed by
        'listen()' propagates onto the listening session's
        '_maxseg_override' so the listener-fork pivot pushes
        it into accepted children.

        Reference: Linux TCP_MAXSEG (per-connection SYN MSS clamp).
        """

        from pytcp.runtime.socket import TCP_MAXSEG

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_MAXSEG, 1200)
        s._local_ip_address = Ip4Address("10.0.0.1")
        s._local_port = 40000
        s.listen()

        self.assertEqual(
            self._session_cls.return_value._maxseg_override,
            1200,
            msg="listen() must propagate '_tcp_maxseg' to TcpSession._maxseg_override.",
        )


class TestTcpSocketDualStackPresentation(_TcpSocketTestCase):
    """
    H3 Phase 3c — dual-stack presentation tests. When a socket has
    '_dual_stack = True' (set by the listener-fork on an accepted
    child of an AF_INET6 V6ONLY=0 listener that accepted an IPv4
    inbound), the app-facing accessors wrap the wire-IPv4
    addresses to the IPv4-mapped IPv6 form so the application
    sees Linux dual-stack semantics. The wire attributes
    ('_local_ip_address' / '_remote_ip_address' / '_address_family'
    / 'socket_id') stay AF_INET4 so the RX-path active-socket
    lookup keeps matching the inbound IPv4 packets.
    """

    def test__tcp_socket__dual_stack_default_off(self) -> None:
        """
        Ensure '_dual_stack' defaults to False on a freshly-
        constructed socket — the regression pin against accidental
        presentation wrapping.

        Reference: socket_linux_parity_audit.md §H3 Phase 3c (default off).
        """

        s = TcpSocket(family=AddressFamily.INET6)

        self.assertFalse(
            s._dual_stack,
            msg="'_dual_stack' must default to False on a freshly-constructed socket.",
        )

    def test__tcp_socket__dual_stack_local_ip_address_wraps_to_mapped(self) -> None:
        """
        Ensure 'local_ip_address' returns the IPv4-mapped IPv6
        form when '_dual_stack' is True — the property the
        'getsockname()' surface reads.

        Reference: RFC 4291 §2.5.5.2 (IPv4-mapped surfacing on dual-stack).
        """

        from net_addr import Ip6Address

        s = TcpSocket(family=AddressFamily.INET6)
        s._local_ip_address = Ip4Address("10.0.0.7")
        s._dual_stack = True

        self.assertEqual(
            s.local_ip_address,
            Ip6Address("::ffff:10.0.0.7"),
            msg="local_ip_address must wrap wire IPv4 to ::ffff:0:0/96 form when dual_stack.",
        )

    def test__tcp_socket__dual_stack_remote_ip_address_wraps_to_mapped(self) -> None:
        """
        Ensure 'remote_ip_address' returns the IPv4-mapped IPv6
        form when '_dual_stack' is True — the property the
        'getpeername()' / 'accept()' return surfaces read.

        Reference: RFC 4291 §2.5.5.2 (IPv4-mapped on dual-stack accept).
        """

        from net_addr import Ip6Address

        s = TcpSocket(family=AddressFamily.INET6)
        s._remote_ip_address = Ip4Address("10.0.0.91")
        s._dual_stack = True

        self.assertEqual(
            s.remote_ip_address,
            Ip6Address("::ffff:10.0.0.91"),
            msg="remote_ip_address must wrap wire IPv4 to ::ffff:0:0/96 form when dual_stack.",
        )

    def test__tcp_socket__dual_stack_family_reports_af_inet6(self) -> None:
        """
        Ensure the 'family' property reports AF_INET6 when
        '_dual_stack' is True even though '_address_family' is
        AF_INET4 (for wire / RX-lookup correctness). Matches
        Linux's accept() returning an AF_INET6 child of a
        dual-stack listener.

        Reference: Linux IPV6_V6ONLY (accepted child reports AF_INET6).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._dual_stack = True

        self.assertIs(
            s.family,
            AddressFamily.INET6,
            msg="family property must report AF_INET6 when dual_stack is True.",
        )
        self.assertIs(
            s._address_family,
            AddressFamily.INET4,
            msg="_address_family must stay AF_INET4 (wire) under dual_stack.",
        )

    def test__tcp_socket__dual_stack_getsockname_returns_mapped_string(self) -> None:
        """
        Ensure 'getsockname()' returns the IPv4-mapped IPv6
        string form when '_dual_stack' is True — the application-
        facing API the dual-stack contract exists for.

        Reference: Linux IPV6_V6ONLY (getsockname IPv4-mapped surface).
        """

        s = TcpSocket(family=AddressFamily.INET6)
        s._local_ip_address = Ip4Address("10.0.0.7")
        s._local_port = 8080
        s._dual_stack = True

        self.assertEqual(
            s.getsockname(),
            ("::ffff:10.0.0.7", 8080),
            msg="getsockname() must return the IPv4-mapped string form when dual_stack.",
        )

    def test__tcp_socket__dual_stack_getpeername_returns_mapped_string(self) -> None:
        """
        Ensure 'getpeername()' returns the IPv4-mapped IPv6
        string form when '_dual_stack' is True.

        Reference: Linux IPV6_V6ONLY (getpeername IPv4-mapped surface).
        """

        s = TcpSocket(family=AddressFamily.INET6)
        s._remote_ip_address = Ip4Address("10.0.0.91")
        s._remote_port = 12345
        s._dual_stack = True

        self.assertEqual(
            s.getpeername(),
            ("::ffff:10.0.0.91", 12345),
            msg="getpeername() must return the IPv4-mapped string form when dual_stack.",
        )

    def test__tcp_socket__non_dual_stack_keeps_wire_form(self) -> None:
        """
        Ensure '_dual_stack=False' (the default) leaves the wire
        addresses untouched on all four accessors — the
        regression pin against accidental wrapping on
        single-family sockets.

        Reference: socket_linux_parity_audit.md §H3 Phase 3c (no-op when off).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._local_ip_address = Ip4Address("10.0.0.7")
        s._local_port = 8080
        s._remote_ip_address = Ip4Address("10.0.0.91")
        s._remote_port = 12345
        # _dual_stack stays False (default).

        self.assertEqual(
            s.local_ip_address,
            Ip4Address("10.0.0.7"),
            msg="local_ip_address must return wire IPv4 when dual_stack is False.",
        )
        self.assertEqual(
            s.remote_ip_address,
            Ip4Address("10.0.0.91"),
            msg="remote_ip_address must return wire IPv4 when dual_stack is False.",
        )
        self.assertIs(
            s.family,
            AddressFamily.INET4,
            msg="family must report AF_INET4 when dual_stack is False.",
        )
        self.assertEqual(
            s.getsockname(),
            ("10.0.0.7", 8080),
            msg="getsockname() must return wire string when dual_stack is False.",
        )


class TestTcpSocketFileno(_TcpSocketTestCase):
    """
    The 'TcpSocket.fileno' / read-readiness signal-and-drain tests.
    """

    def setUp(self) -> None:
        """
        Build a fresh TCP socket. 'tearDown' closes the eventfd
        before the parent fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = TcpSocket(family=AddressFamily.INET4)

    def tearDown(self) -> None:
        """
        Release the socket's eventfd while the 'log' patch is still
        active, then let the parent tear down the stack stubs.
        '_close_io_runtime' rather than 'close()' here because the
        socket has no session attached.
        """

        try:
            self._socket._close_io_runtime()
        except OSError:
            pass
        super().tearDown()

    def test__tcp_socket__fileno_returns_non_negative_int(self) -> None:
        """
        Ensure 'fileno()' on a TCP socket returns a non-negative
        integer file descriptor for selector consumption.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()

        self.assertIsInstance(
            fd,
            int,
            msg="TcpSocket.fileno() must return an int.",
        )
        self.assertGreaterEqual(
            fd,
            0,
            msg="TcpSocket.fileno() must return a non-negative fd.",
        )

    def test__tcp_socket__fileno_initially_not_select_ready(self) -> None:
        """
        Ensure a freshly-constructed TCP socket reports as not
        readable until either a child connection lands on the
        accept queue or session data lands in the rx buffer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="A fresh TcpSocket must not be select-readable.",
        )

    def test__tcp_socket__fileno_select_ready_after_accept_queue_appended(self) -> None:
        """
        Ensure a child socket landing on the listening socket's
        accept queue (the listener-fork hook in
        'tcp__fsm__syn_rcvd.py') makes the listening socket
        select-readable so an event-loop accept-loop wakes.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 9293 §3.10.2 (OPEN passive / accept queue delivery).
        """

        child = MagicMock()
        self._socket._tcp_accept.append(child)
        self._socket._event__tcp_session_established.release()
        self._socket._signal_readable()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="A child appended to the accept queue must mark the listening fd readable.",
        )

    def test__tcp_socket__accept_drains_fileno_when_last_child_consumed(self) -> None:
        """
        Ensure 'accept()' returns the listening fd to the
        not-readable state once the last queued child has been
        consumed — selector-driven accept loops rely on this.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 9293 §3.10.2 (OPEN passive / accept queue delivery).
        """

        child = MagicMock()
        child.remote_ip_address = Ip4Address("10.0.0.5")
        child.remote_port = 12345
        self._socket._tcp_accept.append(child)
        self._socket._event__tcp_session_established.release()
        self._socket._signal_readable()

        self._socket.accept()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="accept() consuming the last queued child must clear the readable bit.",
        )

    def test__tcp_socket__accept_keeps_fileno_ready_when_more_children_queued(self) -> None:
        """
        Ensure 'accept()' on a queue with more than one pending
        child leaves the listening fd select-readable so the next
        selector tick still wakes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = MagicMock()
        first.remote_ip_address = Ip4Address("10.0.0.5")
        first.remote_port = 12345
        second = MagicMock()
        second.remote_ip_address = Ip4Address("10.0.0.6")
        second.remote_port = 12346
        self._socket._tcp_accept.extend([first, second])
        self._socket._event__tcp_session_established.release()
        self._socket._event__tcp_session_established.release()
        self._socket._signal_readable()
        self._socket._signal_readable()

        self._socket.accept()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="accept() leaving children queued must keep the listening fd readable.",
        )

    def test__tcp_socket__close_io_runtime_closes_underlying_fd(self) -> None:
        """
        Ensure '_close_io_runtime()' tears down the eventfd backing
        'fileno()' on a TCP socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()
        self._socket._close_io_runtime()

        with self.assertRaises(OSError) as context:
            fcntl.fcntl(fd, fcntl.F_GETFD)

        self.assertEqual(
            context.exception.errno,
            errno.EBADF,
            msg="_close_io_runtime() must close the eventfd backing fileno() (EBADF).",
        )


class TestTcpSocketNonBlocking(_TcpSocketTestCase):
    """
    The 'TcpSocket.setblocking' non-blocking-recv / accept tests.
    """

    def setUp(self) -> None:
        """
        Build a non-blocking TCP socket. tearDown releases the
        eventfd before the parent fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = TcpSocket(family=AddressFamily.INET4)
        self._socket.setblocking(False)

    def tearDown(self) -> None:
        """
        Close the eventfd before the parent tears down patches.
        """

        try:
            self._socket._close_io_runtime()
        except OSError:
            pass
        super().tearDown()

    def test__tcp_socket__recv_raises_blocking_io_error_when_no_data(self) -> None:
        """
        Ensure 'recv()' on a non-blocking TCP socket with an empty
        rx buffer raises 'BlockingIOError(EAGAIN)' to match POSIX
        'O_NONBLOCK' semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 9293 §3.10.5 (RECEIVE call).
        """

        session = MagicMock()
        session.receive.side_effect = TimeoutError("no data ready")
        self._socket._tcp_session = session
        self._socket._remote_ip_address = Ip4Address("10.0.0.5")
        self._socket._remote_port = 80

        with self.assertRaises(BlockingIOError) as context:
            self._socket.recv()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="Non-blocking recv() with no data must raise BlockingIOError(EAGAIN).",
        )

    def test__tcp_socket__recv_passes_zero_timeout_when_non_blocking(self) -> None:
        """
        Ensure 'recv()' on a non-blocking TCP socket forwards
        'timeout=0' to 'TcpSession.receive' so the session does not
        wait — the per-call non-blocking attempt is what makes
        BlockingIOError translation correct.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = MagicMock()
        session.receive.return_value = b"data"
        self._socket._tcp_session = session
        self._socket._remote_ip_address = Ip4Address("10.0.0.5")
        self._socket._remote_port = 80

        self._socket.recv()

        session.receive.assert_called_once_with(byte_count=None, timeout=0)

    def test__tcp_socket__recv_per_call_timeout_overrides_non_blocking(self) -> None:
        """
        Ensure an explicit 'timeout=' parameter takes precedence
        over the 'setblocking(False)' flag — per-call timeout wins,
        matching CPython socket semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = MagicMock()
        session.receive.side_effect = TimeoutError("session timeout")
        self._socket._tcp_session = session
        self._socket._remote_ip_address = Ip4Address("10.0.0.5")
        self._socket._remote_port = 80

        with self.assertRaises(TimeoutError):
            self._socket.recv(timeout=0.01)

    def test__tcp_socket__accept_raises_blocking_io_error_when_no_child(self) -> None:
        """
        Ensure 'accept()' on a non-blocking listening TCP socket
        with an empty accept queue raises 'BlockingIOError(EAGAIN)'.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 9293 §3.10.2 (OPEN passive / accept queue delivery).
        """

        with self.assertRaises(BlockingIOError) as context:
            self._socket.accept()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="Non-blocking accept() with no child queued must raise BlockingIOError(EAGAIN).",
        )

    def test__tcp_socket__accept_returns_child_when_non_blocking_and_queued(self) -> None:
        """
        Ensure 'accept()' on a non-blocking socket returns the
        queued child immediately when one is available.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        child = MagicMock()
        child.remote_ip_address = Ip4Address("10.0.0.5")
        child.remote_port = 12345
        self._socket._tcp_accept.append(child)
        self._socket._event__tcp_session_established.release()
        self._socket._signal_readable()

        result, _ = self._socket.accept()

        self.assertIs(
            result,
            child,
            msg="Non-blocking accept() with a queued child must return it.",
        )

    def test__tcp_socket__accept_per_call_timeout_overrides_non_blocking(self) -> None:
        """
        Ensure an explicit 'timeout=' on 'accept()' takes precedence
        over the 'setblocking(False)' flag and yields 'TimeoutError'
        on elapse.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TimeoutError):
            self._socket.accept(timeout=0.01)


class TestTcpSocketErrnoMapping(_TcpSocketTestCase):
    """
    The 'TcpSocket' OSError errno-mapping tests.
    """

    def test__tcp_socket__bind_twice_carries_einval_errno(self) -> None:
        """
        Ensure 'bind()' on an already-bound TCP socket raises
        'OSError' with '.errno == errno.EINVAL'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(s._close_io_runtime)
        s.bind(("10.0.0.1", 8080))

        with self.assertRaises(OSError) as context:
            s.bind(("10.0.0.1", 8081))

        self.assertEqual(
            context.exception.errno,
            errno.EINVAL,
            msg="bind-twice OSError must carry errno=EINVAL.",
        )

    def test__tcp_socket__bind_foreign_ip_carries_eaddrnotavail_errno(self) -> None:
        """
        Ensure 'bind()' to a non-stack-owned IP raises 'OSError'
        with '.errno == errno.EADDRNOTAVAIL'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(s._close_io_runtime)

        with self.assertRaises(OSError) as context:
            s.bind(("192.168.99.99", 0))

        self.assertEqual(
            context.exception.errno,
            errno.EADDRNOTAVAIL,
            msg="foreign-IP bind OSError must carry errno=EADDRNOTAVAIL.",
        )

    def test__tcp_socket__bind_address_in_use_carries_eaddrinuse_errno(self) -> None:
        """
        Ensure 'bind()' to an in-use port raises 'OSError' with
        '.errno == errno.EADDRINUSE'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(first._close_io_runtime)
        first.bind(("10.0.0.1", 8080))

        second = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(second._close_io_runtime)

        with self.assertRaises(OSError) as context:
            second.bind(("10.0.0.1", 8080))

        self.assertEqual(
            context.exception.errno,
            errno.EADDRINUSE,
            msg="address-in-use bind OSError must carry errno=EADDRINUSE.",
        )

    def test__tcp_socket__send_no_destination_carries_epipe_errno(self) -> None:
        """
        Ensure 'send()' on a socket with no remote IP raises
        'BrokenPipeError' with '.errno == errno.EPIPE'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(s._close_io_runtime)
        s._tcp_session = MagicMock()

        with self.assertRaises(BrokenPipeError) as context:
            s.send(b"data")

        self.assertEqual(
            context.exception.errno,
            errno.EPIPE,
            msg="no-destination BrokenPipeError must carry errno=EPIPE.",
        )

    def test__tcp_socket__setsockopt_unknown_carries_enoprotoopt_errno(self) -> None:
        """
        Ensure 'setsockopt()' with an unknown (level, optname) pair
        raises 'OSError' with '.errno == errno.ENOPROTOOPT' so apps
        can branch on POSIX 'getsockopt(2)' semantics rather than
        message text.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(s._close_io_runtime)

        with self.assertRaises(OSError) as context:
            s.setsockopt(0, 9999, 1)

        self.assertEqual(
            context.exception.errno,
            errno.ENOPROTOOPT,
            msg="unknown setsockopt OSError must carry errno=ENOPROTOOPT.",
        )

    def test__tcp_socket__getsockopt_unknown_carries_enoprotoopt_errno(self) -> None:
        """
        Ensure 'getsockopt()' with an unknown (level, optname) pair
        raises 'OSError' with '.errno == errno.ENOPROTOOPT'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(s._close_io_runtime)

        with self.assertRaises(OSError) as context:
            s.getsockopt(0, 9999)

        self.assertEqual(
            context.exception.errno,
            errno.ENOPROTOOPT,
            msg="unknown getsockopt OSError must carry errno=ENOPROTOOPT.",
        )


class TestTcpSocketAcceptInheritsBlocking(_TcpSocketTestCase):
    """
    The 'TcpSocket.accept' child-inherits-parent-blocking tests.
    """

    def test__tcp_socket__accept_child_inherits_parent_blocking_default(self) -> None:
        """
        Ensure a child socket popped by 'accept()' inherits the
        parent listening socket's default 'blocking=True' flag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        parent = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(parent._close_io_runtime)

        child = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(child._close_io_runtime)
        child._remote_ip_address = Ip4Address("10.0.0.5")
        child._remote_port = 12345
        parent._tcp_accept.append(child)
        parent._event__tcp_session_established.release()
        parent._signal_readable()

        accepted, _ = parent.accept()

        self.assertTrue(
            cast(TcpSocket, accepted).getblocking(),
            msg="accept() child must inherit the parent's blocking=True default.",
        )

    def test__tcp_socket__recv_forwards_bufsize_as_byte_count_to_session(self) -> None:
        """
        Ensure 'recv(bufsize)' on a TCP socket forwards the bufsize
        argument as 'byte_count' to 'TcpSession.receive', so the
        session's slice-of-rx-buffer respects the caller's request.
        Pinning the contract guards against regressions where the
        socket facade silently drops or remaps the parameter.

        Reference: RFC 9293 §3.10.5 (RECEIVE call).
        """

        parent = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(parent._close_io_runtime)

        session = MagicMock()
        session.receive.return_value = b"abcd"
        parent._tcp_session = session
        parent._remote_ip_address = Ip4Address("10.0.0.5")
        parent._remote_port = 80

        result = parent.recv(bufsize=4)

        self.assertEqual(
            result,
            b"abcd",
            msg="recv(bufsize=4) must return the bytes the session yields.",
        )
        session.receive.assert_called_once_with(byte_count=4, timeout=None)

    def test__tcp_socket__accept_child_inherits_parent_blocking_false(self) -> None:
        """
        Ensure a child socket popped by 'accept()' inherits the
        parent listening socket's 'setblocking(False)' configuration
        — required so async frameworks that flip the listener also
        receive non-blocking children.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        parent = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(parent._close_io_runtime)
        parent.setblocking(False)

        child = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(child._close_io_runtime)
        child._remote_ip_address = Ip4Address("10.0.0.5")
        child._remote_port = 12345
        parent._tcp_accept.append(child)
        parent._event__tcp_session_established.release()
        parent._signal_readable()

        accepted, _ = parent.accept()

        self.assertFalse(
            cast(TcpSocket, accepted).getblocking(),
            msg="accept() child must inherit setblocking(False) from the parent.",
        )
