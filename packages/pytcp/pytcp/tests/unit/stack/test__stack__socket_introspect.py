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
This module contains tests for the socket-list introspection core.

pytcp/tests/unit/stack/test__stack__socket_introspect.py

ver 3.0.8
"""

import inspect
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.stack.socket_introspect import (
    SocketIntrospectApi,
    SocketSnapshot,
    build_socket_snapshots,
)


class _FakeStatus:
    """
    A minimal TCP-status stand-in carrying only the queue counts.
    """

    def __init__(self, *, rx_buffer_len: int, tx_buffer_len: int) -> None:
        self.rx_buffer_len = rx_buffer_len
        self.tx_buffer_len = tx_buffer_len


class _FakeUdpSocket:
    """
    A UDP-like socket double (no FSM state, no buffer accounting).
    """

    def __init__(
        self,
        *,
        address_family: AddressFamily,
        local_address: Ip4Address | Ip6Address,
        local_port: int,
        remote_address: Ip4Address | Ip6Address,
        remote_port: int,
    ) -> None:
        self.address_family = address_family
        self.socket_type = SocketType.DGRAM
        self.local_ip_address = local_address
        self.local_port = local_port
        self.remote_ip_address = remote_address
        self.remote_port = remote_port


class _FakeTcpSocket:
    """
    A TCP-like socket double with FSM state and queue accounting.
    """

    def __init__(
        self,
        *,
        local_address: Ip4Address | Ip6Address,
        local_port: int,
        remote_address: Ip4Address | Ip6Address,
        remote_port: int,
        state: FsmState,
        rx_queue: int = 0,
        tx_queue: int = 0,
    ) -> None:
        self.address_family = AddressFamily.INET4
        self.socket_type = SocketType.STREAM
        self.local_ip_address = local_address
        self.local_port = local_port
        self.remote_ip_address = remote_address
        self.remote_port = remote_port
        self.state = state
        self._status = _FakeStatus(rx_buffer_len=rx_queue, tx_buffer_len=tx_queue)

    def status(self) -> _FakeStatus:
        """
        Return the TCP status carrying the queue counts.
        """

        return self._status


class TestBuildSocketSnapshots(TestCase):
    """
    The socket-snapshot building / filtering tests.
    """

    def test__build__maps_tcp_socket_fields(self) -> None:
        """
        Ensure a TCP socket maps to a snapshot carrying its FSM state and
        queue counts.

        Reference: RFC 9293 §3.3.2 (TCP connection state).
        """

        sock = _FakeTcpSocket(
            local_address=Ip4Address("10.0.1.7"),
            local_port=50000,
            remote_address=Ip4Address("10.0.1.91"),
            remote_port=80,
            state=FsmState.ESTABLISHED,
            rx_queue=12,
            tx_queue=34,
        )

        self.assertEqual(
            build_socket_snapshots([sock]),
            (
                SocketSnapshot(
                    address_family=AddressFamily.INET4,
                    socket_type=SocketType.STREAM,
                    local_address=Ip4Address("10.0.1.7"),
                    local_port=50000,
                    remote_address=Ip4Address("10.0.1.91"),
                    remote_port=80,
                    state=FsmState.ESTABLISHED,
                    rx_queue=12,
                    tx_queue=34,
                ),
            ),
            msg="A TCP socket must map to a snapshot with its state and queue counts.",
        )

    def test__build__maps_udp_socket_with_no_state(self) -> None:
        """
        Ensure a UDP socket maps to a snapshot with no FSM state and zero
        queue counts.

        Reference: RFC 768 (UDP — connectionless datagram socket).
        """

        sock = _FakeUdpSocket(
            address_family=AddressFamily.INET4,
            local_address=Ip4Address("0.0.0.0"),
            local_port=4444,
            remote_address=Ip4Address("0.0.0.0"),
            remote_port=0,
        )

        snapshot = build_socket_snapshots([sock])[0]

        self.assertEqual(
            (snapshot.state, snapshot.rx_queue, snapshot.tx_queue),
            (None, 0, 0),
            msg="A UDP socket must map to a snapshot with no state and zero queues.",
        )

    def test__build__filters_by_family(self) -> None:
        """
        Ensure the family filter selects only sockets of the requested
        address family.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        v4 = _FakeUdpSocket(
            address_family=AddressFamily.INET4,
            local_address=Ip4Address("0.0.0.0"),
            local_port=1,
            remote_address=Ip4Address("0.0.0.0"),
            remote_port=0,
        )
        v6 = _FakeUdpSocket(
            address_family=AddressFamily.INET6,
            local_address=Ip6Address("::"),
            local_port=2,
            remote_address=Ip6Address("::"),
            remote_port=0,
        )

        result = build_socket_snapshots([v4, v6], family=AddressFamily.INET6)

        self.assertEqual(
            tuple(snapshot.address_family for snapshot in result),
            (AddressFamily.INET6,),
            msg="The family filter must select only the requested address family.",
        )

    def test__build__listening_only_selects_listeners(self) -> None:
        """
        Ensure the listening filter selects TCP LISTEN sockets and
        unconnected datagram sockets, excluding connected TCP sockets.

        Reference: RFC 9293 §3.3.2 (LISTEN state).
        """

        listener = _FakeTcpSocket(
            local_address=Ip4Address("0.0.0.0"),
            local_port=80,
            remote_address=Ip4Address("0.0.0.0"),
            remote_port=0,
            state=FsmState.LISTEN,
        )
        established = _FakeTcpSocket(
            local_address=Ip4Address("10.0.1.7"),
            local_port=50000,
            remote_address=Ip4Address("10.0.1.91"),
            remote_port=80,
            state=FsmState.ESTABLISHED,
        )
        bound_udp = _FakeUdpSocket(
            address_family=AddressFamily.INET4,
            local_address=Ip4Address("0.0.0.0"),
            local_port=4444,
            remote_address=Ip4Address("0.0.0.0"),
            remote_port=0,
        )

        result = build_socket_snapshots([listener, established, bound_udp], listening_only=True)

        self.assertEqual(
            {(snapshot.socket_type, snapshot.local_port) for snapshot in result},
            {(SocketType.STREAM, 80), (SocketType.DGRAM, 4444)},
            msg="The listening filter must keep the TCP listener and the unconnected UDP socket only.",
        )

    def test__build__sorts_deterministically(self) -> None:
        """
        Ensure the snapshots are returned in a deterministic order
        regardless of input order.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        high = _FakeUdpSocket(
            address_family=AddressFamily.INET4,
            local_address=Ip4Address("0.0.0.0"),
            local_port=9000,
            remote_address=Ip4Address("0.0.0.0"),
            remote_port=0,
        )
        low = _FakeUdpSocket(
            address_family=AddressFamily.INET4,
            local_address=Ip4Address("0.0.0.0"),
            local_port=1000,
            remote_address=Ip4Address("0.0.0.0"),
            remote_port=0,
        )

        result = build_socket_snapshots([high, low])

        self.assertEqual(
            tuple(snapshot.local_port for snapshot in result),
            (1000, 9000),
            msg="Snapshots must be returned sorted by local port regardless of input order.",
        )


class TestSocketIntrospectApi__KeywordOnlySignatures(TestCase):
    """
    Pin the keyword-only parameters on SocketIntrospectApi.list_sockets
    so the '*'→'/' separator mutation is caught.
    """

    def test__socket_introspect__list_sockets_is_keyword_only(self) -> None:
        """
        Ensure SocketIntrospectApi.list_sockets keeps family /
        socket_type / listening_only keyword-only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        params = inspect.signature(SocketIntrospectApi.list_sockets).parameters
        kw_only = {name for name, param in params.items() if param.kind is inspect.Parameter.KEYWORD_ONLY}
        self.assertEqual(
            kw_only,
            {"family", "socket_type", "listening_only"},
            msg="SocketIntrospectApi.list_sockets must keep its parameters keyword-only.",
        )


class _FakeStatusNoBuffers:
    """A status double that lacks the rx/tx buffer-length attributes."""


class _FakeNoBufferSocket:
    """A TCP-like socket whose status() carries no queue-length fields."""

    def __init__(self) -> None:
        self.address_family = AddressFamily.INET4
        self.socket_type = SocketType.STREAM
        self.local_ip_address = Ip4Address("0.0.0.0")
        self.local_port = 80
        self.remote_ip_address = Ip4Address("0.0.0.0")
        self.remote_port = 0
        self.state = FsmState.LISTEN

    def status(self) -> _FakeStatusNoBuffers:
        """Return a status object with no buffer-length attributes."""

        return _FakeStatusNoBuffers()


class TestBuildSocketSnapshots__MutationGoldens(TestCase):
    """
    Branch and default-value goldens closing the build_socket_snapshots
    filter / queue-accounting mutation survivors.
    """

    def test__build__listening_only_excludes_connected_udp(self) -> None:
        """
        Ensure the listening filter excludes a CONNECTED datagram socket
        (remote_port != 0): the non-TCP listening test is exactly
        'remote_port == 0', so a '>=' edit would wrongly keep a
        connected UDP socket.

        Reference: RFC 768 (UDP — a connected datagram socket is not listening).
        """

        unconnected = _FakeUdpSocket(
            address_family=AddressFamily.INET4,
            local_address=Ip4Address("0.0.0.0"),
            local_port=1000,
            remote_address=Ip4Address("0.0.0.0"),
            remote_port=0,
        )
        connected = _FakeUdpSocket(
            address_family=AddressFamily.INET4,
            local_address=Ip4Address("0.0.0.0"),
            local_port=2000,
            remote_address=Ip4Address("10.0.0.1"),
            remote_port=80,
        )

        result = build_socket_snapshots([unconnected, connected], listening_only=True)

        self.assertEqual(
            tuple(snapshot.local_port for snapshot in result),
            (1000,),
            msg="listening_only must keep the unconnected UDP (1000) and drop the connected one (2000).",
        )

    def test__build__family_filter_continues_past_skipped_socket(self) -> None:
        """
        Ensure the family filter continues scanning after skipping a
        non-matching socket: a leading IPv6 socket must not break the
        loop and drop a later IPv4 match (kills 'continue'→'break').

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        v6 = _FakeUdpSocket(
            address_family=AddressFamily.INET6,
            local_address=Ip6Address("::"),
            local_port=500,
            remote_address=Ip6Address("::"),
            remote_port=0,
        )
        v4 = _FakeUdpSocket(
            address_family=AddressFamily.INET4,
            local_address=Ip4Address("0.0.0.0"),
            local_port=1000,
            remote_address=Ip4Address("0.0.0.0"),
            remote_port=0,
        )

        result = build_socket_snapshots([v6, v4], family=AddressFamily.INET4)

        self.assertEqual(
            tuple(snapshot.local_port for snapshot in result),
            (1000,),
            msg="the IPv6 socket must be skipped (continue), not break, keeping the IPv4 match.",
        )

    def test__build__queues_default_to_zero_without_buffer_fields(self) -> None:
        """
        Ensure the queue accounting falls back to 0 when the socket's
        status object lacks the buffer-length attributes (the getattr
        default), pinning the literal 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshot = build_socket_snapshots([_FakeNoBufferSocket()])[0]

        self.assertEqual(
            (snapshot.rx_queue, snapshot.tx_queue),
            (0, 0),
            msg="a status object without buffer fields must yield (0, 0) queue counts.",
        )
