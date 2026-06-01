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

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.stack.socket_introspect import SocketSnapshot, build_socket_snapshots


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
