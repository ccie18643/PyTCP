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
Integration tests for the H5 row of the socket-layer Linux
parity audit ('docs/refactor/socket_linux_parity_audit.md'
§H5) — UDP sendto to a broadcast destination requires the
sender to have first enabled 'SO_BROADCAST' via setsockopt,
otherwise the send fails with 'OSError(EACCES)'. Matches
Linux's 'udp_sendmsg' broadcast gate (Linux net/ipv4/udp.c).

PyTCP's DHCPv4 client (the only in-tree consumer that sends
to '255.255.255.255' pre-lease) sets SO_BROADCAST on the
client socket explicitly before sending; that update lands
in the same commit so the gate doesn't break the lease
acquisition path.

pytcp/tests/integration/socket/test__socket__so_broadcast_gate.py

ver 3.0.8
"""

import errno

from net_addr import Ip4Address
from net_proto import IpProto
from pytcp import stack
from pytcp.runtime.socket import (
    SO_BROADCAST,
    SOL_SOCKET,
    AddressFamily,
    SocketType,
)
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.runtime.socket.udp__socket import UdpSocket
from pytcp.tests.lib.network_testcase import (
    STACK__IP4_HOST,
    NetworkTestCase,
)

STACK__IP: Ip4Address = STACK__IP4_HOST.address
# Subnet-directed broadcast of the stack's attached 10.0.1.0/24 network.
STACK__DIRECTED_BROADCAST: Ip4Address = STACK__IP4_HOST.network.broadcast

# Silence the SOCKET log channel for the whole module: RAW sockets log
# 'Closed socket' from 'addCleanup(close)' callbacks that fire AFTER the
# harness tearDown restores LOG__CHANNEL, leaking into the runner output.
# Module-level silencing spans every per-test cleanup (unit_testing.md
# §10a.4 / §11).
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence stack log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the production log-channel configuration.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


class TestSocketSoBroadcastGate(NetworkTestCase):
    """
    UDP 'sendto' to a limited-broadcast destination must
    have 'SO_BROADCAST' enabled first or fail with EACCES.
    """

    def test__udp_sendto_limited_broadcast_without_so_broadcast_raises_eaccess(self) -> None:
        """
        Ensure 'sendto' to '255.255.255.255' on a socket
        with 'SO_BROADCAST = 0' (the default) raises
        'OSError(EACCES)' — Linux's 'udp_sendmsg' broadcast
        gate. Apps that need to broadcast MUST enable the
        flag explicitly.

        Reference: Linux net/ipv4/udp.c udp_sendmsg (broadcast gate).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP), 0))

        with self.assertRaises(OSError) as ctx:
            sock.sendto(b"x", ("255.255.255.255", 67))
        self.assertEqual(
            ctx.exception.errno,
            errno.EACCES,
            msg="sendto to limited broadcast without SO_BROADCAST must raise EACCES.",
        )

    def test__udp_sendto_limited_broadcast_with_so_broadcast_succeeds(self) -> None:
        """
        Ensure 'sendto' to '255.255.255.255' on a socket
        with 'SO_BROADCAST = 1' succeeds — the gate only
        applies when the flag is unset.

        Reference: RFC 1122 §4.1.3.3 (UDP broadcast send).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP), 0))
        sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

        sent = sock.sendto(b"x", ("255.255.255.255", 67))

        self.assertEqual(
            sent,
            1,
            msg="sendto with SO_BROADCAST=1 must return the sent byte count.",
        )

    def test__udp_sendto_unicast_without_so_broadcast_succeeds(self) -> None:
        """
        Ensure 'sendto' to a unicast destination on a socket
        with 'SO_BROADCAST = 0' (default) is unaffected by
        the gate — regression pin so the broadcast check
        does NOT spuriously gate unicast traffic.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP), 0))

        sent = sock.sendto(b"x", ("10.0.1.91", 9999))

        self.assertEqual(
            sent,
            1,
            msg="sendto to a unicast peer must not be affected by SO_BROADCAST.",
        )

    def test__udp_connected_send_to_broadcast_without_so_broadcast_raises_eaccess(self) -> None:
        """
        Ensure 'send' on a socket connected to a broadcast
        peer (via 'connect((255.255.255.255, port))') with
        'SO_BROADCAST = 0' raises 'OSError(EACCES)' — the
        gate applies on the connected-socket send path too,
        matching Linux's per-send check.

        Reference: Linux net/ipv4/udp.c udp_sendmsg (broadcast gate).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP), 0))
        sock.connect(("255.255.255.255", 67))

        with self.assertRaises(OSError) as ctx:
            sock.send(b"x")
        self.assertEqual(
            ctx.exception.errno,
            errno.EACCES,
            msg="send on a broadcast-connected socket without SO_BROADCAST must raise EACCES.",
        )


class TestSocketSoBroadcastGateDirected(NetworkTestCase):
    """
    UDP 'sendto' / 'send' to a subnet-directed broadcast
    destination (the all-ones host of a directly-attached
    network, e.g. 10.0.1.255) must also have 'SO_BROADCAST'
    enabled first or fail with EACCES — Linux gates the
    directed broadcast exactly like the limited broadcast.
    """

    def test__udp_sendto_directed_broadcast_without_so_broadcast_raises_eaccess(self) -> None:
        """
        Ensure 'sendto' to a subnet-directed broadcast
        (10.0.1.255, the broadcast of the attached
        10.0.1.0/24 network) on a socket with
        'SO_BROADCAST = 0' raises 'OSError(EACCES)' — Linux
        marks the directed-broadcast route 'RTN_BROADCAST'
        and 'udp_sendmsg' requires the flag for it.

        Reference: Linux net/ipv4/udp.c udp_sendmsg (broadcast gate).
        Reference: Linux net/ipv4/route.c ip_route_output (RTN_BROADCAST).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP), 0))

        with self.assertRaises(OSError) as ctx:
            sock.sendto(b"x", (str(STACK__DIRECTED_BROADCAST), 9999))
        self.assertEqual(
            ctx.exception.errno,
            errno.EACCES,
            msg="sendto to a subnet-directed broadcast without SO_BROADCAST must raise EACCES.",
        )

    def test__udp_sendto_directed_broadcast_with_so_broadcast_succeeds(self) -> None:
        """
        Ensure 'sendto' to a subnet-directed broadcast on a
        socket with 'SO_BROADCAST = 1' succeeds — the gate
        only applies when the flag is unset.

        Reference: RFC 1122 §3.3.6 (directed broadcast send).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP), 0))
        sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

        sent = sock.sendto(b"x", (str(STACK__DIRECTED_BROADCAST), 9999))

        self.assertEqual(
            sent,
            1,
            msg="sendto to a directed broadcast with SO_BROADCAST=1 must return the sent byte count.",
        )

    def test__udp_connected_send_to_directed_broadcast_without_so_broadcast_raises_eaccess(self) -> None:
        """
        Ensure 'send' on a socket connected to a subnet-directed
        broadcast peer with 'SO_BROADCAST = 0' raises
        'OSError(EACCES)' — the gate applies on the connected
        send path too.

        Reference: Linux net/ipv4/udp.c udp_sendmsg (broadcast gate).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.bind((str(STACK__IP), 0))
        sock.connect((str(STACK__DIRECTED_BROADCAST), 9999))

        with self.assertRaises(OSError) as ctx:
            sock.send(b"x")
        self.assertEqual(
            ctx.exception.errno,
            errno.EACCES,
            msg="send on a directed-broadcast-connected socket without SO_BROADCAST must raise EACCES.",
        )


class TestSocketSoBroadcastGateRaw(NetworkTestCase):
    """
    RAW-socket 'sendto' / 'send' to an IPv4 broadcast destination
    must have 'SO_BROADCAST' enabled first or fail with EACCES —
    Linux gates raw broadcast in 'raw_sendmsg' exactly like UDP.
    """

    def _raw_socket(self) -> RawSocket:
        """
        Build an IPv4 RAW socket on an arbitrary experimental IANA
        protocol number (253, RFC 3692) so the send path exercises
        the broadcast gate without protocol-specific handling.
        """

        sock = RawSocket(family=AddressFamily.INET4, type=SocketType.RAW, protocol=IpProto.from_int(253))
        self.addCleanup(sock.close)
        return sock  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def test__raw_sendto_limited_broadcast_without_so_broadcast_raises_eaccess(self) -> None:
        """
        Ensure RAW 'sendto' to '255.255.255.255' on a socket with
        'SO_BROADCAST = 0' (the default) raises 'OSError(EACCES)'
        — the raw send path enforces the same broadcast gate as
        UDP.

        Reference: Linux net/ipv4/raw.c raw_sendmsg (broadcast gate).
        """

        sock = self._raw_socket()

        with self.assertRaises(OSError) as ctx:
            sock.sendto(b"x", ("255.255.255.255", 0))
        self.assertEqual(
            ctx.exception.errno,
            errno.EACCES,
            msg="RAW sendto to limited broadcast without SO_BROADCAST must raise EACCES.",
        )

    def test__raw_sendto_directed_broadcast_without_so_broadcast_raises_eaccess(self) -> None:
        """
        Ensure RAW 'sendto' to a subnet-directed broadcast
        (10.0.1.255) on a socket with 'SO_BROADCAST = 0' raises
        'OSError(EACCES)' — the directed-broadcast gate covers
        raw sends too.

        Reference: Linux net/ipv4/raw.c raw_sendmsg (broadcast gate).
        Reference: Linux net/ipv4/route.c ip_route_output (RTN_BROADCAST).
        """

        sock = self._raw_socket()

        with self.assertRaises(OSError) as ctx:
            sock.sendto(b"x", (str(STACK__DIRECTED_BROADCAST), 0))
        self.assertEqual(
            ctx.exception.errno,
            errno.EACCES,
            msg="RAW sendto to a directed broadcast without SO_BROADCAST must raise EACCES.",
        )

    def test__raw_sendto_broadcast_with_so_broadcast_succeeds(self) -> None:
        """
        Ensure RAW 'sendto' to a broadcast destination on a socket
        with 'SO_BROADCAST = 1' succeeds — the gate only applies
        when the flag is unset.

        Reference: RFC 1122 §3.3.6 (directed broadcast send).
        """

        sock = self._raw_socket()
        sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

        sent = sock.sendto(b"x", (str(STACK__DIRECTED_BROADCAST), 0))

        self.assertEqual(
            sent,
            1,
            msg="RAW sendto to a broadcast with SO_BROADCAST=1 must return the sent byte count.",
        )

    def test__raw_sendto_unicast_without_so_broadcast_succeeds(self) -> None:
        """
        Ensure RAW 'sendto' to a unicast destination on a socket
        with 'SO_BROADCAST = 0' (default) is unaffected by the
        gate — regression pin so the raw broadcast check does NOT
        spuriously gate unicast traffic.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._raw_socket()

        sent = sock.sendto(b"x", ("10.0.1.91", 0))

        self.assertEqual(
            sent,
            1,
            msg="RAW sendto to a unicast peer must not be affected by SO_BROADCAST.",
        )
