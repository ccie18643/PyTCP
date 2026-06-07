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
Unit tests for the in-process socket factory's ICMP Echo ('ping') dispatch.

Pins that the BSD 'socket()' factory routes 'SOCK_DGRAM' + 'IPPROTO_ICMP'
/ 'IPPROTO_ICMPV6' to a 'PingSocket' (both families), that the resulting
object is a genuine 'socket' ABC subclass, and that the base-class surface
it inherits is honest -- the family / type / proto / port introspection
properties and 'fileno()' return sane values instead of crashing on
attributes the socket never set.

pytcp/tests/unit/socket/test__socket__ping_factory.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_proto import IpProto
from pytcp import stack
from pytcp.runtime.socket import (
    IPPROTO_ICMP,
    IPPROTO_ICMPV6,
    AddressFamily,
    SocketType,
)
from pytcp.runtime.socket import socket as pytcp_socket
from pytcp.runtime.socket.ping__socket import PingSocket


class TestSocketPingFactory(TestCase):
    """
    The in-process socket-factory ICMP Echo dispatch tests.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot and clear the ping-socket registry and silence the
        socket-channel lifecycle logging.
        """

        self._registry_prior = dict(stack.icmp_echo_sockets)
        stack.icmp_echo_sockets.clear()
        self.addCleanup(self._restore_registry)
        self.enterContext(patch("pytcp.runtime.socket.ping__socket.log"))

    def _restore_registry(self) -> None:
        """
        Restore the ping-socket registry to its pre-test contents.
        """

        stack.icmp_echo_sockets.clear()
        stack.icmp_echo_sockets.update(self._registry_prior)

    def test__factory__inet4_icmp_dgram_builds_ping_socket(self) -> None:
        """
        Ensure 'socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)' builds a
        'PingSocket' bound to the ICMPv4 protocol.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket(AddressFamily.INET4, SocketType.DGRAM, IPPROTO_ICMP)
        self.addCleanup(sock.close)

        self.assertIsInstance(sock, PingSocket, msg="DGRAM + IPPROTO_ICMP must dispatch to a PingSocket.")
        self.assertIs(sock.proto, IpProto.ICMP4, msg="An IPv4 ping socket must carry the ICMPv4 protocol.")

    def test__factory__inet6_icmpv6_dgram_builds_ping_socket(self) -> None:
        """
        Ensure 'socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)' builds a
        'PingSocket' bound to the ICMPv6 protocol.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket(AddressFamily.INET6, SocketType.DGRAM, IPPROTO_ICMPV6)
        self.addCleanup(sock.close)

        self.assertIsInstance(sock, PingSocket, msg="DGRAM + IPPROTO_ICMPV6 must dispatch to a PingSocket.")
        self.assertIs(sock.proto, IpProto.ICMP6, msg="An IPv6 ping socket must carry the ICMPv6 protocol.")

    def test__factory__ping_socket_is_a_socket_subclass(self) -> None:
        """
        Ensure the factory-built ping socket is a genuine 'socket' ABC
        subclass so the BSD factory's '__new__' dispatch initialises it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket(AddressFamily.INET4, SocketType.DGRAM, IPPROTO_ICMP)
        self.addCleanup(sock.close)

        self.assertIsInstance(
            sock,
            pytcp_socket,
            msg="A ping socket must be a 'socket' ABC subclass for the factory to initialise it.",
        )

    def test__factory__ping_socket_inherited_introspection_is_honest(self) -> None:
        """
        Ensure the base-class introspection surface a ping socket inherits
        returns sane values instead of raising on attributes the socket
        never set -- family / type / proto, the ICMP-id-as-port, and a
        selectable 'fileno'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket(AddressFamily.INET4, SocketType.DGRAM, IPPROTO_ICMP)
        self.addCleanup(sock.close)
        assert isinstance(sock, PingSocket)

        self.assertIs(sock.family, AddressFamily.INET4, msg="Inherited 'family' must report the socket family.")
        self.assertIs(sock.type, SocketType.DGRAM, msg="Inherited 'type' must report SOCK_DGRAM.")
        self.assertEqual(sock.local_port, sock.echo_id, msg="The ICMP id must surface as the local port.")
        self.assertEqual(sock.remote_port, 0, msg="An unconnected ping socket must report remote port 0.")
        self.assertIsInstance(sock.fileno(), int, msg="A ping socket must expose a selectable 'fileno'.")
