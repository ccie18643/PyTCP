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
This module contains the multi-homed-host interface-removal cascade
integration tests. On a running two-interface stack, removing the
second interface (the RTNETLINK 'RTM_DELLINK' control op) tears down
ONLY that interface's state — aborting the TCP sessions bound to its
addresses, dropping its addresses, and purging its egress routes —
while the boot interface and everything bound to it is left untouched.

pytcp/tests/integration/multi_interface/test__multi_interface__remove_cascade.py

ver 3.0.8
"""

from typing import cast
from unittest import TestCase
from unittest.mock import MagicMock, create_autospec

from net_addr import Ip4Address, Ip4IfAddr, Ip4Network, Ip6IfAddr, MacAddress
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import SysCall
from pytcp.runtime.fib import Route
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket import socket as SocketBase
from pytcp.socket.socket_id import SocketId
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import STACK__IP4_HOST

# Second interface — a distinct subnet from the harness boot interface
# (10.0.1.0/24 on interface 1).
IFACE2__MAC_ADDRESS = MacAddress("02:00:00:00:00:08")
IFACE2__IP4_HOST = Ip4IfAddr("10.0.2.7/24")
IFACE2__IP6_HOST = Ip6IfAddr("2001:db8:0:2::7/64")
IFACE2__PEER__IP4_ADDRESS = Ip4Address("10.0.2.91")
IFACE2__PEER__MAC_ADDRESS = MacAddress("02:00:00:00:00:98")


class _StubTcpSocket:
    """
    A minimal TCP socket stand-in exposing only the '_tcp_session'
    attribute the abort path reads.
    """

    def __init__(self, tcp_session: TcpSession) -> None:
        """
        Hold the supplied session spy so the abort path can reach it.
        """

        self._tcp_session = tcp_session


def _register_tcp_session(*, local_address: Ip4Address) -> MagicMock:
    """
    Register a stub TCP socket bound to 'local_address' on
    'stack.sockets' and return its session spy, so a later
    interface removal's abort sweep has a session to ABORT.
    """

    session = create_autospec(TcpSession, spec_set=True)
    socket_id = SocketId(
        address_family=AddressFamily.INET4,
        socket_type=SocketType.STREAM,
        local_address=local_address,
        local_port=49152,
        remote_address=Ip4Address("198.51.100.9"),
        remote_port=80,
    )
    stack.sockets[socket_id] = cast(SocketBase, _StubTcpSocket(cast(TcpSession, session)))
    return cast(MagicMock, session)


class TestMultiInterfaceRemoveCascade(IcmpTestCase, TestCase):
    """
    The multi-homed-host RTM_DELLINK interface-removal cascade tests.
    """

    def setUp(self) -> None:
        """
        Bring up the ICMP harness boot interface, mark the stack
        running (so the removal cascade fires), and attach a second L2
        interface on a distinct subnet via the reusable
        '_add_interface' helper. The base harness snapshots / restores
        'stack.interfaces', 'stack.stack_running' and 'stack.sockets'.
        """

        super().setUp()

        stack.stack_running = True
        self._iface2 = self._add_interface(
            mac_address=IFACE2__MAC_ADDRESS,
            ip4_host=IFACE2__IP4_HOST,
            ip6_host=IFACE2__IP6_HOST,
            arp_entries={IFACE2__PEER__IP4_ADDRESS: IFACE2__PEER__MAC_ADDRESS},
        )

    def test__remove_interface__aborts_only_removed_interface_sessions(self) -> None:
        """
        Ensure removing a running interface ABORTs every TCP session
        bound to one of its addresses (emitting RST) while a session
        bound to another interface's address is left established.

        Reference: RFC 5227 §2.4 final paragraph (host SHOULD actively reset connections on address loss).
        Reference: RFC 9293 §3.10.7.4 (ABORT emits RST and tears the session down).
        """

        removed_session = _register_tcp_session(local_address=IFACE2__IP4_HOST.address)
        surviving_session = _register_tcp_session(local_address=STACK__IP4_HOST.address)

        stack.remove_interface(self._iface2.ifindex)

        removed_session.tcp_fsm.assert_called_once_with(syscall=SysCall.ABORT)
        surviving_session.tcp_fsm.assert_not_called()

    def test__remove_interface__drops_only_removed_interface_addresses(self) -> None:
        """
        Ensure removing a running interface drops every address it
        carried while the boot interface keeps its own addresses — the
        per-interface address teardown is isolated to the removed NIC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        boot_handler = stack.interfaces[stack.STACK__DEFAULT_IFINDEX]
        boot_ip4_before = list(boot_handler._ip4_ifaddr)

        stack.remove_interface(self._iface2.ifindex)

        self.assertEqual(
            self._iface2.handler._ip4_ifaddr,
            [],
            msg="The removed interface must drop every IPv4 address.",
        )
        self.assertEqual(
            self._iface2.handler._ip6_ifaddr,
            [],
            msg="The removed interface must drop every IPv6 address.",
        )
        self.assertEqual(
            boot_handler._ip4_ifaddr,
            boot_ip4_before,
            msg="Removing the second interface must not touch the boot interface's addresses.",
        )

    def test__remove_interface__purges_only_removed_interface_routes(self) -> None:
        """
        Ensure removing a running interface purges the explicitly-
        installed FIB routes that egress it while routes egressing the
        boot interface survive.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        boot_route = Route(
            destination=Ip4Network("10.9.0.0/16"),
            gateway=Ip4Address("10.0.1.1"),
            oif=stack.STACK__DEFAULT_IFINDEX,
        )
        stack.ip4_fib.add(route=Route(destination=Ip4Network("10.0.2.0/24"), oif=self._iface2.ifindex))
        stack.ip4_fib.add(route=boot_route)

        stack.remove_interface(self._iface2.ifindex)

        self.assertEqual(
            stack.ip4_fib.snapshot(),
            (boot_route,),
            msg="remove_interface must purge only the routes egressing the removed interface.",
        )

    def test__remove_interface__deregisters_only_removed_interface(self) -> None:
        """
        Ensure removing a running interface deregisters it from
        'stack.interfaces' and returns its handler, while the boot
        interface stays registered.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        removed = stack.remove_interface(self._iface2.ifindex)

        self.assertIs(
            removed,
            self._iface2.handler,
            msg="remove_interface must return the removed interface's handler.",
        )
        self.assertNotIn(
            self._iface2.ifindex,
            stack.interfaces,
            msg="The removed interface must be deregistered from stack.interfaces.",
        )
        self.assertIn(
            stack.STACK__DEFAULT_IFINDEX,
            stack.interfaces,
            msg="The boot interface must survive the removal of a second interface.",
        )
