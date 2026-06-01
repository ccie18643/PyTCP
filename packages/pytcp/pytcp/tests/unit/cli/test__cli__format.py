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
This module contains golden tests for the CLI output formatters.

pytcp/tests/unit/cli/test__cli__format.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip4Network, MacAddress
from pytcp.cli.cli__format import (
    format_neighbor_table,
    format_route_table,
    format_socket_table,
    format_sysctl,
)
from pytcp.lib.neighbor import NudState
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.fib import Route, RouteProtocol, RouteScope
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.stack.neighbor import NeighborSnapshot
from pytcp.stack.socket_introspect import SocketSnapshot


class TestCliFormatSockets(TestCase):
    """
    The 'ss' socket-table formatter golden tests.
    """

    def test__format_socket_table(self) -> None:
        """
        Ensure the socket table renders a listening TCP socket and a bound
        UDP socket in the aligned 'ss -tuln' layout.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshots = (
            SocketSnapshot(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
                local_address=Ip4Address("0.0.0.0"),
                local_port=80,
                remote_address=Ip4Address("0.0.0.0"),
                remote_port=0,
                state=FsmState.LISTEN,
                rx_queue=0,
                tx_queue=0,
            ),
            SocketSnapshot(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.DGRAM,
                local_address=Ip4Address("0.0.0.0"),
                local_port=4444,
                remote_address=Ip4Address("0.0.0.0"),
                remote_port=0,
                state=None,
                rx_queue=0,
                tx_queue=0,
            ),
        )

        self.assertEqual(
            format_socket_table(snapshots),
            "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n"
            "tcp    LISTEN  0       0       0.0.0.0:80          0.0.0.0:*\n"
            "udp    UNCONN  0       0       0.0.0.0:4444        0.0.0.0:*",
            msg="The socket table must render in the aligned ss -tuln layout.",
        )


class TestCliFormatNeighbors(TestCase):
    """
    The 'ip neighbor' neighbour-table formatter golden tests.
    """

    def test__format_neighbor_table(self) -> None:
        """
        Ensure neighbour entries render in the 'ip neighbor show' line
        layout, with and without a link-layer address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshots = (
            NeighborSnapshot(
                address=Ip4Address("10.0.1.91"),
                mac_address=MacAddress("02:00:00:00:00:91"),
                state=NudState.REACHABLE,
            ),
            NeighborSnapshot(
                address=Ip4Address("10.0.1.92"),
                mac_address=None,
                state=NudState.INCOMPLETE,
            ),
        )

        self.assertEqual(
            format_neighbor_table(snapshots),
            "10.0.1.91 lladdr 02:00:00:00:00:91 REACHABLE\n10.0.1.92 INCOMPLETE",
            msg="The neighbour table must render in the ip neighbor show layout.",
        )


class TestCliFormatRoutes(TestCase):
    """
    The 'ip route' route-table formatter golden tests.
    """

    def test__format_route_table(self) -> None:
        """
        Ensure routes render in the 'ip route show' line layout, with the
        default route collapsed to 'default'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        routes = (
            Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=Ip4Address("10.0.1.1"),
                scope=RouteScope.UNIVERSE,
                protocol=RouteProtocol.STATIC,
                oif=1,
            ),
            Route(
                destination=Ip4Network("10.0.1.0/24"),
                scope=RouteScope.LINK,
                protocol=RouteProtocol.KERNEL,
                prefsrc=Ip4Address("10.0.1.7"),
                oif=1,
            ),
        )

        self.assertEqual(
            format_route_table(routes),
            "default via 10.0.1.1 dev if1 scope universe proto static\n"
            "10.0.1.0/24 dev if1 scope link proto kernel src 10.0.1.7",
            msg="The route table must render in the ip route show layout.",
        )


class TestCliFormatSysctl(TestCase):
    """
    The 'sysctl' entry formatter golden tests.
    """

    def test__format_sysctl(self) -> None:
        """
        Ensure sysctl entries render as 'key = value' lines.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_sysctl({"arp.cache.max_age": 60, "tcp.default.nodelay": False}),
            "arp.cache.max_age = 60\ntcp.default.nodelay = False",
            msg="Sysctl entries must render as 'key = value' lines.",
        )
