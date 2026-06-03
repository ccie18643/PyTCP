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

from net_addr import Ip4Address, Ip4IfAddr, Ip4Network, Ip6Address, Ip6IfAddr, Ip6Network, MacAddress
from pytcp.cli.cli__format import (
    InterfaceView,
    format_activity,
    format_addr,
    format_link,
    format_neighbor_table,
    format_route_table,
    format_socket_table,
    format_sysctl,
)
from pytcp.lib.neighbor import NudState
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.fib import Route
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.stack.activity_introspect import InterfaceActivity
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
        Ensure neighbour entries render in the route-style table layout —
        the Address / Link-Layer Address / State / Device columns, with
        the Device naming the interface each entry was learned on, and an
        empty link-layer column for an unresolved entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        entries = (
            (
                NeighborSnapshot(
                    address=Ip4Address("10.0.1.91"),
                    mac_address=MacAddress("02:00:00:00:00:91"),
                    state=NudState.REACHABLE,
                ),
                "tap7",
            ),
            (
                NeighborSnapshot(
                    address=Ip4Address("10.0.1.92"),
                    mac_address=None,
                    state=NudState.INCOMPLETE,
                ),
                "tap7",
            ),
        )

        self.assertEqual(
            format_neighbor_table(entries),
            "Address                        Link-Layer Address  State       Device\n"
            "10.0.1.91                      02:00:00:00:00:91   REACHABLE   tap7\n"
            "10.0.1.92                                          INCOMPLETE  tap7",
            msg="The neighbour table must render in the route-style column layout.",
        )


class TestCliFormatRoutes(TestCase):
    """
    The net-tools 'route' route-table formatter golden tests.
    """

    _IP4_ROUTES = (
        Route(destination=Ip4Network("0.0.0.0/0"), gateway=Ip4Address("10.0.1.1"), oif=1),
        Route(destination=Ip4Network("10.0.1.0/24"), prefsrc=Ip4Address("10.0.1.7"), oif=1),
    )

    def test__format_route_table__ipv4(self) -> None:
        """
        Ensure the IPv4 routing table renders in the net-tools 'route'
        unified layout: the Destination (CIDR) / Gateway / Flags / Metric /
        Ref / Use / Iface columns, the default route rendered as '0.0.0.0/0', a connected route's
        gateway shown as 0.0.0.0, and the egress interface name.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_route_table(self._IP4_ROUTES, family=AddressFamily.INET4, interface_names={1: "tap7"}),
            "Destination                    Gateway                    Flags Metric Ref   Use Iface\n"
            "0.0.0.0/0                      10.0.1.1                   UG         0   0     0 tap7\n"
            "10.0.1.0/24                    0.0.0.0                    U          0   0     0 tap7",
            msg="The IPv4 route table must render in the net-tools 'route' layout.",
        )

    def test__format_route_table__ipv6(self) -> None:
        """
        Ensure the IPv6 routing table renders in the net-tools 'route -6'
        unified layout: the Destination (CIDR) / Gateway / Flags / Metric /
        Ref / Use / Iface columns shared with IPv4, the default route
        rendered as '::/0', and the egress interface name.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        routes = (
            Route(destination=Ip6Network("::/0"), gateway=Ip6Address("fe80::1"), oif=2),
            Route(
                destination=Ip6Network("2603:808c:2800:4301::/64"), prefsrc=Ip6Address("2603:808c:2800:4301::5"), oif=2
            ),
        )

        self.assertEqual(
            format_route_table(routes, family=AddressFamily.INET6, interface_names={2: "tap9"}),
            "Destination                    Gateway                    Flags Metric Ref   Use Iface\n"
            "::/0                           fe80::1                    UG         0   0     0 tap9\n"
            "2603:808c:2800:4301::/64       ::                         U          0   0     0 tap9",
            msg="The IPv6 route table must render in the net-tools 'route -6' layout.",
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


class TestCliFormatInterfaces(TestCase):
    """
    The 'ip addr' / 'ip link' interface formatter golden tests.
    """

    _VIEW = InterfaceView(
        ifindex=1,
        name="tap7",
        flags=("BROADCAST", "MULTICAST", "UP"),
        mtu=1500,
        mac_address=MacAddress("02:00:00:00:00:07"),
        addresses=(Ip4IfAddr("10.0.1.7/24"), Ip6IfAddr("2001:db8:0:1::7/64")),
    )

    def test__format_addr(self) -> None:
        """
        Ensure interfaces render with their addresses in the 'ip addr
        show' layout.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_addr([self._VIEW]),
            "1: tap7: <BROADCAST,MULTICAST,UP> mtu 1500\n"
            "    link/ether 02:00:00:00:00:07\n"
            "    inet 10.0.1.7/24\n"
            "    inet6 2001:db8:0:1::7/64",
            msg="The addr formatter must render the interface with its inet / inet6 addresses.",
        )

    def test__format_link(self) -> None:
        """
        Ensure interfaces render without addresses in the 'ip link show'
        layout.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_link([self._VIEW]),
            "1: tap7: <BROADCAST,MULTICAST,UP> mtu 1500\n    link/ether 02:00:00:00:00:07",
            msg="The link formatter must render the interface without addresses.",
        )


class TestCliFormatActivity(TestCase):
    """
    The 'format_activity' tests.
    """

    def test__format_activity(self) -> None:
        """
        Ensure format_activity renders each active interface's DHCPv4 state
        and DAD-in-progress addresses, skipping interfaces with no activity.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        activities = (
            InterfaceActivity(ifindex=1, name="tap7", dhcp4_state="BOUND", tentative_ip6=()),
            InterfaceActivity(
                ifindex=2,
                name="tap9",
                dhcp4_state="SELECTING",
                tentative_ip6=(Ip6Address("2603:808c::5"),),
            ),
            InterfaceActivity(ifindex=3, name="tun3", dhcp4_state=None, tentative_ip6=()),
        )

        self.assertEqual(
            format_activity(activities),
            "Activity:\n  tap7: dhcp4 BOUND\n  tap9: dhcp4 SELECTING; tentative 2603:808c::5",
            msg="format_activity must render dhcp4 state + tentative addresses and skip idle interfaces.",
        )

    def test__format_activity__empty_when_idle(self) -> None:
        """
        Ensure format_activity returns an empty string when no interface has
        ongoing activity, so the status section is skipped entirely.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_activity((InterfaceActivity(ifindex=3, name="tun3", dhcp4_state=None, tentative_ip6=()),)),
            "",
            msg="format_activity must return '' when nothing is active.",
        )
