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

import json
from unittest import TestCase

from net_addr import Ip4Address, Ip4IfAddr, Ip4Network, Ip6Address, Ip6IfAddr, Ip6Network, MacAddress
from pytcp.cli.cli__format import (
    InterfaceView,
    flatten_sysctl,
    format_activity,
    format_addr,
    format_addr_json,
    format_link,
    format_neighbor_table,
    format_neighbor_table_json,
    format_route_table,
    format_route_table_json,
    format_socket_table,
    format_socket_table_json,
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

    def test__format_socket_table_json(self) -> None:
        """
        Ensure the socket table renders as a JSON array of one object per
        socket (netid / family / state / recv_q / send_q / local + peer
        address and port), an unconnected socket carrying 'UNCONN'.

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
        )

        self.assertEqual(
            json.loads(format_socket_table_json(snapshots)),
            [
                {
                    "netid": "tcp",
                    "family": "inet",
                    "state": "LISTEN",
                    "recv_q": 0,
                    "send_q": 0,
                    "local_address": "0.0.0.0",
                    "local_port": 80,
                    "peer_address": "0.0.0.0",
                    "peer_port": 0,
                }
            ],
            msg="The socket JSON must carry one object per socket with the ss columns as keys.",
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

    def test__format_neighbor_table_json(self) -> None:
        """
        Ensure neighbour entries render as a JSON array mirroring the 'ip
        -j neighbor' object shape (dst / lladdr / dev / state), an
        unresolved entry carrying a null 'lladdr'.

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
            json.loads(format_neighbor_table_json(entries)),
            [
                {"dst": "10.0.1.91", "lladdr": "02:00:00:00:00:91", "dev": "tap7", "state": "REACHABLE"},
                {"dst": "10.0.1.92", "lladdr": None, "dev": "tap7", "state": "INCOMPLETE"},
            ],
            msg="The neighbour JSON must mirror the 'ip -j neighbor' object shape.",
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

    def test__format_route_table_json(self) -> None:
        """
        Ensure routes render as a JSON array mirroring the 'ip -j route'
        object shape (family / dst / gateway / dev / prefsrc / metric /
        scope / protocol), the family inferred per route, a route with no
        gateway or prefsrc carrying null fields, and no egress interface
        rendering a null 'dev'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            json.loads(format_route_table_json(self._IP4_ROUTES, interface_names={1: "tap7"})),
            [
                {
                    "family": "inet",
                    "dst": "0.0.0.0/0",
                    "gateway": "10.0.1.1",
                    "dev": "tap7",
                    "prefsrc": None,
                    "metric": 0,
                    "scope": "universe",
                    "protocol": "static",
                },
                {
                    "family": "inet",
                    "dst": "10.0.1.0/24",
                    "gateway": None,
                    "dev": "tap7",
                    "prefsrc": "10.0.1.7",
                    "metric": 0,
                    "scope": "universe",
                    "protocol": "static",
                },
            ],
            msg="The route JSON must mirror the 'ip -j route' object shape with the family inferred.",
        )


class TestCliFormatSysctl(TestCase):
    """
    The 'sysctl' entry formatter golden tests.
    """

    def test__format_sysctl(self) -> None:
        """
        Ensure flat (non-interface) sysctl entries render as
        'key = value' lines.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_sysctl({"arp.cache.max_age": 60, "tcp.default.nodelay": False}),
            "arp.cache.max_age = 60\ntcp.default.nodelay = False",
            msg="Flat sysctl entries must render as 'key = value' lines.",
        )

    def test__format_sysctl__interface_scope_flattened(self) -> None:
        """
        Ensure an interface-scope knob's '{slot: value}' storage dict
        flattens to fully-qualified '<namespace>.<slot>.<field>' scalar
        lines — the 'default' template slot first, then each
        per-interface slot in sorted order — mirroring Linux
        'sysctl -a'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_sysctl({"arp.accept": {"default": 0, "tun3": 1, "tap7": 1}}),
            "arp.default.accept = 0\narp.tap7.accept = 1\narp.tun3.accept = 1",
            msg=(
                "Interface-scope knobs must flatten to one "
                "'<namespace>.<slot>.<field>' line per slot, 'default' first."
            ),
        )

    def test__format_sysctl__mixed_flat_and_interface_scope(self) -> None:
        """
        Ensure flat and interface-scope entries coexist in one render,
        each entry expanded in place so the dump order is preserved.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_sysctl(
                {
                    "arp.accept": {"default": 0, "tap7": 1},
                    "tcp.default.nodelay": False,
                },
            ),
            "arp.default.accept = 0\narp.tap7.accept = 1\ntcp.default.nodelay = False",
            msg="Mixed flat and interface-scope entries must each render in place.",
        )

    def test__flatten_sysctl__expands_interface_scope_to_scalar_map(self) -> None:
        """
        Ensure 'flatten_sysctl' expands an interface-scope storage dict
        into a '<namespace>.<slot>.<field>' -> value scalar map — the
        'default' template slot first, then per-interface slots sorted —
        and passes flat entries through unchanged. This is the map the
        CLI uses to recognise a directly-readable leaf.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            flatten_sysctl(
                {
                    "arp.accept": {"default": 0, "tun3": 1, "tap7": 1},
                    "tcp.default.nodelay": False,
                },
            ),
            {
                "arp.default.accept": 0,
                "arp.tap7.accept": 1,
                "arp.tun3.accept": 1,
                "tcp.default.nodelay": False,
            },
            msg="flatten_sysctl must expand interface-scope dicts and pass flat entries through.",
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

    def test__format_addr_json(self) -> None:
        """
        Ensure interfaces render as a JSON array mirroring the 'ip -j
        addr show' object shape (ifindex / ifname / flags / mtu / address
        + per-address 'addr_info' with family / local / prefixlen).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            json.loads(format_addr_json([self._VIEW])),
            [
                {
                    "ifindex": 1,
                    "ifname": "tap7",
                    "flags": ["BROADCAST", "MULTICAST", "UP"],
                    "mtu": 1500,
                    "address": "02:00:00:00:00:07",
                    "addr_info": [
                        {"family": "inet", "local": "10.0.1.7", "prefixlen": 24},
                        {"family": "inet6", "local": "2001:db8:0:1::7", "prefixlen": 64},
                    ],
                }
            ],
            msg="The addr JSON formatter must mirror the 'ip -j addr show' object shape.",
        )

    def test__format_addr_json__no_mac(self) -> None:
        """
        Ensure an interface with no MAC address renders a null 'address'
        field in the JSON output.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        view = InterfaceView(
            ifindex=2,
            name="lo",
            flags=("LOOPBACK", "UP"),
            mtu=65536,
            mac_address=None,
            addresses=(Ip4IfAddr("127.0.0.1/8"),),
        )
        self.assertIsNone(
            json.loads(format_addr_json([view]))[0]["address"],
            msg="An interface with no MAC must render a null 'address' field.",
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
