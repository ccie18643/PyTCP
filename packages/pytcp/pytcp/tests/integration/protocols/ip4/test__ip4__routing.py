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
This module contains the host-mode routing-table integration
tests. Phase 1 pins the harness wiring + FIB per-test isolation;
Phases 2 / 5 add the next-hop and static-route scenarios.

pytcp/tests/integration/protocols/ip4/test__ip4__routing.py

ver 3.0.9
"""

from typing import cast
from unittest.mock import MagicMock

from net_addr import Ip4Address, Ip4IfAddr, Ip4Network, Ip6Network, MacAddress
from pytcp import stack
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.runtime.socket import AddressFamily
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_GATEWAY,
    STACK__IP4_GATEWAY_MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_GATEWAY,
    NetworkTestCase,
)

# Static-route fixture — a non-default prefix reached via a
# second on-link router (Linux 'ip route add 10.9.0.0/16 via
# 10.0.1.254').
_STATIC_NET = Ip4Network("10.9.0.0/16")
_STATIC_GW = Ip4Address("10.0.1.254")
_STATIC_GW__MAC = MacAddress("02:00:00:00:00:fe")
_DST_IN_STATIC = Ip4Address("10.9.1.1")
_DST_DEFAULT_ONLY = Ip4Address("8.8.8.8")

# Second interface address for the multihoming pin — a host
# with a working ARP entry on a subnet that is NOT the source
# address's subnet.
_IFADDR_B = Ip4IfAddr("10.0.2.7/24")
_DST_ON_B = Ip4Address("10.0.2.50")
_DST_ON_B__MAC = MacAddress("02:00:00:00:00:50")

_FIXTURE_IP4_DEFAULT = Route(
    destination=Ip4Network("0.0.0.0/0"),
    gateway=STACK__IP4_GATEWAY,
    protocol=RouteProtocol.BOOT,
)
_FIXTURE_IP6_DEFAULT = Route(
    destination=Ip6Network("::/0"),
    gateway=STACK__IP6_GATEWAY,
    protocol=RouteProtocol.BOOT,
)


class TestIp4RoutingHarnessWiring(NetworkTestCase):
    """
    The host-mode FIB harness-wiring and isolation tests.
    """

    def test__ip4__routing__harness_installs_fixture_default_routes(self) -> None:
        """
        Ensure the integration harness exposes the read-only
        Route API and that it reports exactly the fixture
        default routes the topology pre-installs. The
        auto-synthesized on-link connected routes (protocol
        KERNEL) are filtered out so the assertion stays focused
        on the FIB-installed default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            tuple(
                route
                for route in stack.route.list_routes(family=AddressFamily.INET4)
                if route.protocol is not RouteProtocol.KERNEL
            ),
            (_FIXTURE_IP4_DEFAULT,),
            msg="Harness must pre-install exactly the IPv4 fixture default route.",
        )
        self.assertEqual(
            tuple(
                route
                for route in stack.route.list_routes(family=AddressFamily.INET6)
                if route.protocol is not RouteProtocol.KERNEL
            ),
            (_FIXTURE_IP6_DEFAULT,),
            msg="Harness must pre-install exactly the IPv6 fixture default route.",
        )

    def test__ip4__routing__fib_is_isolated_across_tests_a(self) -> None:
        """
        Ensure every test starts with a freshly-rebuilt FIB
        holding only the fixture default route, then mutates it;
        the mutation must not leak into the sibling test.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            stack.ip4_fib.snapshot(),
            (_FIXTURE_IP4_DEFAULT,),
            msg="FIB must start each test with only the fixture default route.",
        )

        stack.ip4_fib.add(
            route=Route(
                destination=Ip4Network("10.9.0.0/16"),
                gateway=STACK__IP4_GATEWAY,
                protocol=RouteProtocol.STATIC,
            )
        )

        self.assertEqual(
            len(stack.ip4_fib.snapshot()),
            2,
            msg="The in-test mutation must be visible within this test.",
        )

    def test__ip4__routing__fib_is_isolated_across_tests_b(self) -> None:
        """
        Ensure the sibling test's FIB mutation did not leak into
        this test — proving 'mock__init' rebuilds the FIBs fresh
        per test.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            stack.ip4_fib.snapshot(),
            (_FIXTURE_IP4_DEFAULT,),
            msg="Sibling test's static route must not leak into this test's FIB.",
        )


def _eth_dst(frame: bytes) -> MacAddress:
    """
    Extract the Ethernet II destination MAC (first 6 octets).
    """

    return MacAddress(frame[0:6])


class TestIp4RoutingNextHop(NetworkTestCase):
    """
    The host-mode FIB IPv4 next-hop decision tests.
    """

    def test__ip4__routing__multihomed_on_link_dst_resolved_directly(self) -> None:
        """
        Ensure an IPv4 destination that is on-link for a
        different interface address than the packet's source
        address is resolved directly (its own MAC), not via the
        default gateway. This is the destination-keyed,
        Linux-correct result and a deliberate behaviour change
        from the prior source-address-coupled next-hop scan.

        Reference: RFC 1122 §3.3.1 (next-hop selection / longest-prefix match).
        Reference: RFC 1122 §3.3.4.1 (multihoming — routing is destination-keyed).
        """

        self._packet_handler._ip4_ifaddr = [STACK__IP4_HOST, _IFADDR_B]

        def _arp(*, ip4_address: Ip4Address) -> MacAddress | None:
            return {
                _DST_ON_B: _DST_ON_B__MAC,
                STACK__IP4_GATEWAY: STACK__IP4_GATEWAY_MAC_ADDRESS,
            }.get(ip4_address)

        # The harness binds 'self._arp_cache' to a strict
        # autospec mock; the cast surfaces the test-time mock
        # type to mypy (typing.md §17 — test-time type fact mypy
        # cannot model through the harness swap).
        cast(MagicMock, self._arp_cache).find_entry.side_effect = _arp

        status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=_DST_ON_B,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="On-link multihomed destination must be sent, not dropped.",
        )
        self.assertEqual(
            _eth_dst(self._frames_tx[0]),
            _DST_ON_B__MAC,
            msg="On-link destination must resolve to its own MAC, not the gateway MAC.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send,
            1,
            msg="Multihomed on-link destination must take the locnet (direct) path.",
        )

    def test__ip4__routing__off_link_dst_resolved_via_default_gateway(self) -> None:
        """
        Ensure an IPv4 destination matched only by the default
        route is resolved via that route's gateway MAC.

        Reference: RFC 1122 §3.3.1 (next-hop selection / default route).
        """

        status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=_DST_ON_B,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Off-link destination with a default route must be sent.",
        )
        self.assertEqual(
            _eth_dst(self._frames_tx[0]),
            STACK__IP4_GATEWAY_MAC_ADDRESS,
            msg="Off-link destination must resolve to the default route's gateway MAC.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send,
            1,
            msg="Off-link destination must take the extnet-gateway path.",
        )

    def test__ip4__routing__no_route_drops(self) -> None:
        """
        Ensure an off-link IPv4 destination with no matching
        route (no connected route, default route removed) is
        dropped without emitting a frame.

        Reference: RFC 1122 §3.3.1 (next-hop selection — no route to host).
        """

        stack.ip4_fib.remove(destination=Ip4Network("0.0.0.0/0"))

        status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=Ip4Address("203.0.113.9"),
        )

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP4,
            msg="An off-link destination with no route must drop.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="A no-route drop must not emit a frame.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__extnet__no_gw__drop,
            1,
            msg="A no-route drop must bump the extnet no-gateway drop counter.",
        )


class TestIp4RoutingStaticRoute(NetworkTestCase):
    """
    The host-mode FIB static non-default-route tests.
    """

    def _install_static_route_and_arp(self) -> None:
        """
        Add a static 10.9.0.0/16 route via an on-link router
        alongside the harness default route, and wire the ARP
        mock for the three relevant next hops.
        """

        stack.route.add_route(
            route=Route(
                destination=_STATIC_NET,
                gateway=_STATIC_GW,
                protocol=RouteProtocol.STATIC,
            )
        )

        def _arp(*, ip4_address: Ip4Address) -> MacAddress | None:
            return {
                _STATIC_GW: _STATIC_GW__MAC,
                STACK__IP4_GATEWAY: STACK__IP4_GATEWAY_MAC_ADDRESS,
                HOST_A__IP4_ADDRESS: HOST_A__MAC_ADDRESS,
            }.get(ip4_address)

        cast(MagicMock, self._arp_cache).find_entry.side_effect = _arp

    def test__ip4__routing__static_route_beats_default(self) -> None:
        """
        Ensure a destination inside the static /16 prefix
        resolves via the static route's gateway, not the /0
        default — longest-prefix match.

        Reference: RFC 1122 §3.3.1 (next-hop selection / longest-prefix match).
        """

        self._install_static_route_and_arp()

        status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=_DST_IN_STATIC,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="A destination inside the static prefix must be sent.",
        )
        self.assertEqual(
            _eth_dst(self._frames_tx[0]),
            _STATIC_GW__MAC,
            msg="The static /16 route's gateway MAC must win over the default route.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send,
            1,
            msg="The static-route destination must take the extnet-gateway path.",
        )

    def test__ip4__routing__default_used_outside_static_prefix(self) -> None:
        """
        Ensure a destination matched only by the /0 default
        route (outside the static /16) resolves via the default
        gateway.

        Reference: RFC 1122 §3.3.1 (next-hop selection / default route).
        """

        self._install_static_route_and_arp()

        status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=_DST_DEFAULT_ONLY,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="A destination outside the static prefix must be sent via the default route.",
        )
        self.assertEqual(
            _eth_dst(self._frames_tx[0]),
            STACK__IP4_GATEWAY_MAC_ADDRESS,
            msg="A destination outside the static prefix must use the default gateway MAC.",
        )

    def test__ip4__routing__on_link_unaffected_by_static_route(self) -> None:
        """
        Ensure an on-link destination still resolves directly
        (connected route) when a static non-default route is
        also installed.

        Reference: RFC 1122 §3.3.1 (next-hop selection / connected over routed).
        """

        self._install_static_route_and_arp()

        status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="An on-link destination must be sent.",
        )
        self.assertEqual(
            _eth_dst(self._frames_tx[0]),
            HOST_A__MAC_ADDRESS,
            msg="An on-link destination must resolve directly, unaffected by the static route.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send,
            1,
            msg="An on-link destination must take the locnet (direct) path.",
        )
