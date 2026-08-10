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
This module contains the milestone-M0 baseline integration tests for
the Phase-2 router forwarding plane. They validate the three-interface
'RouterTestCase' topology (interface registration and FIB egress
selection) and pin the current host-mode baseline: with forwarding
disabled — the state before the M1 'ip_forward' knob lands — an inbound
transit datagram is dropped, never forwarded. The forwarding tests that
flip this baseline arrive with M1.

pytcp/tests/integration/router/test__router__forwarding_baseline.py

ver 3.0.10
"""

from pytcp import stack
from pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, HOST_A__IP6_ADDRESS, HOST_A__MAC_ADDRESS
from pytcp.tests.lib.router_testcase import (
    HOST_D__IP4,
    HOST_D__IP6,
    INTERNET__IP4,
    INTERNET__IP6,
    UPSTREAM_GW__IP4,
    UPSTREAM_GW__IP6,
    RouterTestCase,
)


class TestRouterForwardingBaseline(RouterTestCase):
    """
    The M0 router-harness and host-mode forwarding-baseline tests.
    """

    def test__router__harness__three_interfaces_registered(self) -> None:
        """
        Ensure the harness registers exactly three interfaces — the boot
        interface (ifindex 1) plus the LAN-B and upstream interfaces at
        the next two ifindexes — so forwarding tests have distinct
        ingress and egress interfaces to select between.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(stack.interfaces),
            3,
            msg=f"The router topology must register three interfaces. Got: {dict(stack.interfaces)!r}",
        )
        self.assertEqual(
            self.if1.ifindex,
            1,
            msg="The boot interface (LAN-A) must be ifindex 1.",
        )
        self.assertEqual(
            (self.if2.ifindex, self.if3.ifindex),
            (2, 3),
            msg=f"LAN-B / upstream must be ifindex 2 / 3. Got: {self.if2.ifindex}, {self.if3.ifindex}.",
        )

    def test__router__harness__fib_selects_lan_b_egress_ip4(self) -> None:
        """
        Ensure the FIB resolves an IPv4 destination on the LAN-B subnet
        to the LAN-B interface via its synthesized connected route — the
        egress-selection capability the three-interface topology exists
        to exercise.

        Reference: RFC 1812 §5.2.4 (next-hop address determination).
        """

        route = stack.ip4_fib.lookup(HOST_D__IP4, connected=stack.connected_ip4_networks())

        self.assertIsNotNone(
            route,
            msg=f"The FIB must resolve on-link destination {HOST_D__IP4}.",
        )
        assert route is not None
        self.assertEqual(
            route.oif,
            self.if2.ifindex,
            msg=f"On-link destination {HOST_D__IP4} must egress LAN-B (if-{self.if2.ifindex}). Got oif: {route.oif}.",
        )

    def test__router__harness__fib_selects_upstream_egress_ip4(self) -> None:
        """
        Ensure the FIB resolves an off-net IPv4 destination through the
        default route out the upstream interface toward the upstream
        gateway — the FIB must choose the upstream egress over the two
        LAN interfaces.

        Reference: RFC 1812 §5.2.4 (next-hop address determination).
        """

        route = stack.ip4_fib.lookup(INTERNET__IP4, connected=stack.connected_ip4_networks())

        self.assertIsNotNone(
            route,
            msg=f"The default route must resolve off-net destination {INTERNET__IP4}.",
        )
        assert route is not None
        self.assertEqual(
            route.oif,
            self.if3.ifindex,
            msg=f"Off-net destination {INTERNET__IP4} must egress upstream (if-{self.if3.ifindex}). Got: {route.oif}.",
        )
        self.assertEqual(
            route.gateway,
            UPSTREAM_GW__IP4,
            msg=f"Off-net destination must resolve to the upstream gateway. Got: {route.gateway!r}.",
        )

    def test__router__harness__fib_selects_lan_b_egress_ip6(self) -> None:
        """
        Ensure the FIB resolves an IPv6 destination on the LAN-B subnet
        to the LAN-B interface via its synthesized connected route.

        Reference: RFC 1812 §5.2.4 (next-hop address determination).
        """

        route = stack.ip6_fib.lookup(HOST_D__IP6, connected=stack.connected_ip6_networks())

        self.assertIsNotNone(
            route,
            msg=f"The FIB must resolve on-link destination {HOST_D__IP6}.",
        )
        assert route is not None
        self.assertEqual(
            route.oif,
            self.if2.ifindex,
            msg=f"On-link destination {HOST_D__IP6} must egress LAN-B (if-{self.if2.ifindex}). Got oif: {route.oif}.",
        )

    def test__router__harness__fib_selects_upstream_egress_ip6(self) -> None:
        """
        Ensure the FIB resolves an off-net IPv6 destination through the
        default route out the upstream interface toward the upstream
        gateway.

        Reference: RFC 1812 §5.2.4 (next-hop address determination).
        """

        route = stack.ip6_fib.lookup(INTERNET__IP6, connected=stack.connected_ip6_networks())

        self.assertIsNotNone(
            route,
            msg=f"The default route must resolve off-net destination {INTERNET__IP6}.",
        )
        assert route is not None
        self.assertEqual(
            route.oif,
            self.if3.ifindex,
            msg=f"Off-net destination {INTERNET__IP6} must egress upstream (if-{self.if3.ifindex}). Got: {route.oif}.",
        )
        self.assertEqual(
            route.gateway,
            UPSTREAM_GW__IP6,
            msg=f"Off-net destination must resolve to the upstream gateway. Got: {route.gateway!r}.",
        )

    def test__router__ip4__forwarding_disabled__host_drops_transit(self) -> None:
        """
        Ensure an inbound IPv4 transit datagram — addressed to a host on
        another interface's subnet, not to the router itself — is dropped
        with no frame emitted on any interface, the current host-mode
        baseline before forwarding is enabled in M1.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        """

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=HOST_D__IP4,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unknown__drop=1,
        )

    def test__router__ip6__forwarding_disabled__host_drops_transit(self) -> None:
        """
        Ensure an inbound IPv6 transit datagram — addressed to a host on
        another interface's subnet, not to the router itself — is dropped
        with no frame emitted on any interface, the current host-mode
        baseline before forwarding is enabled in M1.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        """

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP6_ADDRESS,
                dst_ip=HOST_D__IP6,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unknown__drop=1,
        )
