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
This module contains the integration test pinning that an
inbound IPv6 Router Advertisement installs / withdraws the
host-mode FIB default route (Phase 3b-RA).

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__ra_default_route.py

ver 3.0.8
"""

from net_addr import Ip6Address, Ip6Network, MacAddress
from pytcp import stack
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.runtime.socket import AddressFamily
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import STACK__IP6_HOST, STACK__MAC_ADDRESS

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

# A router whose link-local differs from the harness fixture
# default-route gateway (fe80::1) so the RA-installed route is
# unambiguously distinguishable from the pre-installed BOOT one.
ROUTER__LINK_LOCAL = Ip6Address("fe80::abcd")
ROUTER__MAC = MacAddress("02:00:00:00:00:ab")


class TestIcmp6Nd__RaDefaultRoute(NdTestCase):
    """
    The RA → host-mode FIB default-route install / withdraw
    tests.
    """

    def test__icmp6__nd__ra_nonzero_lifetime_installs_default_route(self) -> None:
        """
        Ensure an RA with a non-zero router lifetime installs a
        protocol=RA ::/0 default route via the RA source
        link-local, replacing the harness fixture BOOT default.
        The auto-synthesized on-link connected routes (protocol
        KERNEL) are filtered out so the assertion stays focused
        on the RA-installed default.

        Reference: RFC 4861 §6.3.4 (RA processing — default router).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
            )
        )

        self.assertEqual(
            tuple(
                route
                for route in stack.route.list_routes(family=AddressFamily.INET6)
                if route.protocol is not RouteProtocol.KERNEL
            ),
            (
                Route(
                    destination=Ip6Network("::/0"),
                    gateway=ROUTER__LINK_LOCAL,
                    protocol=RouteProtocol.RA,
                ),
            ),
            msg="A non-zero-lifetime RA must install one protocol=RA default route.",
        )

    def test__icmp6__nd__ra_zero_lifetime_withdraws_default_route(self) -> None:
        """
        Ensure an RA with router lifetime 0 from a router that
        previously advertised one withdraws the FIB default
        route. The auto-synthesized on-link connected routes
        (protocol KERNEL) are filtered out so the assertion
        observes only the withdrawn FIB default.

        Reference: RFC 4861 §6.3.4 (RA processing — zero lifetime removes the router).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
            )
        )
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=0,
            )
        )

        self.assertEqual(
            tuple(
                route
                for route in stack.route.list_routes(family=AddressFamily.INET6)
                if route.protocol is not RouteProtocol.KERNEL
            ),
            (),
            msg="A zero-lifetime RA must withdraw the FIB default route.",
        )
