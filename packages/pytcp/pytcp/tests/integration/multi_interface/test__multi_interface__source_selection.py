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
Multi-interface (N>1) egress-aware source-address selection tests.

On a multi-homed host the source address of a stack-originated packet
must come from the interface the FIB egresses the packet on — never from
a different interface, whose own TX path would drop the packet because it
does not own that address. These tests register a second interface, route
an off-link destination out it, and assert that 'select_local_ip6_source'
/ 'select_local_ip4_source' return the EGRESS interface's address rather
than the boot interface's.

pytcp/tests/integration/multi_interface/test__multi_interface__source_selection.py

ver 3.0.9
"""

from typing import override
from unittest import TestCase

from net_addr import Ip4Address, Ip4IfAddr, Ip4Network, Ip6Address, Ip6IfAddr, Ip6Network, MacAddress
from pytcp import stack
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import STACK__IP4_HOST, STACK__IP6_HOST

IFACE2__IFINDEX = 2
IFACE2__MAC_ADDRESS = MacAddress("02:00:00:00:00:08")
IFACE2__IP4_HOST = Ip4IfAddr("10.0.2.7/24")
IFACE2__IP6_HOST = Ip6IfAddr("2001:db8:0:2::7/64")

# Off-link destinations covered by a route that egresses IFACE2.
DST_OFFLINK__IP4 = Ip4Address("203.0.113.1")
DST_OFFLINK__IP6 = Ip6Address("2606:4700::1")


class TestMultiInterfaceSourceSelection(IcmpTestCase, TestCase):
    """
    The multi-interface egress-aware source-selection tests.
    """

    @override
    def setUp(self) -> None:
        """
        Add a second interface on a distinct subnet alongside the boot
        interface; the base harness snapshots / restores 'stack.interfaces'
        and the routing tables.
        """

        super().setUp()

        self._iface2 = self._add_interface(
            mac_address=IFACE2__MAC_ADDRESS,
            ip4_host=IFACE2__IP4_HOST,
            ip6_host=IFACE2__IP6_HOST,
        )

    def test__multi_interface__ip6_source_matches_egress_interface(self) -> None:
        """
        Ensure 'select_local_ip6_source' sources an off-link packet from
        the address of the interface the FIB egresses it on (IFACE2),
        never from the boot interface — the bug where a global address
        from interface A is attached to a packet egressing interface B,
        which B then drops because it does not own A's address.

        Reference: RFC 6724 §5 (source selection scoped to the egress interface).
        """

        stack.ip6_fib.add(
            route=Route(
                destination=Ip6Network("2606:4700::/32"),
                oif=IFACE2__IFINDEX,
                protocol=RouteProtocol.STATIC,
            )
        )

        source = stack.select_local_ip6_source(DST_OFFLINK__IP6)

        self.assertEqual(
            source,
            IFACE2__IP6_HOST.address,
            msg="The source must come from the egress interface (IFACE2), not the boot interface.",
        )
        self.assertNotEqual(
            source,
            STACK__IP6_HOST.address,
            msg="The source must not come from the boot interface when the FIB egresses via IFACE2.",
        )

    def test__multi_interface__ip4_source_matches_egress_interface(self) -> None:
        """
        Ensure 'select_local_ip4_source' sources an off-link packet from
        the egress interface's address (IFACE2), never the boot interface.

        Reference: RFC 1122 §3.3.4.2 (multihoming — source from the egress interface).
        """

        stack.ip4_fib.add(
            route=Route(
                destination=Ip4Network("203.0.113.0/24"),
                oif=IFACE2__IFINDEX,
                protocol=RouteProtocol.STATIC,
            )
        )

        source = stack.select_local_ip4_source(DST_OFFLINK__IP4)

        self.assertEqual(
            source,
            IFACE2__IP4_HOST.address,
            msg="The source must come from the egress interface (IFACE2), not the boot interface.",
        )
        self.assertNotEqual(
            source,
            STACK__IP4_HOST.address,
            msg="The source must not come from the boot interface when the FIB egresses via IFACE2.",
        )
