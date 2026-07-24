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
Integration tests for the IPv6 ND host-to-router load sharing
(RFC 4311 §3) — nd_linux_parity §24.

When multiple default routers share the highest preference,
the host SHOULD distribute traffic across them per-destination
so different flows take different first-hops. The
'get_icmp6_default_router_for_destination(destination)'
accessor implements this via a deterministic hash of the
destination address modulo the highest-preference router
count.

Per-destination distribution (rather than per-packet
round-robin) is what the RFC mandates: a single flow always
gets the same first-hop, so TCP doesn't reorder, but
different destinations spread across routers.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__router_load_sharing.py

ver 3.0.8
"""

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6NdRoutePreference
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

ROUTER_A__LINK_LOCAL = Ip6Address("fe80::a")
ROUTER_A__MAC = MacAddress("02:00:00:00:00:0a")

ROUTER_B__LINK_LOCAL = Ip6Address("fe80::b")
ROUTER_B__MAC = MacAddress("02:00:00:00:00:0b")

ROUTER_C__LINK_LOCAL = Ip6Address("fe80::c")
ROUTER_C__MAC = MacAddress("02:00:00:00:00:0c")


class TestIcmp6Nd__RouterLoadSharing__SameDestStableRouter(NdTestCase):
    """
    The picker is deterministic per destination — same
    destination always selects the same router across calls
    so TCP flows aren't reordered.
    """

    def test__icmp6__nd__router_load_sharing__same_dest_same_router(self) -> None:
        """
        Ensure repeated calls with the same destination return
        the same default router.

        Reference: RFC 4311 §3 (per-destination, not per-packet).
        """

        for mac, lla in [
            (ROUTER_A__MAC, ROUTER_A__LINK_LOCAL),
            (ROUTER_B__MAC, ROUTER_B__LINK_LOCAL),
            (ROUTER_C__MAC, ROUTER_C__LINK_LOCAL),
        ]:
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=mac,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=lla,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    prf=Icmp6NdRoutePreference.MEDIUM,
                ),
            )

        dest = Ip6Address("2001:db8::42")
        first = self._packet_handler.get_icmp6_default_router_for_destination(destination=dest)
        for _ in range(10):
            again = self._packet_handler.get_icmp6_default_router_for_destination(destination=dest)
            self.assertEqual(
                first,
                again,
                msg="Per-destination picker must be deterministic across calls.",
            )


class TestIcmp6Nd__RouterLoadSharing__DifferentDestsDistribute(NdTestCase):
    """
    Different destinations should land on different routers
    (over enough samples) — the load-sharing property.
    """

    def test__icmp6__nd__router_load_sharing__distributes_across_routers(self) -> None:
        """
        Ensure 100 distinct destinations distribute across all
        three equal-preference routers (no router gets all
        traffic; no router is starved).

        Reference: RFC 4311 §3 (load sharing across equal-preference routers).
        """

        for mac, lla in [
            (ROUTER_A__MAC, ROUTER_A__LINK_LOCAL),
            (ROUTER_B__MAC, ROUTER_B__LINK_LOCAL),
            (ROUTER_C__MAC, ROUTER_C__LINK_LOCAL),
        ]:
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=mac,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=lla,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    prf=Icmp6NdRoutePreference.MEDIUM,
                ),
            )

        # 100 distinct destinations spanning a /64.
        chosen_addresses: set[Ip6Address] = set()
        for i in range(100):
            dest = Ip6Address(int(Ip6Address("2001:db8::1")) + i * 0x100)
            chosen = self._packet_handler.get_icmp6_default_router_for_destination(destination=dest)
            assert chosen is not None
            chosen_addresses.add(chosen.address)

        self.assertEqual(
            chosen_addresses,
            {ROUTER_A__LINK_LOCAL, ROUTER_B__LINK_LOCAL, ROUTER_C__LINK_LOCAL},
            msg=(
                "Over 100 distinct destinations, all three equal-preference "
                f"routers must be selected at least once. Got: {chosen_addresses!r}"
            ),
        )


class TestIcmp6Nd__RouterLoadSharing__OnlyHighestPreference(NdTestCase):
    """
    Load sharing applies only within the highest-preference
    equivalence class — a LOW-preference router never gets
    traffic if a HIGH-preference router is available.
    """

    def test__icmp6__nd__router_load_sharing__low_pref_never_picked(self) -> None:
        """
        Ensure a LOW-preference router is never returned when
        HIGH-preference routers are available, regardless of
        destination.

        Reference: RFC 4191 §2.1 (preference precedence).
        """

        # Two HIGH-preference routers (A, B), one LOW (C).
        for mac, lla, prf in [
            (ROUTER_A__MAC, ROUTER_A__LINK_LOCAL, Icmp6NdRoutePreference.HIGH),
            (ROUTER_B__MAC, ROUTER_B__LINK_LOCAL, Icmp6NdRoutePreference.HIGH),
            (ROUTER_C__MAC, ROUTER_C__LINK_LOCAL, Icmp6NdRoutePreference.LOW),
        ]:
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=mac,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=lla,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    prf=prf,
                ),
            )

        chosen_addresses: set[Ip6Address] = set()
        for i in range(50):
            dest = Ip6Address(int(Ip6Address("2001:db8::1")) + i * 0x100)
            chosen = self._packet_handler.get_icmp6_default_router_for_destination(destination=dest)
            assert chosen is not None
            chosen_addresses.add(chosen.address)

        self.assertNotIn(
            ROUTER_C__LINK_LOCAL,
            chosen_addresses,
            msg=(
                "LOW-preference router must NEVER be picked when HIGH-preference "
                f"routers exist. Got: {chosen_addresses!r}"
            ),
        )


class TestIcmp6Nd__RouterLoadSharing__NoRoutersReturnsNone(NdTestCase):
    """
    With no default routers, the accessor returns None.
    """

    def test__icmp6__nd__router_load_sharing__empty_returns_none(self) -> None:
        """
        Ensure the accessor returns None when no default
        routers are tracked.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        chosen = self._packet_handler.get_icmp6_default_router_for_destination(
            destination=Ip6Address("2001:db8::1"),
        )
        self.assertIsNone(
            chosen,
            msg=f"No routers → accessor must return None. Got: {chosen!r}",
        )
