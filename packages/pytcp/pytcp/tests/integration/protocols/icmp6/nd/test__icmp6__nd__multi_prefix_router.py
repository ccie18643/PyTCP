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
Integration tests for the IPv6 ND first-hop router selection
in multi-prefix networks (RFC 8028) — nd_linux_parity §23.

When more than one default router exists, the host picks the
router whose RA-advertised prefix covers the outbound source
address. This is the multi-WAN / dual-ISP scenario: each ISP
advertises its own prefix, and a packet whose source is in
ISP A's prefix MUST exit via ISP A's router (otherwise the
ISP's anti-spoofing filter drops it).

Falls back to the overall highest-preference default router
when no source-matching router exists (the route's source
came from somewhere other than RA SLAAC, e.g. static config).

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__multi_prefix_router.py

ver 3.0.8
"""

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6NdOptionPi, Icmp6NdRoutePreference
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

ROUTER_A__LINK_LOCAL = Ip6Address("fe80::a")
ROUTER_A__MAC = MacAddress("02:00:00:00:00:0a")
ROUTER_A__PREFIX = "2001:db8:a::"

ROUTER_B__LINK_LOCAL = Ip6Address("fe80::b")
ROUTER_B__MAC = MacAddress("02:00:00:00:00:0b")
ROUTER_B__PREFIX = "2001:db8:b::"


def _pi(prefix_str: str) -> Icmp6NdOptionPi:
    """
    Build an autoconf-eligible PI option for the given prefix
    string; lifetimes are non-zero so the SLAAC table records
    the entry.
    """

    from net_addr import Ip6Network

    return Icmp6NdOptionPi(
        flag_l=True,
        flag_a=True,
        flag_r=False,
        valid_lifetime=2592000,
        preferred_lifetime=604800,
        prefix=Ip6Network(prefix_str + "/64"),
    )


class TestIcmp6Nd__MultiPrefixRouter__SourceMatchingRouter(NdTestCase):
    """
    With two routers each advertising a distinct prefix, the
    accessor returns the router whose advertised prefix covers
    the supplied source address.
    """

    def setUp(self) -> None:
        """
        Drive two RAs, one from each router, each advertising
        its own prefix. After this the host has two
        default-router entries and two SLAAC entries each tied
        to the announcing router.
        """

        super().setUp()
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_A__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_A__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                options=[_pi(ROUTER_A__PREFIX)],
            ),
        )
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_B__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_B__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                options=[_pi(ROUTER_B__PREFIX)],
            ),
        )

    def test__icmp6__nd__multi_prefix_router__source_in_a_returns_a(self) -> None:
        """
        Ensure a source address in router A's advertised
        prefix selects router A as the first-hop.

        Reference: RFC 8028 §3 (host-side first-hop selection by source).
        """

        # Use the host-derived address for router A's prefix —
        # the same address the SLAAC table tracks.
        slaac_a = next(
            entry
            for entry in self._packet_handler._icmp6_slaac_addresses
            if entry.prefix == _pi(ROUTER_A__PREFIX).prefix
        )
        chosen = self._packet_handler.get_icmp6_default_router_for_source(source=slaac_a.address)

        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(
            chosen.address,
            ROUTER_A__LINK_LOCAL,
            msg=("Source in router A's prefix must select router A. " f"Got: {chosen.address!r}"),
        )

    def test__icmp6__nd__multi_prefix_router__source_in_b_returns_b(self) -> None:
        """
        Ensure a source address in router B's advertised
        prefix selects router B as the first-hop.

        Reference: RFC 8028 §3 (host-side first-hop selection by source).
        """

        slaac_b = next(
            entry
            for entry in self._packet_handler._icmp6_slaac_addresses
            if entry.prefix == _pi(ROUTER_B__PREFIX).prefix
        )
        chosen = self._packet_handler.get_icmp6_default_router_for_source(source=slaac_b.address)

        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(
            chosen.address,
            ROUTER_B__LINK_LOCAL,
            msg=("Source in router B's prefix must select router B. " f"Got: {chosen.address!r}"),
        )


class TestIcmp6Nd__MultiPrefixRouter__FallbackToHighestPreference(NdTestCase):
    """
    When no router advertised a prefix that covers the source
    address (e.g. statically-configured GUA, or source in a
    prefix unrelated to the default-router list), fall back
    to the overall highest-preference default router.
    """

    def test__icmp6__nd__multi_prefix_router__unknown_source_falls_back(self) -> None:
        """
        Ensure a source address that no default router's RA
        prefix covers triggers the fallback to the highest-
        preference router.

        Reference: RFC 8028 §3 (fallback when source is not bound to a known prefix).
        """

        # Router A: LOW preference. Router B: HIGH preference.
        # Source address is in a prefix neither announced.
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_A__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_A__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                prf=Icmp6NdRoutePreference.LOW,
                options=[_pi(ROUTER_A__PREFIX)],
            ),
        )
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_B__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_B__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                prf=Icmp6NdRoutePreference.HIGH,
                options=[_pi(ROUTER_B__PREFIX)],
            ),
        )

        unknown_source = Ip6Address("2001:db8:cafe::1")
        chosen = self._packet_handler.get_icmp6_default_router_for_source(source=unknown_source)

        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(
            chosen.address,
            ROUTER_B__LINK_LOCAL,
            msg=("Unknown-prefix source must fall back to the HIGH-preference " f"router. Got: {chosen.address!r}"),
        )


class TestIcmp6Nd__MultiPrefixRouter__NoRoutersReturnsNone(NdTestCase):
    """
    With no default routers learned, the accessor returns None.
    """

    def test__icmp6__nd__multi_prefix_router__empty_returns_none(self) -> None:
        """
        Ensure the accessor returns None when no default
        routers are tracked.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        chosen = self._packet_handler.get_icmp6_default_router_for_source(
            source=Ip6Address("2001:db8::1"),
        )
        self.assertIsNone(
            chosen,
            msg=f"No routers → accessor must return None. Got: {chosen!r}",
        )
