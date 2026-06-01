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
Integration tests for the IPv6 Neighbor Discovery Default Router
Preference field (RFC 4191) — nd_linux_parity §14. The 2-bit Prf
field rides in bits 3-4 of the RA-header flags byte and indicates
the router's relative preference. Receivers store the value on
the default-router-list entry, normalise the RESERVED encoding
(10) to MEDIUM (00) per RFC 4191 §2.2, and sort the list by
preference (HIGH first, then MEDIUM, then LOW) so route lookup
naturally picks the most-preferred router.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__router_preference.py

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

ROUTER_HIGH__LINK_LOCAL = Ip6Address("fe80::1")
ROUTER_HIGH__MAC = MacAddress("02:00:00:00:00:01")

ROUTER_MEDIUM__LINK_LOCAL = Ip6Address("fe80::2")
ROUTER_MEDIUM__MAC = MacAddress("02:00:00:00:00:02")

ROUTER_LOW__LINK_LOCAL = Ip6Address("fe80::3")
ROUTER_LOW__MAC = MacAddress("02:00:00:00:00:03")


class TestIcmp6Nd__RouterPreference__StoredOnEntry(NdTestCase):
    """
    The Prf field on an inbound RA is captured into the matching
    Icmp6DefaultRouter entry so consumers (sort order, future
    RFC 4191 route-info-option processing) can use it.
    """

    def test__icmp6__nd__ra__high_preference_stored_on_entry(self) -> None:
        """
        Ensure an RA carrying Prf=HIGH stores HIGH on the
        default-router list entry.

        Reference: RFC 4191 §2.2 (Prf field encoding).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_HIGH__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_HIGH__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                prf=Icmp6NdRoutePreference.HIGH,
            ),
        )

        routers = self._packet_handler._icmp6_default_routers
        self.assertEqual(
            len(routers),
            1,
            msg=f"Expected one default-router entry, got {routers!r}",
        )
        self.assertEqual(
            routers[0].prf,
            Icmp6NdRoutePreference.HIGH,
            msg=f"Default-router entry must store the advertised Prf. Got: {routers[0]!r}",
        )

    def test__icmp6__nd__ra__low_preference_stored_on_entry(self) -> None:
        """
        Ensure an RA carrying Prf=LOW stores LOW on the
        default-router list entry.

        Reference: RFC 4191 §2.2 (Prf field encoding).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_LOW__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_LOW__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                prf=Icmp6NdRoutePreference.LOW,
            ),
        )

        routers = self._packet_handler._icmp6_default_routers
        self.assertEqual(
            routers[0].prf,
            Icmp6NdRoutePreference.LOW,
            msg=f"Default-router entry must store LOW Prf. Got: {routers[0]!r}",
        )

    def test__icmp6__nd__ra__default_preference_stored_on_entry(self) -> None:
        """
        Ensure an RA without an explicit Prf (encoded as MEDIUM
        on the wire — bits 3-4 = 00) stores MEDIUM on the entry.

        Reference: RFC 4191 §2.2 (MEDIUM is the default Prf encoding).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_MEDIUM__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_MEDIUM__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
            ),
        )

        routers = self._packet_handler._icmp6_default_routers
        self.assertEqual(
            routers[0].prf,
            Icmp6NdRoutePreference.MEDIUM,
            msg=f"Default RA without Prf must store MEDIUM. Got: {routers[0]!r}",
        )


class TestIcmp6Nd__RouterPreference__ReservedNormalization(NdTestCase):
    """
    RFC 4191 §2.2: a receiver that sees the RESERVED Prf encoding
    (10) MUST treat it as if it were MEDIUM (00).
    """

    def test__icmp6__nd__ra__reserved_preference_treated_as_medium(self) -> None:
        """
        Ensure an RA carrying Prf=RESERVED stores MEDIUM on the
        default-router-list entry — the RFC's "MUST treat as if
        it were Medium" interoperability rule.

        Reference: RFC 4191 §2.2 (Prf=10 RESERVED MUST be normalised to MEDIUM).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_MEDIUM__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_MEDIUM__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                prf=Icmp6NdRoutePreference.RESERVED,
            ),
        )

        routers = self._packet_handler._icmp6_default_routers
        self.assertEqual(
            routers[0].prf,
            Icmp6NdRoutePreference.MEDIUM,
            msg=("Prf=RESERVED must be normalised to MEDIUM at the host. " f"Got: {routers[0]!r}"),
        )


class TestIcmp6Nd__RouterPreference__SortOrder(NdTestCase):
    """
    'get_icmp6_default_routers()' returns entries sorted by
    preference (HIGH first, then MEDIUM, then LOW) so a TX-side
    consumer that picks the first valid entry naturally selects
    the most-preferred router.
    """

    def test__icmp6__nd__default_routers__sorted_by_preference(self) -> None:
        """
        Ensure 'get_icmp6_default_routers()' orders entries by
        Prf descending (HIGH, MEDIUM, LOW) regardless of
        learning order.

        Reference: RFC 4191 §2.1 (default-router preference rule).
        """

        # Learn LOW first, then MEDIUM, then HIGH — the accessor
        # must reorder them.
        for mac, lla, prf in (
            (ROUTER_LOW__MAC, ROUTER_LOW__LINK_LOCAL, Icmp6NdRoutePreference.LOW),
            (ROUTER_MEDIUM__MAC, ROUTER_MEDIUM__LINK_LOCAL, Icmp6NdRoutePreference.MEDIUM),
            (ROUTER_HIGH__MAC, ROUTER_HIGH__LINK_LOCAL, Icmp6NdRoutePreference.HIGH),
        ):
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

        active = self._packet_handler.get_icmp6_default_routers()
        self.assertEqual(
            [entry.prf for entry in active],
            [
                Icmp6NdRoutePreference.HIGH,
                Icmp6NdRoutePreference.MEDIUM,
                Icmp6NdRoutePreference.LOW,
            ],
            msg=f"Accessor must return entries in HIGH > MEDIUM > LOW order. Got: {active!r}",
        )
