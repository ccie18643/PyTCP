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
Integration tests for the IPv6 Neighbor Discovery default-router
list (RFC 4861 §6.3.4). PyTCP previously stored a single 'gateway'
overwritten by every RA; the host now maintains a list of default
routers keyed on the RA source link-local, ages out entries past
their advertised Router Lifetime, and gates the whole behaviour
behind 'icmp6.accept_ra_defrtr' (mirroring Linux
'net.ipv6.conf.<iface>.accept_ra_defrtr').

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__default_router_list.py

ver 3.0.8
"""

import time
from unittest.mock import patch

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdOptions,
)
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

# RFC 4861 §6.1.2 mandates RA source must be link-local.
ROUTER_A__LINK_LOCAL = Ip6Address("fe80::1")
ROUTER_A__MAC = MacAddress("02:00:00:00:00:01")

ROUTER_B__LINK_LOCAL = Ip6Address("fe80::2")
ROUTER_B__MAC = MacAddress("02:00:00:00:00:02")


class TestIcmp6Nd__DefaultRouterList__Add(NdTestCase):
    """
    A non-zero-lifetime RA installs an entry in the default-
    router list, indexed by the RA's link-local source.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__nonzero_lifetime_adds_default_router(self) -> None:
        """
        Ensure an RA with non-zero router_lifetime installs the
        source link-local in the host's default-router list with
        lifetime stored as a monotonic-clock deadline.

        Reference: RFC 4861 §6.3.4 (RA processing — default-router list).
        """

        before = time.monotonic()
        frame = self._make_nd_ra_frame(
            eth_src=ROUTER_A__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER_A__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=1800,
        )

        self._drive_rx(frame=frame)

        routers = self._packet_handler._icmp6_default_routers
        self.assertEqual(
            len(routers),
            1,
            msg=f"Expected one default-router entry, got {routers!r}",
        )
        entry = routers[0]
        self.assertEqual(
            entry.address,
            ROUTER_A__LINK_LOCAL,
            msg=f"Default-router entry must store the RA source. Got: {entry!r}",
        )
        self.assertEqual(
            entry.lifetime,
            1800,
            msg=f"Default-router entry must preserve the advertised lifetime. Got: {entry!r}",
        )
        self.assertGreaterEqual(
            entry.expires_at,
            before + 1800,
            msg=f"Default-router 'expires_at' must be at least now+lifetime. Got: {entry!r}",
        )

    def test__icmp6__nd__ra__update_router_packet_stats(self) -> None:
        """
        Ensure a non-zero-lifetime RA bumps the
        'icmp6__nd_router_advertisement__update_router' counter.

        Reference: RFC 4861 §6.3.4 (RA processing — default-router list).
        """

        frame = self._make_nd_ra_frame(
            eth_src=ROUTER_A__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER_A__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=1800,
        )

        self._drive_rx(frame=frame)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_router_advertisement=1,
            icmp6__nd_router_advertisement__update_router=1,
        )


class TestIcmp6Nd__DefaultRouterList__Refresh(NdTestCase):
    """
    A second RA from the same router refreshes lifetime in place
    rather than appending a duplicate entry.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__second_ra_updates_lifetime_in_place(self) -> None:
        """
        Ensure two consecutive RAs from the same source produce
        a single list entry whose lifetime tracks the most-recent
        advertisement.

        Reference: RFC 4861 §6.3.4 (RA processing — default-router list).
        """

        first = self._make_nd_ra_frame(
            eth_src=ROUTER_A__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER_A__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=1800,
        )
        self._drive_rx(frame=first)

        second = self._make_nd_ra_frame(
            eth_src=ROUTER_A__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER_A__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=600,
        )
        self._drive_rx(frame=second)

        routers = self._packet_handler._icmp6_default_routers
        self.assertEqual(
            len(routers),
            1,
            msg=f"Refresh from same router must not duplicate the entry. Got: {routers!r}",
        )
        self.assertEqual(
            routers[0].lifetime,
            600,
            msg=f"Refresh must overwrite lifetime to the most recent value. Got: {routers!r}",
        )


class TestIcmp6Nd__DefaultRouterList__MultipleRouters(NdTestCase):
    """
    RAs from distinct link-local sources install distinct entries.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__separate_routers_separate_entries(self) -> None:
        """
        Ensure RAs from two distinct routers produce two distinct
        default-router list entries.

        Reference: RFC 4861 §6.3.4 (RA processing — default-router list).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_A__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_A__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
            ),
        )
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_B__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_B__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=900,
            ),
        )

        routers = self._packet_handler._icmp6_default_routers
        addresses = {entry.address for entry in routers}
        self.assertEqual(
            addresses,
            {ROUTER_A__LINK_LOCAL, ROUTER_B__LINK_LOCAL},
            msg=f"Distinct routers must produce distinct entries. Got: {routers!r}",
        )


class TestIcmp6Nd__DefaultRouterList__ZeroLifetimeRemoves(NdTestCase):
    """
    An RA with router_lifetime=0 removes the matching entry from
    the default-router list (RFC 4861 §6.3.4: "If the address is
    already present in the host's Default Router List ... and the
    received Router Lifetime value is zero, immediately time-out
    the entry").
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__zero_lifetime_removes_default_router(self) -> None:
        """
        Ensure a follow-up RA with router_lifetime=0 removes the
        previously-installed entry.

        Reference: RFC 4861 §6.3.4 (zero Router Lifetime times out the entry).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_A__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_A__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
            ),
        )
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_A__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_A__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=0,
            ),
        )

        self.assertEqual(
            self._packet_handler._icmp6_default_routers,
            [],
            msg=(
                "router_lifetime=0 RA must remove the matching default-"
                f"router entry. Got: {self._packet_handler._icmp6_default_routers!r}"
            ),
        )

    def test__icmp6__nd__ra__zero_lifetime_remove_packet_stats(self) -> None:
        """
        Ensure the zero-lifetime path bumps the
        'icmp6__nd_router_advertisement__remove_router' counter
        when the entry actually existed.

        Reference: RFC 4861 §6.3.4 (zero Router Lifetime times out the entry).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_A__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_A__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
            ),
        )
        self._packet_handler._packet_stats_rx.icmp6__nd_router_advertisement__update_router = 0
        self._packet_handler._packet_stats_rx.icmp6__nd_router_advertisement = 0
        self._packet_handler._packet_stats_rx.icmp6__pre_parse = 0
        self._packet_handler._packet_stats_rx.ip6__pre_parse = 0
        self._packet_handler._packet_stats_rx.ip6__dst_unicast = 0
        self._packet_handler._packet_stats_rx.ethernet__pre_parse = 0
        self._packet_handler._packet_stats_rx.ethernet__dst_unicast = 0

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER_A__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER_A__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=0,
            ),
        )

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_router_advertisement=1,
            icmp6__nd_router_advertisement__remove_router=1,
        )


class TestIcmp6Nd__DefaultRouterList__LazyAgeing(NdTestCase):
    """
    The accessor 'get_icmp6_default_routers' must filter out
    entries whose 'expires_at' is in the past (RFC 4861 §6.3.5
    'when the lifetime expires it MUST be removed').
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__default_routers__expired_filtered(self) -> None:
        """
        Ensure 'get_icmp6_default_routers()' omits entries past
        their 'expires_at'. The internal list may still hold the
        entry (lazy ageing) — only the accessor must be
        lifetime-honest.

        Reference: RFC 4861 §6.3.5 (router-state timeout).
        """

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=1000.0,
        ):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER_A__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER_A__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=60,
                ),
            )

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=1000.0 + 61,
        ):
            active = self._packet_handler.get_icmp6_default_routers()

        self.assertEqual(
            active,
            [],
            msg=f"Expired entries must not surface from the accessor. Got: {active!r}",
        )


class TestIcmp6Nd__DefaultRouterList__SysctlAcceptRaDefrtr(NdTestCase):
    """
    'icmp6.accept_ra_defrtr' = 0 disables default-router
    learning entirely (Linux parity).
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__accept_ra_defrtr_zero_drops_update(self) -> None:
        """
        Ensure 'icmp6.accept_ra_defrtr=0' drops default-router
        installation and bumps the drop counter, leaving the
        list empty.

        Reference: Linux 'net.ipv6.conf.<iface>.accept_ra_defrtr'.
        """

        with sysctl_module.override("icmp6.default.accept_ra_defrtr", 0):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER_A__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER_A__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                ),
            )

        self.assertEqual(
            self._packet_handler._icmp6_default_routers,
            [],
            msg=(
                "accept_ra_defrtr=0 must suppress entry installation. "
                f"Got: {self._packet_handler._icmp6_default_routers!r}"
            ),
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__nd_router_advertisement__defrtr__drop,
            1,
            msg="accept_ra_defrtr=0 path must bump the drop counter.",
        )


class TestIcmp6Nd__DefaultRouterList__OptionConstructionPaths(NdTestCase):
    """
    The frame builder must handle both option-less RAs and RAs
    carrying additional options without breaking parsing.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__builder_emits_parseable_frame(self) -> None:
        """
        Ensure the harness '_make_nd_ra_frame()' produces a frame
        whose ICMPv6 payload parses back into the expected
        Router Advertisement message — protects against silent
        builder regressions.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = self._make_nd_ra_frame(
            eth_src=ROUTER_A__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER_A__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=1800,
        )

        probe = self._parse_tx_icmp6(frame)

        message = probe.message
        assert isinstance(
            message, Icmp6NdMessageRouterAdvertisement
        ), f"Builder must yield an RA message. Got: {type(message)!r}"
        self.assertEqual(
            message.router_lifetime,
            1800,
            msg=f"Builder must propagate the router_lifetime kwarg. Got: {message!r}",
        )
        self.assertEqual(
            message.options,
            Icmp6NdOptions(),
            msg=f"Default RA frame must carry no options. Got: {message!r}",
        )
