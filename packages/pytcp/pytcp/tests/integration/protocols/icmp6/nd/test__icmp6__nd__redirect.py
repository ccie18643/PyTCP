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
Integration tests for the IPv6 Neighbor Discovery Redirect message
(RFC 4861 §8) RX-handler — PyTCP host-side acceptance gates and
neighbour-cache override.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__redirect.py

ver 3.0.8
"""

from typing import override

from net_addr import Ip6Address, MacAddress
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

# RFC 4861 §8.1 requires a Redirect's IP source to be link-local;
# PyTCP's stack treats fe80::1 as the canonical default-router
# link-local in the integration harness (see network_testcase).
ROUTER__LINK_LOCAL = Ip6Address("fe80::1")
ROUTER__MAC = MacAddress("02:00:00:00:00:01")

# A "better next hop" router learned via Redirect — link-local per
# §8.1, MAC delivered in the Redirect's TLLA option.
TARGET__LINK_LOCAL = Ip6Address("fe80::99")
TARGET__MAC = MacAddress("02:00:00:00:00:99")


class TestIcmp6Rx__NdRedirect__AcceptWithTlla(NdTestCase):
    """
    A valid inbound Redirect carrying a TLLA must learn the
    (Target, TLLA) pair into the neighbour cache.
    """

    def test__icmp6__rx__redirect__accept_with_tlla__no_tx(self) -> None:
        """
        Ensure a valid Redirect produces no TX frames — the host-
        side handler is purely cache-updating.

        Reference: RFC 4861 §8 (Redirect Function).
        """

        frame = self._make_nd_redirect_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            target=TARGET__LINK_LOCAL,
            destination=HOST_A__IP6_ADDRESS,
            tlla=TARGET__MAC,
        )

        self._drive_rx(frame=frame)

        self._assert_no_tx()

    def test__icmp6__rx__redirect__accept_with_tlla__packet_stats_rx(self) -> None:
        """
        Ensure a valid TLLA-bearing Redirect bumps the generic
        Redirect counter and the cache-update counter.

        Reference: RFC 4861 §8.3 (Updating the Conceptual Data Structures).
        """

        frame = self._make_nd_redirect_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            target=TARGET__LINK_LOCAL,
            destination=HOST_A__IP6_ADDRESS,
            tlla=TARGET__MAC,
        )

        self._drive_rx(frame=frame)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_redirect=1,
            icmp6__nd_redirect__update_nd_cache=1,
        )


class TestIcmp6Rx__NdRedirect__OnLinkSignal(NdTestCase):
    """
    Per RFC 4861 §4.5: when Target == Destination, the redirected
    destination is itself a neighbour. Verify the cache is updated
    for the destination address (not a separate router).
    """

    def test__icmp6__rx__redirect__on_link_signal__updates_cache(self) -> None:
        """
        Ensure a Redirect with Target == Destination still
        produces an ND-cache update for the supplied TLLA — the
        on-link signal that "this destination is a neighbour."

        Reference: RFC 4861 §4.5 (Target equals Destination semantics).
        """

        frame = self._make_nd_redirect_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            target=HOST_A__IP6_ADDRESS,  # Target == Destination
            destination=HOST_A__IP6_ADDRESS,
            tlla=HOST_A__MAC_ADDRESS,
        )

        self._drive_rx(frame=frame)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_redirect=1,
            icmp6__nd_redirect__update_nd_cache=1,
        )


class TestIcmp6Rx__NdRedirect__BadTarget(NdTestCase):
    """
    RFC 4861 §8.1 requires Target Address to be link-local OR
    equal to Destination. A global-unicast Target whose value is
    NOT the Destination must be dropped.
    """

    def test__icmp6__rx__redirect__bad_target__dropped(self) -> None:
        """
        Ensure a Redirect whose Target is a global-unicast
        address different from Destination is silently dropped
        without updating the cache.

        Reference: RFC 4861 §8.1 (Target MUST be link-local or equal Destination).
        """

        bad_target = Ip6Address("2001:db8:0:1::abcd")
        frame = self._make_nd_redirect_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            target=bad_target,
            destination=HOST_A__IP6_ADDRESS,
            tlla=TARGET__MAC,
        )

        self._drive_rx(frame=frame)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_redirect=1,
            icmp6__nd_redirect__bad_target__drop=1,
        )


class TestIcmp6Rx__NdRedirect__MulticastDestination(NdTestCase):
    """
    RFC 4861 §8.1 forbids the ICMP Destination Address field
    from being a multicast address. The parser's validate_sanity
    drops such frames at parse time.
    """

    def test__icmp6__rx__redirect__multicast_destination__parse_dropped(self) -> None:
        """
        Ensure a Redirect whose Destination Address is multicast
        is rejected by the parser's sanity validation — counted
        in 'icmp6__failed_parse__drop' rather than reaching the
        Redirect handler.

        Reference: RFC 4861 §8.1 (Destination MUST NOT be multicast).
        """

        multicast_dst = Ip6Address("ff02::1")  # all-nodes link-local
        frame = self._make_nd_redirect_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            target=TARGET__LINK_LOCAL,
            destination=multicast_dst,
            tlla=TARGET__MAC,
        )

        self._drive_rx(frame=frame)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__failed_parse__drop=1,
        )


class TestIcmp6Rx__NdRedirect__AcceptRedirectsZero(NdTestCase):
    """
    Linux's 'net.ipv6.conf.<iface>.accept_redirects = 0' must
    silently drop every inbound Redirect regardless of its
    contents.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so the per-test override does not
        leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__rx__redirect__accept_redirects_zero__dropped(self) -> None:
        """
        Ensure setting 'icmp6.accept_redirects = 0' suppresses
        every Redirect's processing — no cache update, only the
        kill-switch counter is bumped.

        Reference: Linux net.ipv6.conf.<iface>.accept_redirects (mode 0).
        """

        with sysctl_module.override("icmp6.default.accept_redirects", 0):
            frame = self._make_nd_redirect_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                target=TARGET__LINK_LOCAL,
                destination=HOST_A__IP6_ADDRESS,
                tlla=TARGET__MAC,
            )
            self._drive_rx(frame=frame)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unicast=1,
            icmp6__pre_parse=1,
            icmp6__nd_redirect=1,
            icmp6__nd_redirect__accept_redirects_zero__drop=1,
        )
