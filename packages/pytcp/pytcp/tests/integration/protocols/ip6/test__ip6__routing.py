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
tests for IPv6 — Phase 2 next-hop decision pins.

pytcp/tests/integration/protocols/ip6/test__ip6__routing.py

ver 3.0.9
"""

from typing import cast
from unittest.mock import MagicMock

from net_addr import Ip6Address, Ip6IfAddr, Ip6Network, MacAddress
from pytcp import stack
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    STACK__IP6_GATEWAY,
    STACK__IP6_GATEWAY_MAC_ADDRESS,
    STACK__IP6_HOST,
    NetworkTestCase,
)

# Second interface address for the IPv6 multihoming pin.
_IFADDR_B = Ip6IfAddr("2001:db8:0:2::7/64")
_DST_ON_B = Ip6Address("2001:db8:0:2::50")
_DST_ON_B__MAC = MacAddress("02:00:00:00:00:50")


def _eth_dst(frame: bytes) -> MacAddress:
    """
    Extract the Ethernet II destination MAC (first 6 octets).
    """

    return MacAddress(frame[0:6])


class TestIp6RoutingNextHop(NetworkTestCase):
    """
    The host-mode FIB IPv6 next-hop decision tests.
    """

    def test__ip6__routing__multihomed_on_link_dst_resolved_directly(self) -> None:
        """
        Ensure an IPv6 destination that is on-link for a
        different interface address than the packet's source
        address is resolved directly, not via the default
        router. Destination-keyed, Linux-correct behaviour — a
        deliberate change from the prior source-coupled scan.

        Reference: RFC 1122 §3.3.1 (next-hop selection / longest-prefix match).
        Reference: RFC 4861 §5.2 (IPv6 next-hop determination is destination-keyed).
        """

        self._packet_handler._ip6_ifaddr = [STACK__IP6_HOST, _IFADDR_B]

        def _nd(*, ip6_address: Ip6Address) -> MacAddress | None:
            return {
                _DST_ON_B: _DST_ON_B__MAC,
                STACK__IP6_GATEWAY: STACK__IP6_GATEWAY_MAC_ADDRESS,
            }.get(ip6_address)

        # The harness binds 'self._nd_cache' to a strict
        # autospec mock; the cast surfaces the test-time mock
        # type to mypy (typing.md §17 — test-time type fact mypy
        # cannot model through the harness swap).
        cast(MagicMock, self._nd_cache).find_entry.side_effect = _nd

        status = self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=_DST_ON_B,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="On-link multihomed IPv6 destination must be sent, not dropped.",
        )
        self.assertEqual(
            _eth_dst(self._frames_tx[0]),
            _DST_ON_B__MAC,
            msg="On-link IPv6 destination must resolve to its own MAC, not the router MAC.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send,
            1,
            msg="Multihomed on-link IPv6 destination must take the locnet (direct) path.",
        )

    def test__ip6__routing__off_link_dst_resolved_via_default_router(self) -> None:
        """
        Ensure an IPv6 destination matched only by the ::/0
        default route is resolved via that route's (link-local)
        router MAC.

        Reference: RFC 4861 §6.3.6 (default router selection).
        """

        status = self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=_DST_ON_B,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Off-link IPv6 destination with a default route must be sent.",
        )
        self.assertEqual(
            _eth_dst(self._frames_tx[0]),
            STACK__IP6_GATEWAY_MAC_ADDRESS,
            msg="Off-link IPv6 destination must resolve to the default router's MAC.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send,
            1,
            msg="Off-link IPv6 destination must take the extnet-gateway path.",
        )

    def test__ip6__routing__no_route_drops(self) -> None:
        """
        Ensure an off-link IPv6 destination with no matching
        route is dropped without emitting a frame.

        Reference: RFC 4861 §5.2 (IPv6 next-hop determination — no route).
        """

        stack.ip6_fib.remove(destination=Ip6Network("::/0"))

        status = self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=Ip6Address("2606:4700:4700::1111"),
        )

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP6,
            msg="An off-link IPv6 destination with no route must drop.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="A no-route IPv6 drop must not emit a frame.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_tx.ethernet__dst_unspec__ip6_lookup__extnet__no_gw__drop,
            1,
            msg="A no-route IPv6 drop must bump the extnet no-gateway drop counter.",
        )
