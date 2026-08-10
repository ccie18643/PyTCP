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
Integration tests for the IPv6 Neighbor Discovery RA parameter
mirror state per RFC 4861 §6.3.4 — nd_linux_parity §13. The host
captures three RA-header fields into observable host state:

    Cur-Hop-Limit   → outbound IPv6 default Hop Limit
    Reachable Time  → NUD REACHABLE state timeout
    Retrans Timer   → NS retransmission interval

A field value of zero per RFC 4861 §4.2 means "unspecified by this
router" and MUST NOT overwrite the existing host value. The Linux-
parity sysctl 'icmp6.accept_ra_min_hop_limit' floors the
acceptable Cur-Hop-Limit (mirrors
'net.ipv6.conf.<iface>.accept_ra_min_hop_limit'); below the floor
the field is silently dropped.

Consumer integration (TX-side default hop, NUD reachable_time,
DAD retrans_time override) is a separate phase — this commit only
pins the wire-state observation. The 'get_icmp6_ra_parameters()'
accessor exposes the captured values for tests and future
consumers.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__ra_parameters.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip6Address, MacAddress
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

ROUTER__LINK_LOCAL = Ip6Address("fe80::1")
ROUTER__MAC = MacAddress("02:00:00:00:00:01")


class TestIcmp6Nd__RaParameters__InitialState(NdTestCase):
    """
    Fresh packet handler exposes a parameter snapshot whose
    fields are all None — no RA observation has happened yet.
    """

    def test__icmp6__nd__ra_parameters__initial_state_all_none(self) -> None:
        """
        Ensure 'get_icmp6_ra_parameters()' on a freshly-built
        packet handler returns a snapshot whose cur_hop_limit,
        reachable_time_ms, and retrans_timer_ms fields are all
        None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        params = self._packet_handler.get_icmp6_ra_parameters()

        self.assertIsNone(
            params.cur_hop_limit,
            msg=f"Initial cur_hop_limit must be None. Got: {params!r}",
        )
        self.assertIsNone(
            params.reachable_time_ms,
            msg=f"Initial reachable_time_ms must be None. Got: {params!r}",
        )
        self.assertIsNone(
            params.retrans_timer_ms,
            msg=f"Initial retrans_timer_ms must be None. Got: {params!r}",
        )


class TestIcmp6Nd__RaParameters__CurHopLimit(NdTestCase):
    """
    Cur-Hop-Limit field handling: non-zero advertised values
    overwrite the stored mirror; zero means "unspecified" and
    must not overwrite an existing value; values below the
    'accept_ra_min_hop_limit' sysctl are silently dropped.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__cur_hop_limit_nonzero_stored(self) -> None:
        """
        Ensure a non-zero Cur-Hop-Limit field on an inbound RA
        is captured into the host's parameter mirror.

        Reference: RFC 4861 §6.3.4 (Cur-Hop-Limit copy on non-zero).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                hop=64,
            ),
        )

        params = self._packet_handler.get_icmp6_ra_parameters()
        self.assertEqual(
            params.cur_hop_limit,
            64,
            msg=f"Non-zero RA Cur-Hop-Limit must be captured. Got: {params!r}",
        )

    def test__icmp6__nd__ra__cur_hop_limit_zero_does_not_overwrite(self) -> None:
        """
        Ensure a zero Cur-Hop-Limit field on a follow-up RA does
        NOT overwrite the previously-captured value — zero means
        "unspecified by this router".

        Reference: RFC 4861 §4.2 (Cur-Hop-Limit zero is unspecified).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                hop=64,
            ),
        )
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                hop=0,
            ),
        )

        params = self._packet_handler.get_icmp6_ra_parameters()
        self.assertEqual(
            params.cur_hop_limit,
            64,
            msg=f"Zero Cur-Hop-Limit must not overwrite prior value. Got: {params!r}",
        )

    def test__icmp6__nd__ra__cur_hop_limit_below_floor_dropped(self) -> None:
        """
        Ensure 'icmp6.accept_ra_min_hop_limit' floors the
        accepted Cur-Hop-Limit value — values below the
        configured floor are silently dropped without
        overwriting the host's mirror.

        Reference: Linux 'net.ipv6.conf.<iface>.accept_ra_min_hop_limit'.
        """

        with sysctl_module.override("icmp6.default.accept_ra_min_hop_limit", 128):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    hop=64,
                ),
            )

        params = self._packet_handler.get_icmp6_ra_parameters()
        self.assertIsNone(
            params.cur_hop_limit,
            msg=f"Below-floor Cur-Hop-Limit must not update mirror. Got: {params!r}",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__nd_router_advertisement__cur_hop_limit__floor__drop,
            1,
            msg="Below-floor Cur-Hop-Limit must bump floor__drop counter.",
        )

    def test__icmp6__nd__ra__cur_hop_limit_at_floor_accepted(self) -> None:
        """
        Ensure a Cur-Hop-Limit value exactly equal to the
        'accept_ra_min_hop_limit' floor is accepted (the
        comparison is >=, not >).

        Reference: Linux 'net.ipv6.conf.<iface>.accept_ra_min_hop_limit' (≥ semantics).
        """

        with sysctl_module.override("icmp6.default.accept_ra_min_hop_limit", 64):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    hop=64,
                ),
            )

        params = self._packet_handler.get_icmp6_ra_parameters()
        self.assertEqual(
            params.cur_hop_limit,
            64,
            msg=f"Floor-equal Cur-Hop-Limit must be accepted. Got: {params!r}",
        )


class TestIcmp6Nd__RaParameters__ReachableTime(NdTestCase):
    """
    Reachable-Time field handling: non-zero advertised values
    overwrite the stored mirror; zero means "unspecified".
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__ra__reachable_time_nonzero_stored(self) -> None:
        """
        Ensure a non-zero Reachable-Time field on an inbound RA
        is captured into the host's parameter mirror.

        Reference: RFC 4861 §6.3.4 (Reachable Time copy on non-zero).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                reachable_time=45000,
            ),
        )

        params = self._packet_handler.get_icmp6_ra_parameters()
        self.assertEqual(
            params.reachable_time_ms,
            45000,
            msg=f"Non-zero RA Reachable-Time must be captured. Got: {params!r}",
        )

    def test__icmp6__nd__ra__reachable_time_zero_does_not_overwrite(self) -> None:
        """
        Ensure a zero Reachable-Time field on a follow-up RA
        does NOT overwrite the previously-captured value.

        Reference: RFC 4861 §4.2 (Reachable Time zero is unspecified).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                reachable_time=45000,
            ),
        )
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                reachable_time=0,
            ),
        )

        params = self._packet_handler.get_icmp6_ra_parameters()
        self.assertEqual(
            params.reachable_time_ms,
            45000,
            msg=f"Zero Reachable-Time must not overwrite prior value. Got: {params!r}",
        )


class TestIcmp6Nd__RaParameters__RetransTimer(NdTestCase):
    """
    Retrans-Timer field handling: non-zero advertised values
    overwrite the stored mirror; zero means "unspecified".
    """

    def test__icmp6__nd__ra__retrans_timer_nonzero_stored(self) -> None:
        """
        Ensure a non-zero Retrans-Timer field on an inbound RA
        is captured into the host's parameter mirror.

        Reference: RFC 4861 §6.3.4 (Retrans Timer copy on non-zero).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                retrans_timer=1500,
            ),
        )

        params = self._packet_handler.get_icmp6_ra_parameters()
        self.assertEqual(
            params.retrans_timer_ms,
            1500,
            msg=f"Non-zero RA Retrans-Timer must be captured. Got: {params!r}",
        )

    def test__icmp6__nd__ra__retrans_timer_zero_does_not_overwrite(self) -> None:
        """
        Ensure a zero Retrans-Timer field on a follow-up RA
        does NOT overwrite the previously-captured value.

        Reference: RFC 4861 §4.2 (Retrans Timer zero is unspecified).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                retrans_timer=1500,
            ),
        )
        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                retrans_timer=0,
            ),
        )

        params = self._packet_handler.get_icmp6_ra_parameters()
        self.assertEqual(
            params.retrans_timer_ms,
            1500,
            msg=f"Zero Retrans-Timer must not overwrite prior value. Got: {params!r}",
        )


class TestIcmp6Nd__RaParameters__UpdateCounters(NdTestCase):
    """
    Update counters for the three parameter fields are bumped
    independently — tests that pin one update don't accidentally
    pin the others.
    """

    def test__icmp6__nd__ra__all_three_fields_bump_distinct_counters(self) -> None:
        """
        Ensure a single RA carrying non-zero values for all
        three fields bumps each update counter exactly once.

        Reference: RFC 4861 §6.3.4 (RA processing — host parameter copy).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                hop=64,
                reachable_time=30000,
                retrans_timer=1000,
            ),
        )

        stats = self._packet_handler._packet_stats_rx
        self.assertEqual(
            stats.icmp6__nd_router_advertisement__cur_hop_limit__update,
            1,
            msg="Non-zero Cur-Hop-Limit must bump cur_hop_limit__update.",
        )
        self.assertEqual(
            stats.icmp6__nd_router_advertisement__reachable_time__update,
            1,
            msg="Non-zero Reachable-Time must bump reachable_time__update.",
        )
        self.assertEqual(
            stats.icmp6__nd_router_advertisement__retrans_timer__update,
            1,
            msg="Non-zero Retrans-Timer must bump retrans_timer__update.",
        )
