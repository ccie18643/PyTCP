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
Integration tests for the IPv6 Neighbor Discovery SLAAC per-prefix
lifetime tracking — the wire-state half of nd_linux_parity §12.

PyTCP previously consumed each RA's Prefix-Information options once
at boot to derive an EUI-64 SLAAC address, then forgot the
preferred / valid lifetime values. The host now stores a per-prefix
'Icmp6SlaacAddress(prefix, preferred_until, valid_until)' entry per
admitted PI option, refreshes it on each subsequent RA, and removes
it when an inbound PI advertises 'valid_lifetime=0' (RFC 4862
§5.5.3 (e)(4) / (e)(6)(a) interaction). The full 2-hour rule
(§5.5.3 (e)(6) (b)/(c)) and the per-address state machine
(PREFERRED → DEPRECATED → REMOVED) are deferred to §12b.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__slaac_address_tracking.py

ver 3.0.10
"""

import time
from typing import override
from unittest.mock import patch

from net_addr import Ip6Address, Ip6Network, MacAddress
from net_proto import Icmp6NdOptionPi
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

ROUTER__LINK_LOCAL = Ip6Address("fe80::1")
ROUTER__MAC = MacAddress("02:00:00:00:00:01")

PREFIX_A = Ip6Network("2001:db8:0:1::/64")
PREFIX_B = Ip6Network("2001:db8:0:2::/64")


def _pi_option(
    *,
    prefix: Ip6Network,
    valid_lifetime: int,
    preferred_lifetime: int,
    flag_a: bool = True,
    flag_l: bool = True,
) -> Icmp6NdOptionPi:
    """
    Build a Prefix-Information option with autoconfiguration enabled.
    """

    return Icmp6NdOptionPi(
        flag_l=flag_l,
        flag_a=flag_a,
        flag_r=False,
        valid_lifetime=valid_lifetime,
        preferred_lifetime=preferred_lifetime,
        prefix=prefix,
    )


class TestIcmp6Nd__SlaacPrefix__Install(NdTestCase):
    """
    A non-zero-lifetime PI installs an Icmp6SlaacAddress entry.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__pi__nonzero_lifetimes_install_entry(self) -> None:
        """
        Ensure an admitted PI option with a non-zero valid
        lifetime installs an Icmp6SlaacAddress entry whose
        deadlines are 'time.monotonic()' offsets of the
        advertised values.

        Reference: RFC 4862 §5.5.3 (e)(4) (autoconfig: form / refresh
        an address from a non-zero-Valid-Lifetime PI).
        """

        before = time.monotonic()
        frame = self._make_nd_ra_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=1800,
            options=[
                _pi_option(
                    prefix=PREFIX_A,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                ),
            ],
        )

        self._drive_rx(frame=frame)

        prefixes = self._packet_handler._icmp6_slaac_addresses
        self.assertEqual(
            len(prefixes),
            1,
            msg=f"Expected one SLAAC prefix entry, got {prefixes!r}",
        )
        entry = prefixes[0]
        self.assertEqual(
            entry.prefix,
            PREFIX_A,
            msg=f"SLAAC prefix entry must store the advertised prefix. Got: {entry!r}",
        )
        self.assertGreaterEqual(
            entry.valid_until,
            before + 2592000,
            msg=f"valid_until must be at least now + advertised valid_lifetime. Got: {entry!r}",
        )
        self.assertGreaterEqual(
            entry.preferred_until,
            before + 604800,
            msg=f"preferred_until must be at least now + advertised preferred_lifetime. Got: {entry!r}",
        )

    def test__icmp6__nd__pi__update_address_packet_stats(self) -> None:
        """
        Ensure an admitted non-zero-lifetime PI bumps the
        'icmp6__nd_router_advertisement__pi__update_address'
        counter.

        Reference: RFC 4862 §5.5.3 (e)(4) (autoconfig install path).
        """

        frame = self._make_nd_ra_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=1800,
            options=[
                _pi_option(
                    prefix=PREFIX_A,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                ),
            ],
        )

        self._drive_rx(frame=frame)

        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__nd_router_advertisement__pi__update_address,
            1,
            msg="Admitted non-zero-lifetime PI must bump the update_prefix counter.",
        )


class TestIcmp6Nd__SlaacPrefix__Refresh(NdTestCase):
    """
    A second PI for the same prefix refreshes lifetimes in place.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__pi__second_pi_updates_lifetimes_in_place(self) -> None:
        """
        Ensure two consecutive RAs carrying a PI for the same
        prefix produce a single entry whose lifetimes track the
        most-recent advertisement.

        Reference: RFC 4862 §5.5.3 (e)(5) (preferred-lifetime reset on match).
        """

        first = self._make_nd_ra_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=1800,
            options=[
                _pi_option(
                    prefix=PREFIX_A,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                ),
            ],
        )
        self._drive_rx(frame=first)

        second = self._make_nd_ra_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=1800,
            options=[
                _pi_option(
                    prefix=PREFIX_A,
                    valid_lifetime=86400,
                    preferred_lifetime=3600,
                ),
            ],
        )
        before_second = time.monotonic()
        self._drive_rx(frame=second)

        prefixes = self._packet_handler._icmp6_slaac_addresses
        self.assertEqual(
            len(prefixes),
            1,
            msg=f"Refresh on same prefix must not duplicate. Got: {prefixes!r}",
        )
        entry = prefixes[0]
        self.assertGreaterEqual(
            entry.valid_until,
            before_second + 86400,
            msg=f"Refresh must overwrite valid_until. Got: {entry!r}",
        )
        self.assertGreaterEqual(
            entry.preferred_until,
            before_second + 3600,
            msg=f"Refresh must overwrite preferred_until. Got: {entry!r}",
        )


class TestIcmp6Nd__SlaacPrefix__MultiplePrefixes(NdTestCase):
    """
    Distinct prefixes in the same RA produce distinct entries.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__pi__separate_prefixes_separate_entries(self) -> None:
        """
        Ensure a single RA carrying two PI options produces two
        distinct SLAAC prefix entries.

        Reference: RFC 4862 §5.5.3 (e)(4) (per-prefix autoconfiguration).
        """

        frame = self._make_nd_ra_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=1800,
            options=[
                _pi_option(
                    prefix=PREFIX_A,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                ),
                _pi_option(
                    prefix=PREFIX_B,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                ),
            ],
        )

        self._drive_rx(frame=frame)

        prefixes = {entry.prefix for entry in self._packet_handler._icmp6_slaac_addresses}
        self.assertEqual(
            prefixes,
            {PREFIX_A, PREFIX_B},
            msg=f"Two distinct PIs must produce two distinct entries. Got: {prefixes!r}",
        )


class TestIcmp6Nd__SlaacPrefix__ZeroValidLifetimeRemoves(NdTestCase):
    """
    A follow-up PI with valid_lifetime=0 removes the matching entry.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__pi__valid_lifetime_zero_removes_entry(self) -> None:
        """
        Ensure a follow-up PI with valid_lifetime=0 invalidates
        the matching SLAAC prefix — the (e)(6)(a) "set the valid
        lifetime to the advertised value" path collapses to
        removal when the advertised value is 0.

        Reference: RFC 4862 §5.5.3 (e)(6)(a) (advertised lifetime overwrites address valid lifetime).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                options=[
                    _pi_option(
                        prefix=PREFIX_A,
                        valid_lifetime=2592000,
                        preferred_lifetime=604800,
                    ),
                ],
            ),
        )

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                options=[
                    _pi_option(
                        prefix=PREFIX_A,
                        valid_lifetime=0,
                        preferred_lifetime=0,
                    ),
                ],
            ),
        )

        self.assertEqual(
            self._packet_handler._icmp6_slaac_addresses,
            [],
            msg=(
                "valid_lifetime=0 PI must remove the matching SLAAC entry. "
                f"Got: {self._packet_handler._icmp6_slaac_addresses!r}"
            ),
        )

    def test__icmp6__nd__pi__valid_lifetime_zero_remove_packet_stats(self) -> None:
        """
        Ensure the zero-lifetime PI invalidation path bumps the
        'icmp6__nd_router_advertisement__pi__remove_address'
        counter when an entry actually existed.

        Reference: RFC 4862 §5.5.3 (e)(6)(a) (advertised lifetime overwrites address valid lifetime).
        """

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                options=[
                    _pi_option(
                        prefix=PREFIX_A,
                        valid_lifetime=2592000,
                        preferred_lifetime=604800,
                    ),
                ],
            ),
        )

        before = self._packet_handler._packet_stats_rx.icmp6__nd_router_advertisement__pi__remove_address

        self._drive_rx(
            frame=self._make_nd_ra_frame(
                eth_src=ROUTER__MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip6_src=ROUTER__LINK_LOCAL,
                ip6_dst=STACK__IP6_ADDRESS,
                router_lifetime=1800,
                options=[
                    _pi_option(
                        prefix=PREFIX_A,
                        valid_lifetime=0,
                        preferred_lifetime=0,
                    ),
                ],
            ),
        )

        after = self._packet_handler._packet_stats_rx.icmp6__nd_router_advertisement__pi__remove_address
        self.assertEqual(
            after - before,
            1,
            msg="Zero-lifetime PI invalidation path must bump remove_prefix counter.",
        )


class TestIcmp6Nd__SlaacPrefix__LazyAgeing(NdTestCase):
    """
    The accessor 'get_icmp6_slaac_addresses' filters out entries past
    their valid_until deadline.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__slaac_prefixes__expired_filtered(self) -> None:
        """
        Ensure 'get_icmp6_slaac_addresses()' omits entries whose
        valid_until is in the past — lazy ageing, no background
        sweep needed.

        Reference: RFC 4862 §5.5.3 (e) (valid lifetime expiry implies
        no longer autoconfigurable).
        """

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=2000.0,
        ):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    options=[
                        _pi_option(
                            prefix=PREFIX_A,
                            valid_lifetime=120,
                            preferred_lifetime=60,
                        ),
                    ],
                ),
            )

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=2000.0 + 121,
        ):
            active = self._packet_handler.get_icmp6_slaac_addresses()

        self.assertEqual(
            active,
            [],
            msg=f"Expired SLAAC prefixes must not surface from accessor. Got: {active!r}",
        )


class TestIcmp6Nd__SlaacPrefix__SysctlAcceptRaPinfo(NdTestCase):
    """
    'icmp6.accept_ra_pinfo' = 0 disables PI consumption entirely
    (Linux parity).
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__pi__accept_ra_pinfo_zero_drops(self) -> None:
        """
        Ensure 'icmp6.accept_ra_pinfo=0' suppresses SLAAC entry
        installation and bumps the kill-switch drop counter.

        Reference: Linux 'net.ipv6.conf.<iface>.accept_ra_pinfo'.
        """

        with sysctl_module.override("icmp6.default.accept_ra_pinfo", 0):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    options=[
                        _pi_option(
                            prefix=PREFIX_A,
                            valid_lifetime=2592000,
                            preferred_lifetime=604800,
                        ),
                    ],
                ),
            )

        self.assertEqual(
            self._packet_handler._icmp6_slaac_addresses,
            [],
            msg=(
                "accept_ra_pinfo=0 must suppress SLAAC entry installation. "
                f"Got: {self._packet_handler._icmp6_slaac_addresses!r}"
            ),
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__nd_router_advertisement__pi__pinfo_disabled__drop,
            1,
            msg="accept_ra_pinfo=0 path must bump pinfo_disabled__drop counter.",
        )


class TestIcmp6Nd__SlaacPrefix__IndependentFromRouterLifetime(NdTestCase):
    """
    PI consumption is independent from default-router learning —
    a router_lifetime=0 RA must still install the SLAAC entry per
    RFC 4861 §6.3.4 ("the lifetime applies only to the router's
    usefulness as a default router; not to other information").
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__pi__processed_when_router_lifetime_zero(self) -> None:
        """
        Ensure a PI is consumed even when the carrying RA has
        router_lifetime=0 — the two state machines are
        independent.

        Reference: RFC 4861 §6.3.4 (Router Lifetime applies only to
        default-router usefulness, not other RA information).
        """

        frame = self._make_nd_ra_frame(
            eth_src=ROUTER__MAC,
            eth_dst=STACK__MAC_ADDRESS,
            ip6_src=ROUTER__LINK_LOCAL,
            ip6_dst=STACK__IP6_ADDRESS,
            router_lifetime=0,
            options=[
                _pi_option(
                    prefix=PREFIX_A,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                ),
            ],
        )

        self._drive_rx(frame=frame)

        self.assertEqual(
            len(self._packet_handler._icmp6_slaac_addresses),
            1,
            msg=(
                "PI must be consumed even when router_lifetime=0. "
                f"Got: {self._packet_handler._icmp6_slaac_addresses!r}"
            ),
        )
        self.assertEqual(
            self._packet_handler._icmp6_default_routers,
            [],
            msg=(
                "router_lifetime=0 must not install a default-router "
                f"entry. Got: {self._packet_handler._icmp6_default_routers!r}"
            ),
        )
