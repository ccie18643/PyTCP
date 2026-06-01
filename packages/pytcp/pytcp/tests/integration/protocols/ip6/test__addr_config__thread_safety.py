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
This module contains the per-interface address-configuration
thread-safety tests — pinning that every cross-thread mutation of
the IPv4 / IPv6 interface-address, SLAAC / temporary / default-
router and DAD-state structures happens under the interface
address-config lock AND publishes a fresh object (copy-on-write),
so the per-packet RX / TX readers iterate an immutable snapshot
and never tear on a free-threaded build.

packages/pytcp/pytcp/tests/integration/protocols/ip6/test__addr_config__thread_safety.py

ver 3.0.8
"""

import threading
from typing import override

from net_addr import Ip4IfAddr, Ip6Address, Ip6IfAddr, Ip6Mask
from pytcp.stack import sysctl
from pytcp.tests.lib.network_testcase import NetworkTestCase

_IP6_HOST = Ip6IfAddr((Ip6Address("2001:db8:cafe::99"), Ip6Mask("/64")))
_IP4_HOST = Ip4IfAddr("10.99.0.1/24")
_IP6_MCAST = Ip6Address("ff02::dead")
_ROUTER = Ip6Address("fe80::1234")
_DAD_CANDIDATE = Ip6Address("2001:db8:cafe::dad")


class _TrackingRLock:
    """
    A reentrant lock recording the maximum hold depth reached so a
    test can prove an address-config write acquired the lock and
    released it afterwards.
    """

    def __init__(self) -> None:
        """
        Wrap a real reentrant lock and start at zero hold depth.
        """

        self._lock = threading.RLock()
        self.depth = 0
        self.max_depth = 0

    def __enter__(self) -> "_TrackingRLock":
        """
        Acquire the underlying lock and record the deeper hold.
        """

        self._lock.acquire()
        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        return self

    def __exit__(self, *_: object) -> None:
        """
        Record the shallower hold and release the underlying lock.
        """

        self.depth -= 1
        self._lock.release()


class TestAddressConfigLocking(NetworkTestCase):
    """
    The per-interface address-config copy-on-write + lock tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and install a depth-tracking lock in place
        of the real address-config lock for every test.
        """

        super().setUp()
        self._tracking = _TrackingRLock()
        setattr(self._packet_handler, "_lock__addr_config", self._tracking)

    def test__addr_config__assign_ip6_host_cow_under_lock(self) -> None:
        """
        Ensure assigning an IPv6 interface address publishes a fresh
        '_ip6_ifaddr' list (copy-on-write) while holding the
        address-config lock, leaving the prior snapshot untouched so
        a concurrent RX / TX reader iterating it cannot tear.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = self._packet_handler
        old = handler._ip6_ifaddr

        handler._assign_ip6_host(ip6_host=_IP6_HOST)

        self.assertIsNot(
            handler._ip6_ifaddr,
            old,
            msg="_assign_ip6_host must publish a new _ip6_ifaddr list (copy-on-write).",
        )
        self.assertNotIn(
            _IP6_HOST,
            old,
            msg="The prior _ip6_ifaddr snapshot must be left untouched.",
        )
        self.assertIn(
            _IP6_HOST,
            handler._ip6_ifaddr,
            msg="The assigned host must be present in the published _ip6_ifaddr list.",
        )
        self.assertGreaterEqual(
            self._tracking.max_depth,
            1,
            msg="_assign_ip6_host must acquire the address-config lock.",
        )
        self.assertEqual(
            self._tracking.depth,
            0,
            msg="_assign_ip6_host must release the address-config lock.",
        )

    def test__addr_config__assign_ip4_host_cow_under_lock(self) -> None:
        """
        Ensure assigning an IPv4 interface address publishes a fresh
        '_ip4_ifaddr' list (copy-on-write) while holding the
        address-config lock, leaving the prior snapshot untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = self._packet_handler
        old = handler._ip4_ifaddr

        handler._assign_ip4_host(ip4_host=_IP4_HOST)

        self.assertIsNot(
            handler._ip4_ifaddr,
            old,
            msg="_assign_ip4_host must publish a new _ip4_ifaddr list (copy-on-write).",
        )
        self.assertNotIn(
            _IP4_HOST,
            old,
            msg="The prior _ip4_ifaddr snapshot must be left untouched.",
        )
        self.assertGreaterEqual(
            self._tracking.max_depth,
            1,
            msg="_assign_ip4_host must acquire the address-config lock.",
        )

    def test__addr_config__assign_ip6_multicast_cow_under_lock(self) -> None:
        """
        Ensure joining an IPv6 multicast group publishes a fresh
        '_ip6_multicast' list (copy-on-write) while holding the
        address-config lock, leaving the prior snapshot untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = self._packet_handler
        old = handler._ip6_multicast

        handler._assign_ip6_multicast(_IP6_MCAST)

        self.assertIsNot(
            handler._ip6_multicast,
            old,
            msg="_assign_ip6_multicast must publish a new _ip6_multicast list (copy-on-write).",
        )
        self.assertNotIn(
            _IP6_MCAST,
            old,
            msg="The prior _ip6_multicast snapshot must be left untouched.",
        )
        self.assertGreaterEqual(
            self._tracking.max_depth,
            1,
            msg="_assign_ip6_multicast must acquire the address-config lock.",
        )

    def test__addr_config__update_default_router_cow_under_lock(self) -> None:
        """
        Ensure installing an RA default router publishes a fresh
        '_icmp6_default_routers' list (copy-on-write) while holding
        the address-config lock, leaving the prior snapshot
        untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = self._packet_handler
        old = handler._icmp6_default_routers

        handler._update_icmp6_default_router(address=_ROUTER, router_lifetime=1800)

        self.assertIsNot(
            handler._icmp6_default_routers,
            old,
            msg="_update_icmp6_default_router must publish a new list (copy-on-write).",
        )
        self.assertGreaterEqual(
            self._tracking.max_depth,
            1,
            msg="_update_icmp6_default_router must acquire the address-config lock.",
        )

    def test__addr_config__dad_state_cow_under_lock(self) -> None:
        """
        Ensure a DAD-state transition publishes a fresh
        '_icmp6_dad__states' dict (copy-on-write) while holding the
        address-config lock, so the RX / TX readers that '.get' a
        candidate's state never tear against the DAD-claim thread.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = self._packet_handler
        old = handler._icmp6_dad__states

        # 'accept_dad=0' short-circuits DAD to a single VALID dict
        # write with no probes / blocking waits.
        with sysctl.override("icmp6.default.accept_dad", 0):
            handler._perform_ip6_nd_dad(ip6_unicast_candidate=_DAD_CANDIDATE)

        self.assertIsNot(
            handler._icmp6_dad__states,
            old,
            msg="A DAD-state write must publish a new _icmp6_dad__states dict (copy-on-write).",
        )
        self.assertNotIn(
            _DAD_CANDIDATE,
            old,
            msg="The prior _icmp6_dad__states snapshot must be left untouched.",
        )
        self.assertGreaterEqual(
            self._tracking.max_depth,
            1,
            msg="The DAD-state write must acquire the address-config lock.",
        )
