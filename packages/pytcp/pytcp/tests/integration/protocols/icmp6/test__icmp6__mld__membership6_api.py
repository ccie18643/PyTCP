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
This module contains integration tests for the IPv6 multicast-membership
control API (stack.membership6) — the MLDv2 analogue of stack.membership.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld__membership6_api.py

ver 3.0.8
"""

from net_addr import Ip6Address
from pytcp import stack
from pytcp.lib.ip6_multicast_filter import (
    Ip6MulticastFilter,
    Ip6MulticastFilterMode,
)
from pytcp.tests.lib.network_testcase import NetworkTestCase

_GROUP = Ip6Address("ff15::abcd")
_ALL_NODES = Ip6Address("ff02::1")
_SRC_A = Ip6Address("2001:db8::1")
_TOKEN = 4242


class TestMld6MembershipApi(NetworkTestCase):
    """
    The IPv6 multicast-membership-control API tests.
    """

    def test__membership6__join_adds_group_and_mac(self) -> None:
        """
        Ensure 'join' records the group on the interface listen set,
        programs its Ethernet multicast MAC, and surfaces it through
        'list_memberships'.

        Reference: RFC 4291 §2.7 (IPv6 multicast addressing).
        Reference: RFC 2464 §7 (IPv6-to-Ethernet multicast MAC mapping).
        """

        stack.membership6.join(group=_GROUP)

        self.assertIn(_GROUP, self._packet_handler._ip6_multicast)
        self.assertIn(_GROUP.multicast_mac, self._packet_handler._mac_multicast)
        self.assertIn(_GROUP, stack.membership6.list_memberships())

    def test__membership6__join_is_idempotent(self) -> None:
        """
        Ensure joining a group the interface already listens on is a
        no-op (no duplicate group entry).

        Reference: RFC 3810 §4.2 (interface state is membership, not a count).
        """

        stack.membership6.join(group=_GROUP)
        stack.membership6.join(group=_GROUP)

        self.assertEqual(
            self._packet_handler._ip6_multicast.count(_GROUP),
            1,
            msg="A re-joined group must not be duplicated on the listen set.",
        )

    def test__membership6__join_rejects_non_multicast(self) -> None:
        """
        Ensure joining a non-multicast address is rejected.

        Reference: RFC 4291 §2.7 (membership is for multicast groups).
        """

        with self.assertRaises(ValueError):
            stack.membership6.join(group=Ip6Address("2001:db8::1"))

    def test__membership6__leave_removes_group(self) -> None:
        """
        Ensure 'leave' drops the operator hold and removes the group from
        the interface listen set once no contributor remains.

        Reference: RFC 3810 §6.1 (leave on the last contributor drop).
        """

        stack.membership6.join(group=_GROUP)
        stack.membership6.leave(group=_GROUP)

        self.assertNotIn(_GROUP, self._packet_handler._ip6_multicast)

    def test__membership6__leave_rejects_all_nodes(self) -> None:
        """
        Ensure leaving the permanent all-nodes group ff02::1 is refused —
        a host belongs to it permanently.

        Reference: RFC 4291 §2.7.1 (all-nodes is a permanent membership).
        """

        with self.assertRaises(ValueError):
            stack.membership6.leave(group=_ALL_NODES)

    def test__membership6__leave_rejects_non_multicast(self) -> None:
        """
        Ensure leaving a non-multicast address is rejected.

        Reference: RFC 4291 §2.7 (membership is for multicast groups).
        """

        with self.assertRaises(ValueError):
            stack.membership6.leave(group=Ip6Address("2001:db8::1"))

    def test__membership6__set_socket_filter_joins_include(self) -> None:
        """
        Ensure 'set_socket_filter' with a non-empty INCLUDE filter joins
        the group and materializes exactly that filter on the interface.

        Reference: RFC 3810 §4.1 (per-socket INCLUDE source list).
        """

        source_filter = Ip6MulticastFilter(Ip6MulticastFilterMode.INCLUDE, frozenset({_SRC_A}))
        stack.membership6.set_socket_filter(group=_GROUP, token=_TOKEN, source_filter=source_filter)

        self.assertEqual(
            self._packet_handler._ip6_multicast_filters[_GROUP],
            source_filter,
            msg="The interface filter must equal the single socket's INCLUDE filter.",
        )

    def test__membership6__clear_socket_filter_leaves_group(self) -> None:
        """
        Ensure 'clear_socket_filter' drops the socket's hold and leaves
        the group when it was the last contributor.

        Reference: RFC 3810 §4.1 (per-socket INCLUDE{} delete).
        """

        source_filter = Ip6MulticastFilter(Ip6MulticastFilterMode.EXCLUDE)
        stack.membership6.set_socket_filter(group=_GROUP, token=_TOKEN, source_filter=source_filter)
        self.assertIn(_GROUP, self._packet_handler._ip6_multicast)

        stack.membership6.clear_socket_filter(group=_GROUP, token=_TOKEN)

        self.assertNotIn(_GROUP, self._packet_handler._ip6_multicast)

    def test__membership6__unbound_tool_requires_interface(self) -> None:
        """
        Ensure the unbound device-independent tool raises when an
        operation is attempted without selecting an interface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.stack.membership6 import Membership6Api

        with self.assertRaises(RuntimeError):
            Membership6Api().join(group=_GROUP)
