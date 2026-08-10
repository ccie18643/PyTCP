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
This module contains integration tests for the multicast-membership
control API (stack.membership).

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__membership_api.py

ver 3.0.9
"""

from net_addr import Ip4Address, MacAddress
from pytcp import stack
from pytcp.tests.lib.network_testcase import NetworkTestCase


class TestIgmpMembershipApi(NetworkTestCase):
    """
    The multicast-membership-control API tests.
    """

    def test__membership__join_adds_group_and_mac(self) -> None:
        """
        Ensure 'join' records the group on the interface listen set,
        programs its Ethernet multicast MAC, and surfaces it through
        'list_memberships'.

        Reference: RFC 1112 §4 (host group membership).
        Reference: RFC 1112 §6.4 (IPv4-to-Ethernet multicast MAC mapping).
        """

        group = Ip4Address("239.1.1.1")

        stack.membership.join(group=group)

        self.assertIn(group, self._packet_handler._ip4_multicast)
        self.assertIn(MacAddress("01:00:5e:01:01:01"), self._packet_handler._mac_multicast)
        self.assertIn(group, stack.membership.list_memberships())

    def test__membership__join_is_idempotent(self) -> None:
        """
        Ensure joining a group the interface already listens on is a
        no-op (no duplicate group / MAC entry).

        Reference: RFC 1112 §4 (a host belongs to a group, not a count).
        """

        group = Ip4Address("239.1.1.1")

        stack.membership.join(group=group)
        stack.membership.join(group=group)

        self.assertEqual(
            self._packet_handler._ip4_multicast.count(group),
            1,
            msg="A re-joined group must not be duplicated on the listen set.",
        )

    def test__membership__join_rejects_non_multicast(self) -> None:
        """
        Ensure joining a non-multicast address is rejected.

        Reference: RFC 1112 §4 (membership is for multicast groups).
        """

        with self.assertRaises(ValueError) as error:
            stack.membership.join(group=Ip4Address("192.0.2.1"))

        self.assertIn("must be a multicast address", str(error.exception))

    def test__membership__leave_drops_group_and_mac(self) -> None:
        """
        Ensure 'leave' drops a joined group from the listen set and
        unprograms its Ethernet multicast MAC.

        Reference: RFC 1112 §4 (host leaves a multicast group).
        """

        group = Ip4Address("239.1.1.1")

        stack.membership.join(group=group)
        stack.membership.leave(group=group)

        self.assertNotIn(group, self._packet_handler._ip4_multicast)
        self.assertNotIn(MacAddress("01:00:5e:01:01:01"), self._packet_handler._mac_multicast)

    def test__membership__leave_not_joined_is_noop(self) -> None:
        """
        Ensure leaving a group the interface is not in is a silent no-op
        rather than an error.

        Reference: RFC 1112 §4 (leaving an unjoined group is harmless).
        """

        stack.membership.leave(group=Ip4Address("239.9.9.9"))

    def test__membership__leave_rejects_all_systems_group(self) -> None:
        """
        Ensure leaving the all-systems group 224.0.0.1 is refused — a
        host belongs to it permanently.

        Reference: RFC 1112 §4 (all-systems group joined permanently).
        """

        with self.assertRaises(ValueError) as error:
            stack.membership.leave(group=Ip4Address("224.0.0.1"))

        self.assertIn("224.0.0.1", str(error.exception))

    def test__membership__list_memberships_is_immutable_snapshot(self) -> None:
        """
        Ensure 'list_memberships' returns a copy-by-value tuple that the
        caller cannot mutate stack state through.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshot = stack.membership.list_memberships()

        self.assertIsInstance(snapshot, tuple)

        stack.membership.join(group=Ip4Address("239.1.1.1"))

        self.assertNotIn(
            Ip4Address("239.1.1.1"),
            snapshot,
            msg="A previously taken snapshot must not reflect later joins.",
        )

    def test__membership__interface_selector_binds_handler(self) -> None:
        """
        Ensure the unbound membership tool's 'interface(ifindex)'
        selector returns a view bound to that interface's group set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        bound = stack.membership.interface(self._packet_handler._ifindex)

        bound.join(group=Ip4Address("239.5.5.5"))

        self.assertIn(Ip4Address("239.5.5.5"), self._packet_handler._ip4_multicast)
