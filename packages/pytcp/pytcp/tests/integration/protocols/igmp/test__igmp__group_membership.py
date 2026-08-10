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
This module contains integration tests for the per-interface IPv4
multicast group state and its Ethernet multicast-MAC mapping.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__group_membership.py

ver 3.0.9
"""

from net_addr import Ip4Address, MacAddress
from pytcp.tests.lib.network_testcase import NetworkTestCase


class TestIgmpGroupMembership(NetworkTestCase):
    """
    The per-interface IPv4 multicast group-membership tests.
    """

    def test__igmp__assign_ip4_multicast__adds_group_and_mac(self) -> None:
        """
        Ensure assigning an IPv4 multicast group records it on the
        interface listen set and programs the matching Ethernet
        multicast MAC (01:00:5e + low 23 bits of the group).

        Reference: RFC 1112 §4 (host joins multicast groups).
        Reference: RFC 1112 §6.4 (IPv4-to-Ethernet multicast MAC mapping).
        """

        group = Ip4Address("239.1.1.1")

        self._packet_handler._assign_ip4_multicast(group)

        self.assertIn(
            group,
            self._packet_handler._ip4_multicast,
            msg="The joined group must appear on the interface listen set.",
        )
        self.assertIn(
            MacAddress("01:00:5e:01:01:01"),
            self._packet_handler._mac_multicast,
            msg="The group's Ethernet multicast MAC must be programmed on L2.",
        )

    def test__igmp__remove_ip4_multicast__drops_group_and_mac(self) -> None:
        """
        Ensure removing an IPv4 multicast group drops it from the listen
        set and unprograms its Ethernet multicast MAC.

        Reference: RFC 1112 §4 (host leaves multicast groups).
        Reference: RFC 1112 §6.4 (IPv4-to-Ethernet multicast MAC mapping).
        """

        group = Ip4Address("239.1.1.1")

        self._packet_handler._assign_ip4_multicast(group)
        self._packet_handler._remove_ip4_multicast(group)

        self.assertNotIn(
            group,
            self._packet_handler._ip4_multicast,
            msg="The left group must be removed from the interface listen set.",
        )
        self.assertNotIn(
            MacAddress("01:00:5e:01:01:01"),
            self._packet_handler._mac_multicast,
            msg="The group's Ethernet multicast MAC must be unprogrammed on leave.",
        )

    def test__igmp__assign_ip4_multicast__tracks_multiple_groups(self) -> None:
        """
        Ensure joining several IPv4 multicast groups tracks each group
        and each distinct multicast MAC independently.

        Reference: RFC 1112 §4 (a host may belong to several groups).
        """

        groups = [Ip4Address("239.1.1.1"), Ip4Address("239.2.2.2")]

        for group in groups:
            self._packet_handler._assign_ip4_multicast(group)

        for group in groups:
            self.assertIn(
                group,
                self._packet_handler._ip4_multicast,
                msg=f"Group {group} must be tracked on the interface listen set.",
            )
        self.assertIn(MacAddress("01:00:5e:01:01:01"), self._packet_handler._mac_multicast)
        self.assertIn(MacAddress("01:00:5e:02:02:02"), self._packet_handler._mac_multicast)

    def test__igmp__all_systems_group_maps_to_all_systems_mac(self) -> None:
        """
        Ensure the all-systems group 224.0.0.1 — joined permanently at
        interface bring-up — maps to the 01:00:5e:00:00:01 Ethernet
        multicast MAC.

        Reference: RFC 1112 §4 (all-systems group joined permanently).
        Reference: RFC 1112 §6.4 (IPv4-to-Ethernet multicast MAC mapping).
        """

        self.assertEqual(
            Ip4Address("224.0.0.1").multicast_mac,
            MacAddress("01:00:5e:00:00:01"),
            msg="224.0.0.1 must map to the all-systems Ethernet multicast MAC.",
        )
