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
This module contains integration tests for the IGMP policy sysctls
('igmp.max_memberships' and friends).

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__sysctls.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.igmp import igmp__constants
from pytcp.stack import sysctl
from pytcp.tests.lib.network_testcase import NetworkTestCase


class TestIgmpSysctls(NetworkTestCase):
    """
    The IGMP policy-sysctl tests.
    """

    def test__igmp__sysctl__defaults_registered(self) -> None:
        """
        Ensure the IGMP timing / robustness knobs register with their
        documented defaults.

        Reference: RFC 3376 §8.1 (Robustness Variable default 2).
        Reference: RFC 3376 §8.11 (Unsolicited Report Interval default 1 s).
        """

        self.assertEqual(sysctl.get("igmp.robustness"), 2)
        self.assertEqual(sysctl.get("igmp.unsolicited_report_interval"), 1000)
        self.assertEqual(sysctl.get("igmp.max_memberships"), 20)

    def test__igmp__sysctl__override_updates_module_attr(self) -> None:
        """
        Ensure overriding 'igmp.robustness' updates the backing module
        attribute that the TX path reads via qualified access.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl.override("igmp.robustness", 5):
            self.assertEqual(igmp__constants.IGMP__ROBUSTNESS_VARIABLE, 5)

        self.assertEqual(igmp__constants.IGMP__ROBUSTNESS_VARIABLE, 2)

    def test__igmp__sysctl__robustness_rejects_non_positive(self) -> None:
        """
        Ensure the 'igmp.robustness' validator rejects a non-positive
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("igmp.robustness", 0)

    def test__igmp__max_memberships__caps_joins(self) -> None:
        """
        Ensure the membership API rejects a join once
        'igmp.max_memberships' joined groups exist (the implicit
        all-systems group does not count).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl.override("igmp.max_memberships", 2):
            stack.membership.join(group=Ip4Address("239.1.1.1"))
            stack.membership.join(group=Ip4Address("239.2.2.2"))

            with self.assertRaises(ValueError) as error:
                stack.membership.join(group=Ip4Address("239.3.3.3"))

            self.assertIn("membership limit", str(error.exception))

    def test__igmp__max_memberships__all_systems_does_not_count(self) -> None:
        """
        Ensure the implicit all-systems group 224.0.0.1 does not consume
        a membership slot.

        Reference: RFC 1112 §4 (all-systems group joined implicitly).
        """

        # The harness preseeds 224.0.0.1; with a limit of 1, one app
        # join must still succeed despite 224.0.0.1 being present.
        with sysctl.override("igmp.max_memberships", 1):
            stack.membership.join(group=Ip4Address("239.1.1.1"))

        self.assertIn(Ip4Address("239.1.1.1"), self._packet_handler._ip4_multicast)
