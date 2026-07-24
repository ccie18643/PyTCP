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
This module contains tests for the NetAddr package IP version enum.

net_addr/tests/unit/test__ip_version.py

ver 3.0.8
"""

from enum import IntEnum
from unittest import TestCase

from net_addr import IpVersion


class TestNetAddrIpVersion(TestCase):
    """
    The NetAddr IpVersion enum tests.
    """

    def test__net_addr__ip_version__is_int_enum(self) -> None:
        """
        Ensure IpVersion is an IntEnum so its members are usable
        directly as integers (per the enum-discipline rule),
        without a hand-rolled '__int__'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(IpVersion, IntEnum),
            msg="IpVersion must be an IntEnum.",
        )
        self.assertIsInstance(
            IpVersion.IP4,
            int,
            msg="An IpVersion member must be an int instance.",
        )

    def test__net_addr__ip_version__int_value(self) -> None:
        """
        Ensure each IpVersion member equals and converts to its
        IP-version number.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(int(IpVersion.IP4), 4, msg="int(IpVersion.IP4) must be 4.")
        self.assertEqual(int(IpVersion.IP6), 6, msg="int(IpVersion.IP6) must be 6.")
        self.assertEqual(IpVersion.IP4, 4, msg="IpVersion.IP4 must compare equal to 4.")
        self.assertEqual(IpVersion.IP6, 6, msg="IpVersion.IP6 must compare equal to 6.")

    def test__net_addr__ip_version__member_identity(self) -> None:
        """
        Ensure members remain singletons usable by identity and
        the enum exposes exactly IP4 and IP6.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            IpVersion(4),
            IpVersion.IP4,
            msg="IpVersion(4) must be the IP4 singleton.",
        )
        self.assertEqual(
            list(IpVersion),
            [IpVersion.IP4, IpVersion.IP6],
            msg="IpVersion must expose exactly IP4 and IP6.",
        )
