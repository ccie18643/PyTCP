#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# tests/unit/test_config.py - unit tests for config
#
# ver 3.0.2
#


from testslide import TestCase

from pytcp.config import IP4__SUPPORT_ENABLED, IP6__SUPPORT_ENABLED


class TestConfig(TestCase):
    """
    Config test class.
    """

    def test_ipv6_support(self) -> None:
        """
        Test the 'ipv6_support' config parameter.
        """
        self.assertEqual(IP6__SUPPORT_ENABLED, True)

    def test_ipv4_support(self) -> None:
        """
        Test the 'ipv4_support' config parameter.
        """
        self.assertEqual(IP4__SUPPORT_ENABLED, True)
