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
# tests/unit/arp_phrx.py -  Tests specific for ARP PHRX module.
#
# ver 2.7
#


from testslide import TestCase


class TestArpPhrx(TestCase):
    """
    Test ARP phtx module.
    """

    def setUp(self) -> None:
        """
        Setup test environment.
        """

        super().setUp()

    def test__arp_phrx__arp_request(self) -> None:
        """
        Validate that receiving ARP request packet works as expected.
        """

        # TODO: Implement test.

        pass

    def test__arp_phrx__arp_reply(self) -> None:
        """
        Validate that receiving ARP request packet works as expected.
        """

        # TODO: Implement test.

        pass
