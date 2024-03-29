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
# tests/test_packet_handler.py - unit tests for PacketHandler class
#
# ver 2.7
#


from testslide import TestCase

from pytcp.subsystems.packet_handler import PacketHandler


class TestPacketHandler(TestCase):
    """
    Packet handler main unit test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """
        super().setUp()
        self.mock_callable(
            "pytcp.subsystems.packet_handler", "log"
        ).to_return_value(None)
        self.packet_handler = PacketHandler()
