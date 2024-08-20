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
# tests/unit/ethernet_fpa.py -  Tests specific for Ethernet FPA module.
#
# ver 3.0.0
#

from testslide import TestCase

from pytcp.protocols.ethernet.fpa import EthernetAssembler
from protocols.ethernet.base import ETHERNET_HEADER_LEN
from tests.unit.protocols__ethernet__ps import (
    ETHERNET__CARRIED_PACKET,
    ETHERNET__DST,
    ETHERNET__SRC,
    ETHERNET__TEST_FRAME,
)


class TestEthernetAssembler(TestCase):
    """
    Ethernet Assembler unit test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._ethernet__src = ETHERNET__SRC
        self._ethernet__dst = ETHERNET__DST
        self._ethernet__carried_packet = ETHERNET__CARRIED_PACKET
        self._ethernet__test_frame = ETHERNET__TEST_FRAME

        self._packet = EthernetAssembler(
            ethernet__src=self._ethernet__src,
            ethernet__dst=self._ethernet__dst,
            carried_packet=self._ethernet__carried_packet,
        )

    def test__ethernet_fpa____init__(self) -> None:
        """
        Validate that the class constructor creates packet matching
        provided arguments.
        """

        self.assertIs(self._packet._src, self._ethernet__src)
        self.assertIs(self._packet._dst, self._ethernet__dst)
        self.assertIs(
            self._packet._type, self._ethernet__carried_packet.ethernet_type
        )
        self.assertIs(
            self._packet._carried_packet, self._ethernet__carried_packet
        )

    def test__ethernet_fpa____len__(self) -> None:
        """
        Verify that the '__len__()' dunder provides valid packet length.
        """

        self.assertEqual(
            len(self._packet),
            ETHERNET_HEADER_LEN + len(self._ethernet__carried_packet),
        )

    def test__ethernet_fpa__getter__carried_packet(self) -> None:
        """
        Validate that the '_carried_packet' attribute getter provides correct value.
        """

        self.assertIs(
            self._packet.carried_packet, self._ethernet__carried_packet
        )

    def test__ethernet_fpa__assemble(self) -> None:
        """
        Validate that the 'assemble()' method correctly writes data into frame.
        """

        frame = memoryview(bytearray(len(self._packet)))
        self._packet.assemble(frame)

        self.assertEqual(bytes(frame), self._ethernet__test_frame)
