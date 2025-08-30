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
# tests/unit/ethernet_fpp.py -  Tests specific for Ethernet FPP module.
#
# ver 3.0.2
#

from tests.unit.protocols__ethernet__ps import (
    ETHERNET__CARRIED_PACKET,
    ETHERNET__DST,
    ETHERNET__SRC,
    ETHERNET__TEST_FRAME,
)
from testslide import TestCase

from net_addr import MacAddress
from protocols.ethernet.base import ETHERNET_HEADER_LEN, EtherType
from pytcp.protocols.packet_rx import PacketRx
from pytcp.protocols.ethernet.fpp import EthernetIntegrityError, EthernetParser


class TestEthernetParser(TestCase):
    """
    Ethernet Parser unit test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._ethernet__src = ETHERNET__SRC
        self._ethernet__dst = ETHERNET__DST
        self._ethernet__carried_packet = ETHERNET__CARRIED_PACKET

        self._ethernet__test_frame = bytearray(ETHERNET__TEST_FRAME)

    def test__ethernet_fpp____init____success(self) -> None:
        """
        Validate that the class constructor creates packet
        correctly reflecting the provided frame.
        """

        packet_rx = PacketRx(self._ethernet__test_frame)
        self.assertEqual(
            packet_rx.frame, memoryview(self._ethernet__test_frame)
        )

        packet = EthernetParser(packet_rx)
        self.assertEqual(packet.frame, memoryview(self._ethernet__test_frame))

        self.assertEqual(packet.src, self._ethernet__src)
        self.assertEqual(packet.dst, self._ethernet__dst)
        self.assertIs(packet.type, self._ethernet__carried_packet.ethernet_type)

    def test__ethernet_fpp____len__(self) -> None:
        """
        Verify that the '__len__()' dunder provides valid packet length.
        """

        packet_rx = PacketRx(self._ethernet__test_frame)
        packet = EthernetParser(packet_rx)

        self.assertEqual(len(packet), len(self._ethernet__test_frame))

    def test__ethernet_fpp__parse(self) -> None:
        """
        Validate the parsing of Ethernet packet.
        """

        packet_rx = PacketRx(self._ethernet__test_frame)
        packet = EthernetParser(packet_rx)

        self.assertEqual(
            packet.dst, MacAddress(self._ethernet__test_frame[0:6])
        )
        self.assertEqual(
            packet.src, MacAddress(self._ethernet__test_frame[6:12])
        )
        self.assertEqual(
            packet.type, EtherType.from_frame(self._ethernet__test_frame)
        )

    def test__ethernet_fpp__integrity_error(self) -> None:
        """
        Test for Ethernet packet integrity error.
        """

        short_frame = self._ethernet__test_frame[: ETHERNET_HEADER_LEN - 1]
        packet_rx = PacketRx(short_frame)

        with self.assertRaises(EthernetIntegrityError):
            EthernetParser(packet_rx)
