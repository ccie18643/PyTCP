#!/usr/bin/env python3


############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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
# tests/arp_fpa.py -  tests specific for ARP fpa module
#

from testslide import TestCase

from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.arp.fpa import ArpAssembler
from pytcp.protocols.arp.ps import ARP_HEADER_LEN, ARP_OP_REPLY, ARP_OP_REQUEST
from pytcp.protocols.ether.ps import ETHER_TYPE_ARP


class TestArpAssembler(TestCase):
    def test_arp_fpa__ethertype(self):
        """Test the ethertype of ArpAssembler class"""

        self.assertEqual(ArpAssembler.ether_type, ETHER_TYPE_ARP)

    def test_arp_fpa____init__(self):
        """Test class constructor"""

        packet = ArpAssembler(
            sha=MacAddress("00:11:22:33:44:55"),
            spa=Ip4Address("1.2.3.4"),
            tha=MacAddress("66:77:88:99:AA:BB"),
            tpa=Ip4Address("5.6.7.8"),
            oper=ARP_OP_REPLY,
        )

        self.assertEqual(packet._sha, MacAddress("00:11:22:33:44:55"))
        self.assertEqual(packet._spa, Ip4Address("1.2.3.4"))
        self.assertEqual(packet._tha, MacAddress("66:77:88:99:AA:BB"))
        self.assertEqual(packet._tpa, Ip4Address("5.6.7.8"))
        self.assertEqual(packet._oper, ARP_OP_REPLY)

    def test_arp_fpa____init____defaults(self):
        """Test class constructor"""

        packet = ArpAssembler()

        self.assertEqual(packet._sha, MacAddress("00:00:00:00:00:00"))
        self.assertEqual(packet._spa, Ip4Address("0.0.0.0"))
        self.assertEqual(packet._tha, MacAddress("00:00:00:00:00:00"))
        self.assertEqual(packet._tpa, Ip4Address("0.0.0.0"))
        self.assertEqual(packet._oper, ARP_OP_REQUEST)

    def test_arp_fpa____init____assert_oper_request(self):
        """Test assertion for the request operation"""

        ArpAssembler(oper=ARP_OP_REQUEST)

    def test_arp_fpa____init____assert_oper_reply(self):
        """Test assertion for the request operation"""

        ArpAssembler(oper=ARP_OP_REPLY)

    def test_arp_fpa____init____assert_oper_unknown(self):
        """Test assertion for the unknown operation"""

        with self.assertRaises(AssertionError):
            ArpAssembler(oper=-1)

    def test_arp_fpa____len__(self):
        """Test class __len__ operator"""

        packet = ArpAssembler()

        self.assertEqual(len(packet), ARP_HEADER_LEN)

    def test_arp_fpa____str____request(self):
        """Test class __str__ operator"""

        packet = ArpAssembler(
            sha=MacAddress("00:11:22:33:44:55"),
            spa=Ip4Address("1.2.3.4"),
            tha=MacAddress("66:77:88:99:AA:BB"),
            tpa=Ip4Address("5.6.7.8"),
            oper=ARP_OP_REQUEST,
        )

        self.assertEqual(str(packet), "ARP request 1.2.3.4 / 00:11:22:33:44:55 > 5.6.7.8 / 66:77:88:99:aa:bb")

    def test_arp_fpa____str____reply(self):
        """Test class __str__ operator"""

        packet = ArpAssembler(
            sha=MacAddress("00:11:22:33:44:55"),
            spa=Ip4Address("1.2.3.4"),
            tha=MacAddress("66:77:88:99:AA:BB"),
            tpa=Ip4Address("5.6.7.8"),
            oper=ARP_OP_REPLY,
        )

        self.assertEqual(str(packet), "ARP reply 1.2.3.4 / 00:11:22:33:44:55 > 5.6.7.8 / 66:77:88:99:aa:bb")

    def test_arp_fpa__tracker_getter(self):
        """Test tracker getter"""

        packet = ArpAssembler()
        self.assertTrue(repr(packet.tracker).startswith("Tracker(serial='<lr>TX"))

    def test_ether_fpa__assemble(self):
        """Test assemble method"""

        packet = ArpAssembler(
            sha=MacAddress("00:11:22:33:44:55"),
            spa=Ip4Address("1.2.3.4"),
            tha=MacAddress("66:77:88:99:AA:BB"),
            tpa=Ip4Address("5.6.7.8"),
            oper=ARP_OP_REPLY,
        )

        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame)

        self.assertEqual(frame, b'\x00\x01\x08\x00\x06\x04\x00\x02\x00\x11"3DU\x01\x02\x03\x04fw\x88\x99\xaa\xbb\x05\x06\x07\x08')
