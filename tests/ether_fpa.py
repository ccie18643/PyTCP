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
# tests/ether_fpa.py -  tests specific for Ethernet fpa module
#

from testslide import StrictMock, TestCase

from pytcp.lib.mac_address import MacAddress
from pytcp.lib.tracker import Tracker
from pytcp.protocols.arp.fpa import ArpAssembler
from pytcp.protocols.ether.fpa import EtherAssembler
from pytcp.protocols.ether.ps import ETHER_HEADER_LEN, ETHER_TYPE_RAW
from pytcp.protocols.ip4.fpa import Ip4Assembler
from pytcp.protocols.ip6.fpa import Ip6Assembler
from pytcp.protocols.raw.fpa import RawAssembler


class TestEtherAssembler(TestCase):
    def test_ether_fpa__assert_ethertype_arp(self):
        """Test assertion for carried packet ether_type attribute"""

        EtherAssembler(carried_packet=ArpAssembler())

    def test_ether_fpa__assert_ethertype_ip4(self):
        """Test assertion for carried packet ether_type attribute"""

        EtherAssembler(carried_packet=Ip4Assembler())

    def test_ether_fpa__assert_ethertype_ip6(self):
        """Test assertion for carried packet ether_type attribute"""

        EtherAssembler(carried_packet=Ip6Assembler())

    def test_ether_fpa__assert_ethertype_raw(self):
        """Test assertion for carried packet ether_type attribute"""

        EtherAssembler(carried_packet=RawAssembler())

    def test_ether_fpa__assert_ethertype_unknown(self):
        """Test assertion for carried packet ether_type attribute"""

        with self.assertRaises(AssertionError):
            carried_packet_mock = StrictMock()
            carried_packet_mock.ether_type = -1
            carried_packet_mock.tracker = StrictMock(Tracker)
            EtherAssembler(carried_packet=carried_packet_mock)

    def test_ether_fpa__constructor(self):
        """Test class constructor"""

        packet = EtherAssembler(
            src=MacAddress("00:11:22:33:44:55"),
            dst=MacAddress("66:77:88:99:AA:BB"),
            carried_packet=RawAssembler(),
        )

        self.assertEqual(packet._carried_packet, RawAssembler())
        self.assertEqual(packet._tracker, packet._carried_packet._tracker)
        self.assertEqual(packet._src, MacAddress("00:11:22:33:44:55"))
        self.assertEqual(packet._dst, MacAddress("66:77:88:99:AA:BB"))
        self.assertEqual(packet._type, ETHER_TYPE_RAW)

    def test_ether_fpa__constructor__defaults(self):
        """Test class constructor"""

        packet = EtherAssembler()

        self.assertEqual(packet._carried_packet, RawAssembler())
        self.assertEqual(packet._tracker, packet._carried_packet._tracker)
        self.assertEqual(packet._src, MacAddress("00:00:00:00:00:00"))
        self.assertEqual(packet._dst, MacAddress("00:00:00:00:00:00"))
        self.assertEqual(packet._type, ETHER_TYPE_RAW)

    def test_ether_fpa__len(self):
        """Test class __len__ operator"""

        packet = EtherAssembler(
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        self.assertEqual(len(packet), ETHER_HEADER_LEN + 16)

    def test_ether_fpa__str(self):
        """Test class __str__ operator"""

        packet = EtherAssembler(
            src=MacAddress("00:11:22:33:44:55"),
            dst=MacAddress("66:77:88:99:AA:BB"),
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        self.assertEqual(str(packet), "ETHER 00:11:22:33:44:55 > 66:77:88:99:aa:bb, 0xffff (raw_data), plen 30")

    def test_ether_fpa__tracker_getter(self):
        """Test tracker getter"""

        carried_packet_mock = StrictMock()
        carried_packet_mock.ether_type = ETHER_TYPE_RAW
        carried_packet_mock.tracker = StrictMock(Tracker)

        packet = EtherAssembler(carried_packet=carried_packet_mock)

        self.assertEqual(packet.tracker, carried_packet_mock.tracker)

    def test_ether_fpa__dst_getter(self):
        """Test dst getter"""

        packet = EtherAssembler(
            dst=MacAddress("66:77:88:99:AA:BB"),
        )

        self.assertEqual(packet.dst, MacAddress("66:77:88:99:AA:BB"))

    def test_ether_fpa__dst_setter(self):
        """Test dst setter"""

        packet = EtherAssembler(
            dst=MacAddress("66:77:88:99:AA:BB"),
        )

        self.assertEqual(packet.dst, MacAddress("66:77:88:99:AA:BB"))

    def test_ether_fpa__src_getter(self):
        """Test src getter"""

        packet = EtherAssembler(
            src=MacAddress("11:22:33:44:55:66"),
        )

        self.assertEqual(packet.src, MacAddress("11:22:33:44:55:66"))

    def test_ether_fpa__src_setter(self):
        """Test src setter"""

        packet = EtherAssembler(
            src=MacAddress("11:22:33:44:55:66"),
        )

        self.assertEqual(packet.src, MacAddress("11:22:33:44:55:66"))

    def test_ether_fpa__assemble(self):
        """Test assemble method"""

        packet = EtherAssembler(
            src=MacAddress("11:22:33:44:55:66"),
            dst=MacAddress("66:77:88:99:AA:BB"),
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        frame = memoryview(bytearray(ETHER_HEADER_LEN + 16))
        packet.assemble(frame)
        self.assertEqual(bytes(frame), b'fw\x88\x99\xaa\xbb\x11"3DUf\xff\xff0123456789ABCDEF')
