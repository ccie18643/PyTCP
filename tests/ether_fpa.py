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
# tests/ether_fpa.py -  tests specific for Ethernet phtx module
#

from testslide import TestCase, StrictMock

from pytcp.protocols.ether.fpa import EtherAssembler
from pytcp.protocols.arp.fpa import ArpAssembler
from pytcp.protocols.ip4.fpa import Ip4Assembler
from pytcp.protocols.ip6.fpa import Ip6Assembler
from pytcp.protocols.raw.fpa import RawAssembler
from pytcp.protocols.ether.ps import ETHER_TYPE_ARP, ETHER_TYPE_IP4, ETHER_TYPE_IP6, ETHER_TYPE_RAW
from pytcp.lib.tracker import Tracker

class TestEtherAssembler(TestCase):
    def setUp(self):
        super().setUp()

    def test_ether_fpa__ethertype_arp(self):
        """Test assertion for carried packet Arp ether type"""

        carried_packet_mock = StrictMock(ArpAssembler)
        carried_packet_mock.ether_type = ETHER_TYPE_ARP
        carried_packet_mock.tracker = StrictMock(Tracker)
        EtherAssembler(carried_packet=carried_packet_mock)

    def test_ether_fpa__ethertype_ip4(self):
        """Test assertion for carried packet IPv4 ether type"""

        carried_packet_mock = StrictMock(Ip4Assembler)
        carried_packet_mock.ether_type = ETHER_TYPE_IP4
        carried_packet_mock.tracker = StrictMock(Tracker)
        EtherAssembler(carried_packet=carried_packet_mock)

    def test_ether_fpa__ethertype_ip6(self):
        """Test assertion for carried packet IPv6 ether type"""

        carried_packet_mock = StrictMock(Ip4Assembler)
        carried_packet_mock.ether_type = ETHER_TYPE_IP6
        carried_packet_mock.tracker = StrictMock(Tracker)
        EtherAssembler(carried_packet=carried_packet_mock)

    def test_ether_fpa__ethertype_raw(self):
        """Test assertion for carried packet IPv4 ether type"""

        carried_packet_mock = StrictMock(Ip4Assembler)
        carried_packet_mock.ether_type = ETHER_TYPE_RAW
        carried_packet_mock.tracker = StrictMock(Tracker)
        EtherAssembler(carried_packet=carried_packet_mock)

    def test_ether_fpa__ethertype_unknown(self):
        """Test assertion for carried packet unknown ether type"""

        with self.assertRaises(AssertionError):
            carried_packet_mock = StrictMock(Ip4Assembler)
            carried_packet_mock.ether_type = -1
            carried_packet_mock.tracker = StrictMock(Tracker)
            EtherAssembler(carried_packet=carried_packet_mock)

