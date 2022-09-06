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
# tests/udp_fpa.py -  tests specific for UDP fpa module
#
# ver 2.7
#

from testslide import TestCase

from pytcp.lib.tracker import Tracker
from pytcp.protocols.ip4.ps import IP4_PROTO_UDP
from pytcp.protocols.ip6.ps import IP6_NEXT_UDP
from pytcp.protocols.udp.fpa import UdpAssembler
from pytcp.protocols.udp.ps import UDP_HEADER_LEN


class TestUdpAssembler(TestCase):
    """
    UDP packet assembler unit test class.
    """

    def test_udp_fpa__ip4_proto_udp(self):
        """
        Make sure the 'UdpAssembler' class has the proper
        'ip4_proto' value assigned.
        """
        self.assertEqual(UdpAssembler.ip4_proto, IP4_PROTO_UDP)

    def test_udp_fpa__ip6_next_udp(self):
        """
        Make sure the 'UdpAssembler' class has the proper
        'ip6_next' value assigned.
        """
        self.assertEqual(UdpAssembler.ip6_next, IP6_NEXT_UDP)

    def test_udp_fpa____init__(self):
        """
        Test class constructor.
        """
        packet = UdpAssembler(
            sport=12345,
            dport=54321,
            data=b"0123456789ABCDEF",
            echo_tracker=Tracker(prefix="TX"),
        )
        self.assertEqual(packet._sport, 12345)
        self.assertEqual(packet._dport, 54321)
        self.assertEqual(packet._data, b"0123456789ABCDEF")
        self.assertEqual(packet._plen, UDP_HEADER_LEN + 16)
        self.assertTrue(
            repr(packet.tracker._echo_tracker).startswith(
                "Tracker(serial='<lr>TX"
            )
        )

    def test_udp_fpa____init____defaults(self):
        """
        Test class constructor with default arguments.
        """
        packet = UdpAssembler()
        self.assertEqual(packet._sport, 0)
        self.assertEqual(packet._dport, 0)
        self.assertEqual(packet._data, b"")
        self.assertEqual(packet._plen, UDP_HEADER_LEN)

    def test_udp_fpa____init____assert_sport__under(self):
        """
        Test assertion for the 'sport' argument.
        """
        with self.assertRaises(AssertionError):
            UdpAssembler(sport=-1)

    def test_udp_fpa____init____assert_sport__over(self):
        """
        Test assertion for the 'sport'
        """
        with self.assertRaises(AssertionError):
            UdpAssembler(sport=0x10000)

    def test_udp_fpa____init____assert_dport__under(self):
        """
        Test assertion for the 'dport'.
        """
        with self.assertRaises(AssertionError):
            UdpAssembler(dport=-1)

    def test_udp_fpa____init____assert_dport__over(self):
        """
        Test assertion for the dport.
        """
        with self.assertRaises(AssertionError):
            UdpAssembler(dport=0x10000)

    def test_udp_fpa____len__(self):
        """
        Test the '__len__()' dunder.
        """
        packet = UdpAssembler()
        self.assertEqual(len(packet), UDP_HEADER_LEN)

    def test_udp_fpa____len____data(self):
        """
        Test the '__len__()' dunder.
        """
        packet = UdpAssembler(
            data=b"0123456789ABCDEF",
        )

        self.assertEqual(len(packet), UDP_HEADER_LEN + 16)

    def test_udp_fpa____str__(self):
        """
        Test the '__str__() dunder.
        """
        packet = UdpAssembler(
            sport=12345,
            dport=54321,
            data=b"0123456789ABCDEF",
        )
        self.assertEqual(str(packet), "UDP 12345 > 54321, len 24")

    def test_udp_fpa__tracker_getter(self):
        """
        Test the tracker property.
        """
        packet = UdpAssembler()
        self.assertTrue(
            repr(packet.tracker).startswith("Tracker(serial='<lr>TX")
        )

    def test_udp_fpa__assemble(self):
        """
        Test the 'assemble()' method.
        """
        packet = UdpAssembler(
            sport=12345,
            dport=54321,
            data=b"0123456789ABCDEF",
        )
        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame, 0x12345678)
        self.assertEqual(
            bytes(frame), b"09\xd41\x00\x18\xc3\xf90123456789ABCDEF"
        )
