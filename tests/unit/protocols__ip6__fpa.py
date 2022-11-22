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
# tests/ip6_fpa.py -  tests specific for IPv6 fpa module
#
# ver 2.7
#

from testslide import StrictMock, TestCase

from pytcp.config import IP6_DEFAULT_HOP
from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.tracker import Tracker
from pytcp.protocols.ether.ps import ETHER_TYPE_IP6
from pytcp.protocols.icmp6.fpa import Icmp6Assembler
from pytcp.protocols.ip6.fpa import Ip6Assembler
from pytcp.protocols.ip6.ps import IP6_HEADER_LEN, IP6_NEXT_RAW
from pytcp.protocols.raw.fpa import RawAssembler
from pytcp.protocols.tcp.fpa import TcpAssembler
from pytcp.protocols.udp.fpa import UdpAssembler


class TestIp6Assembler(TestCase):
    """
    IPv6 packet assembler unit test class.
    """

    def test_ip6_fpa__ethertype(self) -> None:
        """
        Make sure the 'Ip6Assembler' class has the proper
        'ethertype' value assigned.
        """
        self.assertEqual(Ip6Assembler.ether_type, ETHER_TYPE_IP6)

    def test_ip6_fpa____init__(self) -> None:
        """
        Test the packet constructor.
        """
        packet = Ip6Assembler(
            src=Ip6Address("0:1:2:3:4:5:6:7"),
            dst=Ip6Address("8:9:A:B:C:D:E:F"),
            hop=32,
            dscp=10,
            ecn=2,
            flow=12345678,
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )
        self.assertEqual(
            packet._carried_packet, RawAssembler(data=b"0123456789ABCDEF")
        )
        self.assertEqual(packet._tracker, packet._carried_packet._tracker)
        self.assertEqual(packet._ver, 6)
        self.assertEqual(packet._dscp, 10)
        self.assertEqual(packet._ecn, 2)
        self.assertEqual(packet._flow, 12345678)
        self.assertEqual(packet._hop, 32)
        self.assertEqual(packet._src, Ip6Address("0:1:2:3:4:5:6:7"))
        self.assertEqual(packet._dst, Ip6Address("8:9:A:B:C:D:E:F"))
        self.assertEqual(packet._next, IP6_NEXT_RAW)
        self.assertEqual(packet._dlen, 16)

    def test_ip6_fpa____init____defaults(self) -> None:
        """
        Test the packet constructor with default arguments.
        """
        packet = Ip6Assembler()
        self.assertEqual(packet._carried_packet, RawAssembler(data=b""))
        self.assertEqual(packet._tracker, packet._carried_packet._tracker)
        self.assertEqual(packet._ver, 6)
        self.assertEqual(packet._dscp, 0)
        self.assertEqual(packet._ecn, 0)
        self.assertEqual(packet._flow, 0)
        self.assertEqual(packet._hop, IP6_DEFAULT_HOP)
        self.assertEqual(packet._src, Ip6Address(0))
        self.assertEqual(packet._dst, Ip6Address(0))
        self.assertEqual(packet._next, IP6_NEXT_RAW)
        self.assertEqual(packet._dlen, 0)

    def test_ip6_fpa____init____assert_hop__under(self) -> None:
        """
        Test assertion for the the 'hop' argument.
        """
        with self.assertRaises(AssertionError):
            Ip6Assembler(hop=-1)

    def test_ip6_fpa____init____assert_hop__over(self) -> None:
        """
        Test assertion for the 'hop' argument.
        """
        with self.assertRaises(AssertionError):
            Ip6Assembler(hop=0x100)

    def test_ip6_fpa____init____assert_dscp__under(self) -> None:
        """
        Test assertion for the 'dscp' argument.
        """
        with self.assertRaises(AssertionError):
            Ip6Assembler(dscp=-1)

    def test_ip6_fpa____init____assert_dscp__over(self) -> None:
        """
        Test assertion for the 'dscp' argument.
        """
        with self.assertRaises(AssertionError):
            Ip6Assembler(dscp=0x40)

    def test_ip6_fpa____init____assert_ecn__under(self) -> None:
        """
        Test assertion for the 'ecn' argument.
        """
        with self.assertRaises(AssertionError):
            Ip6Assembler(ecn=-1)

    def test_ip6_fpa____init____assert_ecn__over(self) -> None:
        """
        Test assertion for the 'ecn' argument.
        """
        with self.assertRaises(AssertionError):
            Ip6Assembler(ecn=4)

    def test_ip6_fpa____init____assert_flow__under(self) -> None:
        """
        Test assertion for the 'flow' argument.
        """
        with self.assertRaises(AssertionError):
            Ip6Assembler(flow=-1)

    def test_ip6_fpa____init____assert_flow__over(self) -> None:
        """
        Test assertion for the 'flow' argument.
        """
        with self.assertRaises(AssertionError):
            Ip6Assembler(flow=0x1000000)

    def test_ip6_fpa____init____assert_next_header_udp(self) -> None:
        """
        Test assertion for carried packet 'ip6_next_header' attribute.
        """
        Ip6Assembler(carried_packet=UdpAssembler())

    def test_ip6_fpa____init____assert_next_header_tcp(self) -> None:
        """
        Test assertion for carried packet 'ip6_next_header' attribute.
        """
        Ip6Assembler(carried_packet=TcpAssembler())

    def test_ip6_fpa____init____assert_next_header_icmp6(self) -> None:
        """
        Test assertion for carried packet 'ip6_next_header' attribute.
        """
        Ip6Assembler(carried_packet=Icmp6Assembler())

    def test_ip6_fpa____init____assert_next_header_raw(self) -> None:
        """
        Test assertion for carried packet 'ip6_next_header' attribute.
        """
        Ip6Assembler(carried_packet=RawAssembler())

    def test_ip6_fpa____init____assert_next_header_unknown(self) -> None:
        """
        Test assertion for carried packet 'ip6_next_header' attribute.
        """
        with self.assertRaises(AssertionError):
            carried_packet_mock = StrictMock()
            carried_packet_mock.ip6_next = -1
            carried_packet_mock.tracker = StrictMock(Tracker)
            Ip6Assembler(carried_packet=carried_packet_mock)

    def test_ip6_fpa____len__(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = Ip6Assembler()

        self.assertEqual(len(packet), IP6_HEADER_LEN)

    def test_ip6_fpa____len____data(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = Ip6Assembler(
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )
        self.assertEqual(len(packet), IP6_HEADER_LEN + 16)

    def test_ip6_fpa____str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        packet = Ip6Assembler(
            src=Ip6Address("0:1:2:3:4:5:6:7"),
            dst=Ip6Address("8:9:A:B:C:D:E:F"),
            hop=32,
            dscp=10,
            ecn=2,
            flow=12345678,
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )
        self.assertEqual(
            str(packet),
            "IPv6 0:1:2:3:4:5:6:7 > 8:9:a:b:c:d:e:f, next 255 (raw_data), flow 12345678, dlen 16, hop 32",
        )

    def test_ip6_fpa__tracker_getter(self) -> None:
        """
        Test the '_tracker' attribute getter.
        """
        packet = Ip6Assembler()
        self.assertTrue(
            repr(packet.tracker).startswith("Tracker(serial='<lr>TX")
        )

    def test_ip6_fpa__dst_getter(self) -> None:
        """
        Test the '_dst' attribute getter.
        """
        packet = Ip6Assembler(
            dst=Ip6Address("8:9:A:B:C:D:E:F"),
        )
        self.assertEqual(packet.dst, Ip6Address("8:9:A:B:C:D:E:F"))

    def test_ip6_fpa__src_getter(self) -> None:
        """
        Test the '_src' attribute getter.
        """
        packet = Ip6Assembler(
            src=Ip6Address("0:1:2:3:4:5:6:7"),
        )
        self.assertEqual(packet.src, Ip6Address("0:1:2:3:4:5:6:7"))

    def test_ip6_fpa__dlen_getter(self) -> None:
        """
        Test the 'dlen' property.
        """
        packet = Ip6Assembler(
            carried_packet=RawAssembler(data=b"0123456789ABCDEF")
        )
        self.assertEqual(packet._dlen, 16)

    def test_ip6_fpa__next_getter(self) -> None:
        """
        Test the 'next' property getter.
        """
        packet = Ip6Assembler()
        self.assertEqual(packet.next, IP6_NEXT_RAW)

    def test_ip6_fpa__pshdr_sum(self) -> None:
        """
        Test the 'pshdr_sum' property getter.
        """
        packet = Ip6Assembler(
            src=Ip6Address("0:1:2:3:4:5:6:7"),
            dst=Ip6Address("8:9:A:B:C:D:E:F"),
            carried_packet=RawAssembler(data="0123456789ABCDEF"),
        )
        self.assertEqual(packet.pshdr_sum, 6755588421714211)

    def test_ip6_fpa__assemble(self) -> None:
        """
        Test the 'assemble() method.
        """
        packet = Ip6Assembler(
            src=Ip6Address("0:1:2:3:4:5:6:7"),
            dst=Ip6Address("8:9:A:B:C:D:E:F"),
            hop=32,
            dscp=10,
            ecn=2,
            flow=12345678,
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )
        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame)
        self.assertEqual(
            bytes(frame),
            b"`,aN\x00\x10\xff \x00\x00\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00"
            b"\x07\x00\x08\x00\t\x00\n\x00\x0b\x00\x0c\x00\r\x00\x0e\x00\x0f0123456789ABCDEF",
        )
