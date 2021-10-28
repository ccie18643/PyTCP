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
# tests/ip4_fpa.py -  tests specific for IPv4 fpa module
#

from testslide import StrictMock, TestCase

from pytcp.config import IP4_DEFAULT_TTL
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.tracker import Tracker
from pytcp.protocols.ether.ps import ETHER_TYPE_IP4
from pytcp.protocols.icmp4.fpa import Icmp4Assembler
from pytcp.protocols.ip4.fpa import Ip4Assembler, Ip4FragAssembler, Ip4OptEol, Ip4OptNop
from pytcp.protocols.ip4.ps import (
    IP4_HEADER_LEN,
    IP4_OPT_EOL_LEN,
    IP4_OPT_NOP_LEN,
    IP4_PROTO_ICMP4,
    IP4_PROTO_RAW,
    IP4_PROTO_TCP,
    IP4_PROTO_UDP,
)
from pytcp.protocols.raw.fpa import RawAssembler
from pytcp.protocols.tcp.fpa import TcpAssembler
from pytcp.protocols.udp.fpa import UdpAssembler


class TestIp4Assembler(TestCase):
    def test_ip4_fpa__ethertype(self):
        """Test the ethertype of Ip4Assembler class"""

        self.assertEqual(Ip4Assembler.ether_type, ETHER_TYPE_IP4)

    def test_ip4_fpa__assert_ttl(self):
        """Test assertion for the ttl"""

        Ip4Assembler(ttl=0x20)

    def test_ip4_fpa__assert_ttl__default(self):
        """Test assertion for the ttl"""

        Ip4Assembler()

    def test_ip4_fpa__assert_ttl__bellow(self):
        """Test assertion for the ttl"""

        with self.assertRaises(AssertionError):
            Ip4Assembler(ttl=-1)

    def test_ip4_fpa__assert_ttl__above(self):
        """Test assertion for the ttl"""

        with self.assertRaises(AssertionError):
            Ip4Assembler(ttl=0x100)

    def test_ip4_fpa__assert_dscp(self):
        """Test assertion for the dscp"""

        Ip4Assembler(dscp=0x10)

    def test_ip4_fpa__assert_dscp__default(self):
        """Test assertion for the dscp"""

        Ip4Assembler()

    def test_ip4_fpa__assert_dscp__bellow(self):
        """Test assertion for the dscp"""

        with self.assertRaises(AssertionError):
            Ip4Assembler(dscp=-1)

    def test_ip4_fpa__assert_dscp__above(self):
        """Test assertion for the dscp"""

        with self.assertRaises(AssertionError):
            Ip4Assembler(dscp=0x40)

    def test_ip4_fpa__assert_ecn(self):
        """Test assertion for the ecn"""

        Ip4Assembler(ecn=2)

    def test_ip4_fpa__assert_ecn__default(self):
        """Test assertion for the ecn"""

        Ip4Assembler()

    def test_ip4_fpa__assert_ecn__bellow(self):
        """Test assertion for the ecn"""

        with self.assertRaises(AssertionError):
            Ip4Assembler(ecn=-1)

    def test_ip4_fpa__assert_ecn__above(self):
        """Test assertion for the ecn"""

        with self.assertRaises(AssertionError):
            Ip4Assembler(ecn=4)

    def test_ip4_fpa__assert_id(self):
        """Test assertion for the id"""

        Ip4Assembler(id=12345)

    def test_ip4_fpa__assert_id__default(self):
        """Test assertion for the id"""

        Ip4Assembler()

    def test_ip4_fpa__assert_id__bellow(self):
        """Test assertion for the id"""

        with self.assertRaises(AssertionError):
            Ip4Assembler(id=-1)

    def test_ip4_fpa__assert_id__above(self):
        """Test assertion for the id"""

        with self.assertRaises(AssertionError):
            Ip4Assembler(id=0x10000)

    def test_ip4_fpa__assert_proto_udp(self):
        """Test assertion for carried packet ip4_proto attribute"""

        Ip4Assembler(carried_packet=UdpAssembler())

    def test_ip4_fpa__assert_proto_tcp(self):
        """Test assertion for carried packet ip4_proto attribute"""

        Ip4Assembler(carried_packet=TcpAssembler())

    def test_ip4_fpa__assert_proto_icmp4(self):
        """Test assertion for carried packet ip4_proto attribute"""

        Ip4Assembler(carried_packet=Icmp4Assembler())

    def test_ip4_fpa__assert_proto_raw(self):
        """Test assertion for carried packet ip4_proto attribute"""

        Ip4Assembler(carried_packet=RawAssembler())

    def test_ip4_fpa__assert_proto_unknown(self):
        """Test assertion for carried packet p4_proto attribute"""

        with self.assertRaises(AssertionError):
            carried_packet_mock = StrictMock()
            carried_packet_mock.ip4_proto = -1
            carried_packet_mock.tracker = StrictMock(Tracker)
            Ip4Assembler(carried_packet=carried_packet_mock)

    def test_ip4_fpa__constructor(self):
        """Test class constructor"""

        packet = Ip4Assembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            ttl=32,
            dscp=10,
            ecn=2,
            id=12345,
            flag_df=True,
            options=[Ip4OptNop(), Ip4OptEol()],
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        self.assertEqual(packet._carried_packet, RawAssembler(data=b"0123456789ABCDEF"))
        self.assertEqual(packet._tracker, packet._carried_packet._tracker)
        self.assertEqual(packet._ver, 4)
        self.assertEqual(packet._dscp, 10)
        self.assertEqual(packet._ecn, 2)
        self.assertEqual(packet._id, 12345)
        self.assertEqual(packet._flag_df, True)
        self.assertEqual(packet._flag_mf, False)
        self.assertEqual(packet._offset, 0)
        self.assertEqual(packet._ttl, 32)
        self.assertEqual(packet._src, Ip4Address("1.2.3.4"))
        self.assertEqual(packet._dst, Ip4Address("5.6.7.8"))
        self.assertEqual(packet._options, [Ip4OptNop(), Ip4OptEol()])
        self.assertEqual(packet._proto, IP4_PROTO_RAW)
        self.assertEqual(packet._hlen, IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN)
        self.assertEqual(packet._plen, IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16)

    def test_ip4_fpa__constructor__defaults(self):
        """Test class constructor"""

        packet = Ip4Assembler()

        self.assertEqual(packet._carried_packet, RawAssembler())
        self.assertEqual(packet._tracker, packet._carried_packet._tracker)
        self.assertEqual(packet._ver, 4)
        self.assertEqual(packet._dscp, 0)
        self.assertEqual(packet._ecn, 0)
        self.assertEqual(packet._id, 0)
        self.assertEqual(packet._flag_df, False)
        self.assertEqual(packet._flag_mf, False)
        self.assertEqual(packet._offset, 0)
        self.assertEqual(packet._ttl, IP4_DEFAULT_TTL)
        self.assertEqual(packet._src, Ip4Address(0))
        self.assertEqual(packet._dst, Ip4Address(0))
        self.assertEqual(packet._options, [])
        self.assertEqual(packet._proto, IP4_PROTO_RAW)
        self.assertEqual(packet._hlen, IP4_HEADER_LEN)
        self.assertEqual(packet._plen, IP4_HEADER_LEN)

    def test_ip4_fpa____len__(self):
        """Test class __len__ operator"""

        packet = Ip4Assembler()

        self.assertEqual(len(packet), IP4_HEADER_LEN)

    def test_ip4_fpa____len____options(self):
        """Test class __len__ operator"""

        packet = Ip4Assembler(
            options=[Ip4OptNop(), Ip4OptEol()],
        )

        self.assertEqual(len(packet), IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN)

    def test_ip4_fpa____len____data(self):
        """Test class __len__ operator"""

        packet = Ip4Assembler(
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        self.assertEqual(len(packet), IP4_HEADER_LEN + 16)

    def test_ip4_fpa____len____options_data(self):

        """Test class __len__ operator"""

        packet = Ip4Assembler(
            options=[Ip4OptNop(), Ip4OptEol()],
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        self.assertEqual(len(packet), IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16)

    def test_ip4_fpa____str__(self):
        """Test class __str__ operator"""

        packet = Ip4Assembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            ttl=32,
            dscp=10,
            ecn=2,
            id=12345,
            flag_df=True,
            options=[],
            carried_packet=RawAssembler(),
        )

        self.assertEqual(str(packet), "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (raw_data), id 12345, DF, offset 0, plen 20, ttl 32")

    def test_ip4_fpa____str____options(self):
        """Test class __str__ operator"""

        packet = Ip4Assembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            ttl=32,
            dscp=10,
            ecn=2,
            id=12345,
            flag_df=True,
            options=[Ip4OptNop(), Ip4OptEol()],
            carried_packet=RawAssembler(),
        )

        self.assertEqual(str(packet), "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (raw_data), id 12345, DF, offset 0, plen 22, ttl 32, nop, eol")

    def test_ip4_fpa__tracker_getter(self):
        """Test tracker getter"""

        packet = Ip4Assembler()
        self.assertTrue(repr(packet.tracker).startswith("Tracker(serial='<lr>TX"))

    def test_ip4_fpa__dst_getter(self):
        """Test dst getter"""

        packet = Ip4Assembler(
            dst=Ip4Address("5.6.7.8"),
        )

        self.assertEqual(packet.dst, Ip4Address("5.6.7.8"))

    def test_ip4_fpa__src_getter(self):
        """Test src getter"""

        packet = Ip4Assembler(
            src=Ip4Address("1.2.3.4"),
        )

        self.assertEqual(packet.src, Ip4Address("1.2.3.4"))

    def test_ip4_fpa__hlen_getter(self):
        """Test hlen getter"""

        packet = Ip4Assembler()

        self.assertEqual(packet._hlen, IP4_HEADER_LEN)

    def test_ip4_fpa__hlen_getter__options(self):
        """Test hlen getter"""

        packet = Ip4Assembler(options=[Ip4OptNop(), Ip4OptEol()])

        self.assertEqual(packet.hlen, IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN)

    def test_ip4_fpa__proto_getter(self):
        """Test proto getter"""

        packet = Ip4Assembler()

        self.assertEqual(packet.proto, IP4_PROTO_RAW)

    def test_ip4_fpa__dlen_getter(self):
        """Test dlen getter"""

        packet = Ip4Assembler(
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        self.assertEqual(packet.dlen, 16)

    def test_ip4_fpa__pshdr_sum(self):
        """Test pshdr_sum getter"""

        packet = Ip4Assembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        self.assertEqual(packet.pshdr_sum, 117901852)

    def test_ip4_fpa___raw_options(self):
        """Test _raw_options getter"""

        packet = Ip4Assembler(
            options=[Ip4OptNop(), Ip4OptEol()],
        )

        self.assertEqual(packet._raw_options, b"\x01\x00")

    def test_ip4_fpa__assemble(self):
        """Test assemble method"""

        packet = Ip4Assembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            ttl=32,
            dscp=10,
            ecn=2,
            id=12345,
            flag_df=True,
            options=[Ip4OptNop(), Ip4OptEol()],
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        frame = memoryview(bytearray(IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16))
        packet.assemble(frame)
        self.assertEqual(bytes(frame), b"E*\x00&09@\x00 \xff\x18c\x01\x02\x03\x04\x05\x06\x07\x08\x01\x000123456789ABCDEF")


class TestIp4FragAssembler(TestCase):
    def test_ip4_frag_fpa__ethertype(self):
        """Test the ethertype of Ip4Assembler class"""

    def test_ip4_frag_fpa__assert_ttl(self):
        """Test assertion for the ttl"""

        Ip4FragAssembler(ttl=0x20)

    def test_ip4_frag_fpa__assert_ttl__default(self):
        """Test assertion for the ttl"""

        Ip4FragAssembler()

    def test_ip4_frag_fpa__assert_ttl__bellow(self):
        """Test assertion for the ttl"""

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(ttl=-1)

    def test_ip4_frag_fpa__assert_ttl__above(self):
        """Test assertion for the ttl"""

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(ttl=0x100)

    def test_ip4_frag_fpa__assert_dscp(self):
        """Test assertion for the dscp"""

        Ip4FragAssembler(dscp=0x10)

    def test_ip4_frag_fpa__assert_dscp__default(self):
        """Test assertion for the dscp"""

        Ip4FragAssembler()

    def test_ip4_frag_fpa__assert_dscp__bellow(self):
        """Test assertion for the dscp"""

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(dscp=-1)

    def test_ip4_frag_fpa__assert_dscp__above(self):
        """Test assertion for the dscp"""

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(dscp=0x40)

    def test_ip4_frag_fpa__assert_ecn(self):
        """Test assertion for the ecn"""

        Ip4FragAssembler(ecn=2)

    def test_ip4_frag_fpa__assert_ecn__default(self):
        """Test assertion for the ecn"""

        Ip4FragAssembler()

    def test_ip4_frag_fpa__assert_ecn__bellow(self):
        """Test assertion for the ecn"""

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(ecn=-1)

    def test_ip4_frag_fpa__assert_ecn__above(self):
        """Test assertion for the ecn"""

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(ecn=4)

    def test_ip4_frag_fpa__assert_id(self):
        """Test assertion for the id"""

        Ip4FragAssembler(id=12345)

    def test_ip4_frag_fpa__assert_id__default(self):
        """Test assertion for the id"""

        Ip4FragAssembler()

    def test_ip4_frag_fpa__assert_id__bellow(self):
        """Test assertion for the id"""

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(id=-1)

    def test_ip4_frag_fpa__assert_id__above(self):
        """Test assertion for the id"""

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(id=0x10000)

    def test_ip4_frag_fpa__assert_proto_udp(self):
        """Test assertion for carried packet ip4_proto attribute"""

        Ip4FragAssembler(proto=IP4_PROTO_UDP)

    def test_ip4_frag_fpa__assert_proto_tcp(self):
        """Test assertion for carried packet ip4_proto attribute"""

        Ip4FragAssembler(proto=IP4_PROTO_TCP)

    def test_ip4_frag_fpa__assert_proto_icmp4(self):
        """Test assertion for carried packet ip4_proto attribute"""

        Ip4FragAssembler(proto=IP4_PROTO_ICMP4)

    def test_ip4_frag_fpa__assert_proto_raw(self):
        """Test assertion for carried packet ip4_proto attribute"""

        Ip4FragAssembler(proto=IP4_PROTO_RAW)

    def test_ip4_frag_fpa__assert_proto_unknown(self):
        """Test assertion for carried packet p4_proto attribute"""

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(proto=-1)

    def test_ip4_frag_fpa__constructor(self):
        """Test class constructor"""

        packet = Ip4FragAssembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            ttl=32,
            dscp=10,
            ecn=2,
            id=12345,
            flag_mf=True,
            options=[Ip4OptNop(), Ip4OptEol()],
            data=b"0123456789ABCDEF",
            proto=IP4_PROTO_RAW,
        )

        self.assertEqual(packet._ver, 4)
        self.assertEqual(packet._dscp, 10)
        self.assertEqual(packet._ecn, 2)
        self.assertEqual(packet._id, 12345)
        self.assertEqual(packet._flag_df, False)
        self.assertEqual(packet._flag_mf, True)
        self.assertEqual(packet._offset, 0)
        self.assertEqual(packet._ttl, 32)
        self.assertEqual(packet._src, Ip4Address("1.2.3.4"))
        self.assertEqual(packet._dst, Ip4Address("5.6.7.8"))
        self.assertEqual(packet._options, [Ip4OptNop(), Ip4OptEol()])
        self.assertEqual(packet._data, b"0123456789ABCDEF")
        self.assertEqual(packet._proto, IP4_PROTO_RAW)
        self.assertEqual(packet._hlen, IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN)
        self.assertEqual(packet._plen, IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16)

    def test_ip4_frag_fpa__constructor__defaults(self):
        """Test class constructor"""

        packet = Ip4FragAssembler()

        self.assertEqual(packet._ver, 4)
        self.assertEqual(packet._dscp, 0)
        self.assertEqual(packet._ecn, 0)
        self.assertEqual(packet._id, 0)
        self.assertEqual(packet._flag_df, False)
        self.assertEqual(packet._flag_mf, False)
        self.assertEqual(packet._offset, 0)
        self.assertEqual(packet._ttl, IP4_DEFAULT_TTL)
        self.assertEqual(packet._src, Ip4Address(0))
        self.assertEqual(packet._dst, Ip4Address(0))
        self.assertEqual(packet._options, [])
        self.assertEqual(packet._data, b"")
        self.assertEqual(packet._proto, IP4_PROTO_RAW)
        self.assertEqual(packet._hlen, IP4_HEADER_LEN)
        self.assertEqual(packet._plen, IP4_HEADER_LEN)

    def test_ip4_frag_fpa____len__(self):
        """Test class __len__ operator"""

        packet = Ip4FragAssembler()

        self.assertEqual(len(packet), IP4_HEADER_LEN)

    def test_ip4_frag_fpa____len____options(self):
        """Test class __len__ operator"""

        packet = Ip4FragAssembler(
            options=[Ip4OptNop(), Ip4OptEol()],
        )

        self.assertEqual(len(packet), IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN)

    def test_ip4_frag_fpa____len____data(self):
        """Test class __len__ operator"""

        packet = Ip4FragAssembler(
            data=b"0123456789ABCDEF",
        )

        self.assertEqual(len(packet), IP4_HEADER_LEN + 16)

    def test_ip4_frag_fpa____len____options_data(self):

        """Test class __len__ operator"""

        packet = Ip4FragAssembler(
            options=[Ip4OptNop(), Ip4OptEol()],
            data=b"0123456789ABCDEF",
        )

        self.assertEqual(len(packet), IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16)

    def test_ip4_frag_fpa____str__(self):
        """Test class __str__ operator"""

        packet = Ip4FragAssembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            ttl=32,
            dscp=10,
            ecn=2,
            id=12345,
            flag_mf=True,
            offset=54321,
            options=[],
            proto=IP4_PROTO_RAW,
            data=b"",
        )

        self.assertEqual(str(packet), "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (raw_data), id 12345, MF, offset 54321, plen 20, ttl 32")

    def test_ip4_frag_fpa____str____options(self):
        """Test class __str__ operator"""

        packet = Ip4FragAssembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            ttl=32,
            dscp=10,
            ecn=2,
            id=12345,
            flag_mf=True,
            offset=54321,
            options=[Ip4OptNop(), Ip4OptEol()],
            proto=IP4_PROTO_RAW,
            data=b"",
        )

        self.assertEqual(str(packet), "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (raw_data), id 12345, MF, offset 54321, plen 22, ttl 32, nop, eol")

    def test_ip4_frag_fpa__tracker_getter(self):
        """Test tracker getter"""

        packet = Ip4FragAssembler()
        self.assertTrue(repr(packet.tracker).startswith("Tracker(serial='<lr>TX"))

    def test_ip4_frag_fpa__dst_getter(self):
        """Test dst getter"""

        packet = Ip4FragAssembler(
            dst=Ip4Address("5.6.7.8"),
        )

        self.assertEqual(packet.dst, Ip4Address("5.6.7.8"))

    def test_ip4_frag_fpa__src_getter(self):
        """Test src getter"""

        packet = Ip4FragAssembler(
            src=Ip4Address("1.2.3.4"),
        )

        self.assertEqual(packet.src, Ip4Address("1.2.3.4"))

    def test_ip4_frag_fpa___raw_options(self):
        """Test _raw_options getter"""

        packet = Ip4FragAssembler(
            options=[Ip4OptNop(), Ip4OptEol()],
        )

        self.assertEqual(packet._raw_options, b"\x01\x00")

    def test_ip4_frag_fpa__assemble(self):
        """Test assemble method"""

        packet = Ip4FragAssembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            ttl=32,
            dscp=10,
            ecn=2,
            id=12345,
            flag_mf=True,
            offset=54321,
            options=[Ip4OptNop(), Ip4OptEol()],
            proto=IP4_PROTO_RAW,
            data=b"0123456789ABCDEF",
        )

        frame = memoryview(bytearray(IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16))
        packet.assemble(frame)
        self.assertEqual(bytes(frame), b"E*\x00&09:\x86 \xff\x1d\xdd\x01\x02\x03\x04\x05\x06\x07\x08\x01\x000123456789ABCDEF")


class TestIp4OptEol(TestCase):
    def test_ip4_fpa_opt_eol____str__(self):
        """Test the __str__ dunder"""

        option = Ip4OptEol()

        self.assertEqual(str(option), "eol")

    def test_ip4_fpa_opt_eol____repr__(self):
        """Test the __repr__ dunder"""

        option = Ip4OptEol()

        self.assertEqual(repr(option), "Ip4OptEol()")

    def test_ip4_fpa_opt_eol____bytes__(self):
        """Test the __bytes__ dunder"""

        option = Ip4OptEol()

        self.assertEqual(bytes(option), b"\x00")

    def test_ip4_fpa_opt_eol____eq__(self):
        """Test the __eq__ dunder"""

        option = Ip4OptEol()

        self.assertEqual(option, option)


class TestIp4OptNop(TestCase):
    def test_ip4_fpa_opt_nop____str__(self):
        """Test the __str__ dunder"""

        option = Ip4OptNop()

        self.assertEqual(str(option), "nop")

    def test_ip4_fpa_opt_nop____repr__(self):
        """Test the __repr__ dunder"""

        option = Ip4OptNop()

        self.assertEqual(repr(option), "Ip4OptNop()")

    def test_ip4_fpa_opt_nop____bytes__(self):
        """Test the __bytes__ dunder"""

        option = Ip4OptNop()

        self.assertEqual(bytes(option), b"\x01")

    def test_ip4_fpa_opt_nop____eq__(self):
        """Test the __eq__ dunder"""

        option = Ip4OptNop()

        self.assertEqual(option, option)
