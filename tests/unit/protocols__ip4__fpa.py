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
# tests/ip4_fpa.py -  tests specific for IPv4 fpa module
#
# ver 2.7
#

from testslide import StrictMock, TestCase

from pytcp.config import IP4_DEFAULT_TTL
from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.tracker import Tracker
from pytcp.protocols.ether.ps import ETHER_TYPE_IP4
from pytcp.protocols.icmp4.fpa import Icmp4Assembler
from pytcp.protocols.ip4.fpa import (
    Ip4Assembler,
    Ip4FragAssembler,
    Ip4OptEol,
    Ip4OptNop,
)
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
    """
    IPv4 packet assembler unit test class.
    """

    def test_ip4_fpa__ethertype(self) -> None:
        """
        Make sure the 'Ip4Assembler' class has the proper
        'ethertype' value assigned.
        """
        self.assertEqual(Ip4Assembler.ether_type, ETHER_TYPE_IP4)

    def test_ip4_fpa____init__(self) -> None:
        """
        Test the packet constructor.
        """
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
        self.assertEqual(
            packet._carried_packet, RawAssembler(data=b"0123456789ABCDEF")
        )
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
        self.assertEqual(
            packet._hlen, IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN
        )
        self.assertEqual(
            packet._plen,
            IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16,
        )

    def test_ip4_fpa____init____defaults(self) -> None:
        """
        Test the packet constructor with default arguments.
        """
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

    def test_ip4_fpa____init____assert_ttl__under(self) -> None:
        """
        Test assertion for the 'ttl' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4Assembler(ttl=-1)

    def test_ip4_fpa____init____assert_ttl__over(self) -> None:
        """
        Test assertion for the 'ttl' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4Assembler(ttl=0x100)

    def test_ip4_fpa____init____assert_dscp__under(self) -> None:
        """
        Test assertion for the 'dscp' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4Assembler(dscp=-1)

    def test_ip4_fpa____init____assert_dscp__over(self) -> None:
        """
        Test assertion for the 'dscp' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4Assembler(dscp=0x40)

    def test_ip4_fpa____init____assert_ecn__under(self) -> None:
        """
        Test assertion for the 'ecn' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4Assembler(ecn=-1)

    def test_ip4_fpa____init____assert_ecn__over(self) -> None:
        """
        Test assertion for the 'ecn' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4Assembler(ecn=4)

    def test_ip4_fpa____init____assert_id__under(self) -> None:
        """
        Test assertion for the 'id' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4Assembler(id=-1)

    def test_ip4_fpa____init____assert_id__over(self) -> None:
        """
        Test assertion for the 'id' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4Assembler(id=0x10000)

    def test_ip4_fpa____init____assert_proto_udp(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        Ip4Assembler(carried_packet=UdpAssembler())

    def test_ip4_fpa____init____assert_proto_tcp(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        Ip4Assembler(carried_packet=TcpAssembler())

    def test_ip4_fpa____init____assert_proto_icmp4(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        Ip4Assembler(carried_packet=Icmp4Assembler())

    def test_ip4_fpa____init____assert_proto_raw(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        Ip4Assembler(carried_packet=RawAssembler())

    def test_ip4_fpa____init____assert_proto_unknown(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        with self.assertRaises(AssertionError):
            carried_packet_mock = StrictMock()
            carried_packet_mock.ip4_proto = -1
            carried_packet_mock.tracker = StrictMock(Tracker)
            Ip4Assembler(carried_packet=carried_packet_mock)  # type: ignore[arg-type]

    def test_ip4_fpa____len__(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = Ip4Assembler()
        self.assertEqual(len(packet), IP4_HEADER_LEN)

    def test_ip4_fpa____len____options(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = Ip4Assembler(
            options=[Ip4OptNop(), Ip4OptEol()],
        )
        self.assertEqual(
            len(packet), IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN
        )

    def test_ip4_fpa____len____data(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = Ip4Assembler(
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )
        self.assertEqual(len(packet), IP4_HEADER_LEN + 16)

    def test_ip4_fpa____len____options_data(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = Ip4Assembler(
            options=[Ip4OptNop(), Ip4OptEol()],
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )
        self.assertEqual(
            len(packet), IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16
        )

    def test_ip4_fpa____str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
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
        self.assertEqual(
            str(packet),
            "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (raw_data), "
            "id 12345, DF, offset 0, plen 20, ttl 32",
        )

    def test_ip4_fpa____str____options(self) -> None:
        """
        Test the '__str__()' dunder.
        """
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
        self.assertEqual(
            str(packet),
            "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (raw_data), id 12345, "
            "DF, offset 0, plen 22, ttl 32, nop, eol",
        )

    def test_ip4_fpa__tracker_getter(self) -> None:
        """
        Test the '_tracker' attribute getter.
        """
        packet = Ip4Assembler()
        self.assertTrue(
            repr(packet.tracker).startswith("Tracker(serial='<lr>TX")
        )

    def test_ip4_fpa__dst_getter(self) -> None:
        """
        Test the '_dst' attributer getter.
        """

        packet = Ip4Assembler(
            dst=Ip4Address("5.6.7.8"),
        )

        self.assertEqual(packet.dst, Ip4Address("5.6.7.8"))

    def test_ip4_fpa__src_getter(self) -> None:
        """
        Test the '_src' attribute getter.
        """
        packet = Ip4Assembler(
            src=Ip4Address("1.2.3.4"),
        )
        self.assertEqual(packet.src, Ip4Address("1.2.3.4"))

    def test_ip4_fpa__hlen_getter(self) -> None:
        """
        Test the '_hlen' attribute getter.
        """
        packet = Ip4Assembler()
        self.assertEqual(packet._hlen, IP4_HEADER_LEN)

    def test_ip4_fpa__hlen_getter__options(self) -> None:
        """
        Test the '_hlen' attribute getter with options present.
        """
        packet = Ip4Assembler(options=[Ip4OptNop(), Ip4OptEol()])
        self.assertEqual(
            packet.hlen, IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN
        )

    def test_ip4_fpa__proto_getter(self) -> None:
        """
        Test the '_proto' attribute getter.
        """
        packet = Ip4Assembler()
        self.assertEqual(packet.proto, IP4_PROTO_RAW)

    def test_ip4_fpa__dlen_getter(self) -> None:
        """
        Test the '_dlen' attribute getter.
        """
        packet = Ip4Assembler(
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )
        self.assertEqual(packet.dlen, 16)

    def test_ip4_fpa__pshdr_sum(self) -> None:
        """
        Test the 'pshdr_sum' property.
        """
        packet = Ip4Assembler(
            src=Ip4Address("1.2.3.4"),
            dst=Ip4Address("5.6.7.8"),
            carried_packet=RawAssembler(data=b"0123456789ABCDEF"),
        )

        self.assertEqual(packet.pshdr_sum, 117901852)

    def test_ip4_fpa___raw_options(self) -> None:
        """
        Test the '_raw_options' attribute getter.
        """
        packet = Ip4Assembler(
            options=[Ip4OptNop(), Ip4OptEol()],
        )
        self.assertEqual(packet._raw_options, b"\x01\x00")

    def test_ip4_fpa__assemble(self) -> None:
        """
        Test the 'assemble()' method.
        """
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
        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame)
        self.assertEqual(
            bytes(frame),
            b"E*\x00&09@\x00 \xff\x18c\x01\x02\x03\x04\x05"
            b"\x06\x07\x08\x01\x000123456789ABCDEF",
        )


class TestIp4FragAssembler(TestCase):
    """
    IPv4 fragment packet assembler unit test class.
    """

    def test_ip4_frag_fpa__ethertype(self) -> None:
        """
        Test the 'ethertype' property of the 'Ip4FragAssembler' class.
        """
        self.assertEqual(Ip4Assembler.ether_type, ETHER_TYPE_IP4)

    def test_ip4_frag_fpa____init__(self) -> None:
        """
        Test the packet constructor.
        """
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
        self.assertEqual(
            packet._hlen, IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN
        )
        self.assertEqual(
            packet._plen,
            IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16,
        )

    def test_ip4_frag_fpa____init____defaults(self) -> None:
        """
        Test the packet constructor with default arguments.
        """
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

    def test_ip4_frag_fpa____init____assert_ttl__under(self) -> None:
        """
        Test assertion for the 'ttl' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4FragAssembler(ttl=-1)

    def test_ip4_frag_fpa____init____assert_ttl__over(self) -> None:
        """
        Test assertion for the 'ttl' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4FragAssembler(ttl=0x100)

    def test_ip4_frag_fpa____init____assert_dscp__under(self) -> None:
        """
        Test assertion for the 'dscp' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4FragAssembler(dscp=-1)

    def test_ip4_frag_fpa____init____assert_dscp__over(self) -> None:
        """
        Test assertion for the 'dscp' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4FragAssembler(dscp=0x40)

    def test_ip4_frag_fpa____init____assert_ecn__under(self) -> None:
        """
        Test assertion for the 'ecn' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4FragAssembler(ecn=-1)

    def test_ip4_frag_fpa____init____assert_ecn__over(self) -> None:
        """
        Test assertion for the 'ecn' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4FragAssembler(ecn=4)

    def test_ip4_frag_fpa____init____assert_id__under(self) -> None:
        """
        Test assertion for the 'id' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4FragAssembler(id=-1)

    def test_ip4_frag_fpa____init____assert_id__over(self) -> None:
        """
        Test assertion for the 'id' argument.
        """
        with self.assertRaises(AssertionError):
            Ip4FragAssembler(id=0x10000)

    def test_ip4_frag_fpa____init____assert_proto_udp(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        Ip4FragAssembler(proto=IP4_PROTO_UDP)

    def test_ip4_frag_fpa____init____assert_proto_tcp(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        Ip4FragAssembler(proto=IP4_PROTO_TCP)

    def test_ip4_frag_fpa____init____assert_proto_icmp4(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        Ip4FragAssembler(proto=IP4_PROTO_ICMP4)

    def test_ip4_frag_fpa____init____assert_proto_raw(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        Ip4FragAssembler(proto=IP4_PROTO_RAW)

    def test_ip4_frag_fpa____init____assert_proto_unknown(self) -> None:
        """
        Test assertion for the carried packet 'ip4_proto' attribute.
        """
        with self.assertRaises(AssertionError):
            Ip4FragAssembler(proto=-1)

    def test_ip4_frag_fpa____len__(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        packet = Ip4FragAssembler()
        self.assertEqual(len(packet), IP4_HEADER_LEN)

    def test_ip4_frag_fpa____len____options(self) -> None:
        """
        Test '__len__()' dunder with options present.
        """
        packet = Ip4FragAssembler(
            options=[Ip4OptNop(), Ip4OptEol()],
        )
        self.assertEqual(
            len(packet), IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN
        )

    def test_ip4_frag_fpa____len____data(self) -> None:
        """
        Test the '__len__()' dunder with data present.
        """
        packet = Ip4FragAssembler(
            data=b"0123456789ABCDEF",
        )
        self.assertEqual(len(packet), IP4_HEADER_LEN + 16)

    def test_ip4_frag_fpa____len____options_data(self) -> None:
        """
        Test the '__len__() dunder with options and data present.
        """
        packet = Ip4FragAssembler(
            options=[Ip4OptNop(), Ip4OptEol()],
            data=b"0123456789ABCDEF",
        )
        self.assertEqual(
            len(packet), IP4_HEADER_LEN + IP4_OPT_NOP_LEN + IP4_OPT_EOL_LEN + 16
        )

    def test_ip4_frag_fpa____str__(self) -> None:
        """
        Test the '__str__() dunder.
        """
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
        self.assertEqual(
            str(packet),
            "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (raw_data), id 12345, "
            "MF, offset 54321, plen 20, ttl 32",
        )

    def test_ip4_frag_fpa____str____options(self) -> None:
        """
        Test the '__str__()' dunder with options present.
        """
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
        self.assertEqual(
            str(packet),
            "IPv4 1.2.3.4 > 5.6.7.8, proto 255 (raw_data), id 12345, "
            "MF, offset 54321, plen 22, ttl 32, nop, eol",
        )

    def test_ip4_frag_fpa__tracker_getter(self) -> None:
        """
        Test the '_tracker' attribute getter.
        """
        packet = Ip4FragAssembler()
        self.assertTrue(
            repr(packet.tracker).startswith("Tracker(serial='<lr>TX")
        )

    def test_ip4_frag_fpa__dst_getter(self) -> None:
        """
        Test the '_dst attribute' getter.
        """
        packet = Ip4FragAssembler(
            dst=Ip4Address("5.6.7.8"),
        )
        self.assertEqual(packet.dst, Ip4Address("5.6.7.8"))

    def test_ip4_frag_fpa__src_getter(self) -> None:
        """
        Test the '_src' attribute getter.
        """
        packet = Ip4FragAssembler(
            src=Ip4Address("1.2.3.4"),
        )
        self.assertEqual(packet.src, Ip4Address("1.2.3.4"))

    def test_ip4_frag_fpa___raw_options(self) -> None:
        """
        Test the '_raw_options' attribute getter.
        """
        packet = Ip4FragAssembler(
            options=[Ip4OptNop(), Ip4OptEol()],
        )
        self.assertEqual(packet._raw_options, b"\x01\x00")

    def test_ip4_frag_fpa__assemble(self) -> None:
        """
        Test the 'assemble() method.
        """
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
        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame)
        self.assertEqual(
            bytes(frame),
            b"E*\x00&09:\x86 \xff\x1d\xdd\x01\x02\x03\x04\x05\x06"
            b"\x07\x08\x01\x000123456789ABCDEF",
        )


class TestIp4OptEol(TestCase):
    """
    IPv4 EOL option unit test class.
    """

    def test_ip4_fpa_opt_eol____str__(self) -> None:
        """
        Test the '__str__() dunder.
        """
        option = Ip4OptEol()
        self.assertEqual(str(option), "eol")

    def test_ip4_fpa_opt_eol____repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        option = Ip4OptEol()
        self.assertEqual(repr(option), "Ip4OptEol()")

    def test_ip4_fpa_opt_eol____bytes__(self) -> None:
        """
        Test the '__bytes__()' dunder.
        """
        option = Ip4OptEol()
        self.assertEqual(bytes(option), b"\x00")

    def test_ip4_fpa_opt_eol____eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        option = Ip4OptEol()
        self.assertEqual(option, Ip4OptEol())


class TestIp4OptNop(TestCase):
    """
    IPv4 NOP option unit test class.
    """

    def test_ip4_fpa_opt_nop____str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        option = Ip4OptNop()
        self.assertEqual(str(option), "nop")

    def test_ip4_fpa_opt_nop____repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        option = Ip4OptNop()
        self.assertEqual(repr(option), "Ip4OptNop()")

    def test_ip4_fpa_opt_nop____bytes__(self) -> None:
        """
        Test the '__bytes__()' dunder.
        """
        option = Ip4OptNop()
        self.assertEqual(bytes(option), b"\x01")

    def test_ip4_fpa_opt_nop____eq__(self) -> None:
        """
        Test the '__eq__' dunder.
        """
        option = Ip4OptNop()
        self.assertEqual(option, Ip4OptNop())
