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
# tests/icmp6_fpa.py -  tests specific for ICMPv6 fpa module
#

from testslide import TestCase

from pytcp.lib.mac_address import MacAddress
from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp6.fpa import Icmp6Assembler, Icmp6NdOptSLLA, Icmp6NdOptTLLA
from pytcp.protocols.icmp6.ps import (
    ICMP6_ECHO_REPLY,
    ICMP6_ECHO_REPLY_LEN,
    ICMP6_ECHO_REQUEST,
    ICMP6_ECHO_REQUEST_LEN,
    ICMP6_ND_OPT_SLLA_LEN,
    ICMP6_ND_OPT_TLLA_LEN,
    ICMP6_ND_ROUTER_ADVERTISEMENT,
    ICMP6_ND_ROUTER_ADVERTISEMENT_LEN,
    ICMP6_ND_ROUTER_SOLICITATION,
    ICMP6_ND_ROUTER_SOLICITATION_LEN,
    ICMP6_UNREACHABLE,
    ICMP6_UNREACHABLE__PORT,
    ICMP6_UNREACHABLE_LEN,
)
from pytcp.protocols.ip6.ps import IP6_NEXT_ICMP6


class TestIcmp6Assembler(TestCase):
    def test_icmp6_fpa__ip6_next_icmp6(self):
        """Test the ip6_next property of Icmp6Assembler class"""

        self.assertEqual(Icmp6Assembler.ip6_next, IP6_NEXT_ICMP6)

    def test_icmp6_fpa____init____unreachable_port(self):
        """Test class constructor for Unreachable Port message"""

        packet = Icmp6Assembler(
            type=ICMP6_UNREACHABLE,
            code=ICMP6_UNREACHABLE__PORT,
            un_data=b"0123456789ABCDEF" * 50,
            echo_tracker=Tracker(prefix="TX"),
        )

        self.assertEqual(packet._un_data, (b"0123456789ABCDEF" * 50)[:520])
        self.assertTrue(repr(packet.tracker._echo_tracker).startswith("Tracker(serial='<lr>TX"))

    def test_icmp6_fpa____init____unreachable_port__assert_code__under(self):
        """Test class constructor for Unreachable Port message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REQUEST,
                code=ICMP6_UNREACHABLE__PORT - 1,
            )

    def test_icmp6_fpa____init____unreachable_port__assert_code__over(self):
        """Test class constructor for Unreachable Port message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REQUEST,
                code=ICMP6_UNREACHABLE__PORT + 1,
            )

    def test_icmp6_fpa____init____echo_request(self):
        """Test class constructor for Echo Request message"""

        packet = Icmp6Assembler(
            type=ICMP6_ECHO_REQUEST,
            code=0,
            ec_id=12345,
            ec_seq=54321,
            ec_data=b"0123456789ABCDEF",
            echo_tracker=Tracker(prefix="TX"),
        )

        self.assertEqual(packet._ec_id, 12345)
        self.assertEqual(packet._ec_seq, 54321)
        self.assertEqual(packet._ec_data, b"0123456789ABCDEF")
        self.assertTrue(repr(packet.tracker._echo_tracker).startswith("Tracker(serial='<lr>TX"))

    def test_icmp6_fpa____init____echo_request__assert_code__under(self):
        """Test class constructor for Echo Request message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REQUEST,
                code=-1,
            )

    def test_icmp6_fpa____init____echo_request__assert_code__over(self):
        """Test class constructor for Echo Request message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REQUEST,
                code=1,
            )

    def test_icmp6_fpa____init____echo_request__assert_ec_id__under(self):
        """Test assertion for the ec_id"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REQUEST,
                code=0,
                ec_id=-1,
            )

    def test_icmp6_fpa____init____echo_request__assert_ec_id__over(self):
        """Test assertion for the ec_id"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REQUEST,
                code=0,
                ec_id=0x10000,
            )

    def test_icmp6_fpa____init____echo_request__assert_ec_seq__under(self):
        """Test assertion for the ec_id"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REQUEST,
                code=0,
                ec_seq=-1,
            )

    def test_icmp6_fpa____init____echo_request__assert_ec_seq__over(self):
        """Test assertion for the ec_seq"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REQUEST,
                code=0,
                ec_seq=0x10000,
            )

    def test_icmp6_fpa____init____echo_reply(self):
        """Test class constructor for Echo Reply message"""

        packet = Icmp6Assembler(
            type=ICMP6_ECHO_REPLY,
            code=0,
            ec_id=12345,
            ec_seq=54321,
            ec_data=b"0123456789ABCDEF",
            echo_tracker=Tracker(prefix="TX"),
        )

        self.assertEqual(packet._ec_id, 12345)
        self.assertEqual(packet._ec_seq, 54321)
        self.assertEqual(packet._ec_data, b"0123456789ABCDEF")
        self.assertTrue(repr(packet.tracker._echo_tracker).startswith("Tracker(serial='<lr>TX"))

    def test_icmp6_fpa____init____echo_reply__assert_code__under(self):
        """Test class constructor for Echo Reply message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REPLY,
                code=-1,
            )

    def test_icmp6_fpa____init____echo_reply__assert_code__over(self):
        """Test class constructor for Echo Reply message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REPLY,
                code=1,
            )

    def test_icmp6_fpa____init____echo_reply__assert_ec_id__under(self):
        """Test assertion for the ec_id"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REPLY,
                code=0,
                ec_id=-1,
            )

    def test_icmp6_fpa____init____echo_reply__assert_ec_id__over(self):
        """Test assertion for the ec_id"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REPLY,
                code=0,
                ec_id=0x10000,
            )

    def test_icmp6_fpa____init____echo_reply__assert_ec_seq__under(self):
        """Test assertion for the ec_id"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REPLY,
                code=0,
                ec_seq=-1,
            )

    def test_icmp6_fpa____init____echo_reply__assert_ec_seq__over(self):
        """Test assertion for the ec_seq"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ECHO_REPLY,
                code=0,
                ec_seq=0x10000,
            )

    def test_icmp6_fpa____init____unknown(self):
        """Test class constructor for message with unknown type"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=255,
            )

    def test_icmp6_fpa____init____nd_router_solicitation(self):
        """Test class constructor for ND Router Solicitation message"""

        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_SOLICITATION,
            code=0,
            nd_options=[Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66"))],
            echo_tracker=Tracker(prefix="TX"),
        )

        self.assertEqual(packet._nd_options, [Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66"))])
        self.assertTrue(repr(packet.tracker._echo_tracker).startswith("Tracker(serial='<lr>TX"))

    def test_icmp6_fpa____init____nd_router_solicitation__assert_code__under(self):
        """Test class constructor for ND Router Solicitation message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_SOLICITATION,
                code=-1,
            )

    def test_icmp6_fpa____init____nd_router_solicitation__assert_code__over(self):
        """Test class constructor for ND Router Solicitation message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_SOLICITATION,
                code=1,
            )

    def test_icmp6_fpa____init____nd_router_advertisement(self):
        """Test class constructor for ND Router Advertisement message"""

        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_ADVERTISEMENT,
            code=0,
            ra_hop=255,
            ra_flag_m=True,
            ra_flag_o=True,
            ra_router_lifetime=12345,
            ra_reachable_time=12345678,
            ra_retrans_timer=87654321,
            nd_options=[Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66"))],
            echo_tracker=Tracker(prefix="TX"),
        )

        self.assertEqual(packet._ra_hop, 255),
        self.assertEqual(packet._ra_flag_m, True),
        self.assertEqual(packet._ra_flag_o, True),
        self.assertEqual(packet._ra_router_lifetime, 12345),
        self.assertEqual(packet._ra_reachable_time, 12345678),
        self.assertEqual(packet._ra_retrans_timer, 87654321),
        self.assertEqual(packet._nd_options, [Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66"))])
        self.assertTrue(repr(packet.tracker._echo_tracker).startswith("Tracker(serial='<lr>TX"))

    def test_icmp6_fpa____init____nd_router_advertisement__assert_code__under(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                code=-1,
            )

    def test_icmp6_fpa____init____nd_router_advertisement__assert_code__over(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                code=1,
            )

    def test_icmp6_fpa____init____nd_router_advertisement__assert_hop__under(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                ra_hop=-1,
            )

    def test_icmp6_fpa____init____nd_router_advertisement__assert_hop__over(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                ra_hop=0x100,
            )

    def test_icmp6_fpa____init____nd_router_advertisement__assert_router_lifetime__under(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                ra_router_lifetime=-1,
            )

    def test_icmp6_fpa____init____nd_router_advertisement__assert_router_lifetime__over(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                ra_router_lifetime=0x10000,
            )

    def test_icmp6_fpa____init____nd_router_advertisement__assert_reachable_time__under(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                ra_reachable_time=-1,
            )

    def test_icmp6_fpa____init____nd_router_advertisement__assert_reachable_time__over(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                ra_reachable_time=0x100000000,
            )

    def test_icmp6_fpa____init____nd_router_advertisement__assert_retrans_timer__under(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                ra_retrans_timer=-1,
            )

    def test_icmp6_fpa____init____nd_router_advertisement__assert_retrans_timer__over(self):
        """Test class constructor for ND Router Advertisement message"""

        with self.assertRaises(AssertionError):
            Icmp6Assembler(
                type=ICMP6_ND_ROUTER_ADVERTISEMENT,
                ra_retrans_timer=0x100000000,
            )

    def test_icmp6_fpa____len____unreachable_port(self):
        """Test class __len__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_UNREACHABLE,
            code=ICMP6_UNREACHABLE__PORT,
            un_data=b"0123456789ABCDEF",
        )

        self.assertEqual(len(packet), ICMP6_UNREACHABLE_LEN + 16)

    def test_icmp6_fpa____len____echo_request(self):
        """Test class __len__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_ECHO_REQUEST,
            code=0,
            ec_data=b"0123456789ABCDEF",
        )

        self.assertEqual(len(packet), ICMP6_ECHO_REQUEST_LEN + 16)

    def test_icmp6_fpa____len____echo_reply(self):
        """Test class __len__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_ECHO_REPLY,
            code=0,
            ec_data=b"0123456789ABCDEF",
        )

        self.assertEqual(len(packet), ICMP6_ECHO_REPLY_LEN + 16)

    def test_icmp6_fpa____len____nd_router_solicitation(self):
        """Test class __len__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_SOLICITATION,
            code=0,
            nd_options=[
                Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66")),
                Icmp6NdOptTLLA(MacAddress("66:55:44:33:22:11")),
            ],
        )

        self.assertEqual(len(packet), ICMP6_ND_ROUTER_SOLICITATION_LEN + ICMP6_ND_OPT_SLLA_LEN + ICMP6_ND_OPT_TLLA_LEN)

    def test_icmp6_fpa____len____nd_router_advertisement(self):
        """Test class __len__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_ADVERTISEMENT,
            code=0,
            ra_hop=255,
            ra_flag_m=True,
            ra_flag_o=True,
            ra_router_lifetime=12345,
            ra_reachable_time=12345678,
            ra_retrans_timer=87654321,
            nd_options=[
                Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66")),
                Icmp6NdOptTLLA(MacAddress("66:55:44:33:22:11")),
            ],
            echo_tracker=Tracker(prefix="TX"),
        )

        self.assertEqual(len(packet), ICMP6_ND_ROUTER_ADVERTISEMENT_LEN + ICMP6_ND_OPT_SLLA_LEN + ICMP6_ND_OPT_TLLA_LEN)

    def test_icmp6_fpa____str____unreachable_port(self):
        """Test class __str__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_UNREACHABLE,
            code=ICMP6_UNREACHABLE__PORT,
            un_data=b"0123456789ABCDEF",
        )
        
        self.assertEqual(str(packet), "ICMPv6 1/4 (unreachable_port), dlen 16")

    def test_icmp6_fpa____str____echo_request(self):
        """Test class __str__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_ECHO_REQUEST,
            code=0,
            ec_id=12345,
            ec_seq=54321,
            ec_data=b"0123456789ABCDEF",
        )
        
        self.assertEqual(str(packet), "ICMPv6 128/0 (echo_request), id 12345, seq 54321, dlen 16")

    def test_icmp6_fpa____str____echo_reply(self):
        """Test class __str__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_ECHO_REPLY,
            code=0,
            ec_id=12345,
            ec_seq=54321,
            ec_data=b"0123456789ABCDEF",
        )
        
        self.assertEqual(str(packet), "ICMPv6 129/0 (echo_reply), id 12345, seq 54321, dlen 16")

    def test_icmp6_fpa____str____nd_router_solicitation(self):
        """Test class __str__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_SOLICITATION,
            code=0,
            nd_options=[
                Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66")),
                Icmp6NdOptTLLA(MacAddress("66:55:44:33:22:11")),
            ],
        )
        
        self.assertEqual(
            str(packet),
            "ICMPv6 133/0 (nd_router_solicitation), slla 11:22:33:44:55:66, tlla 66:55:44:33:22:11",
        )

    def test_icmp6_fpa____str____nd_router_solicitation__no_options(self):
        """Test class __str__ operator"""

        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_SOLICITATION,
            code=0,
        )
        
        self.assertEqual(str(packet), "ICMPv6 133/0 (nd_router_solicitation)")

    def test_icmp6_fpa____str____nd_router_advertisement(self):
        """Test class __str__ operator"""
        
        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_ADVERTISEMENT,
            code=0,
            ra_hop=255,
            ra_flag_m=True,
            ra_flag_o=True,
            ra_router_lifetime=12345,
            ra_reachable_time=12345678,
            ra_retrans_timer=87654321,
            nd_options=[
                Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66")),
                Icmp6NdOptTLLA(MacAddress("66:55:44:33:22:11")),
            ],
            echo_tracker=Tracker(prefix="TX"),
        )

        self.assertEqual(
            str(packet),
            "ICMPv6 134/0 (nd_router_advertisement), hop 255, flags MO, rlft 12345, "
            "reacht 12345678, retrt 87654321, slla 11:22:33:44:55:66, tlla 66:55:44:33:22:11"
        )
    
    def test_icmp6_fpa____str____nd_router_advertisement__no_options(self):
        """Test class __str__ operator"""
        
        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_ADVERTISEMENT,
            code=0,
            ra_hop=255,
            ra_flag_m=True,
            ra_flag_o=True,
            ra_router_lifetime=12345,
            ra_reachable_time=12345678,
            ra_retrans_timer=87654321,
            echo_tracker=Tracker(prefix="TX"),
        )
        
        self.assertEqual(
            str(packet),
            "ICMPv6 134/0 (nd_router_advertisement), hop 255, flags MO, rlft 12345, "
            "reacht 12345678, retrt 87654321"
        )
    
    def test_icmp6_fpa__tracker_getter(self):
        """Test tracker getter"""

        packet = Icmp6Assembler()
        self.assertTrue(repr(packet.tracker).startswith("Tracker(serial='<lr>TX"))

    def test_icmp6_fpa__asssemble__unreachable_port(self):
        """Test assemble method"""

        packet = Icmp6Assembler(
            type=ICMP6_UNREACHABLE,
            code=ICMP6_UNREACHABLE__PORT,
            un_data=b"0123456789ABCDEF",
        )

        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame, 1234567)
        self.assertEqual(bytes(frame), b"\x01\x04Y\x8b\x00\x00\x00\x000123456789ABCDEF")

    def test_icmp6_fpa__assemble__echo_request(self):
        """Test assemble method"""

        packet = Icmp6Assembler(
            type=ICMP6_ECHO_REQUEST,
            code=0,
            ec_id=12345,
            ec_seq=54321,
            ec_data=b"0123456789ABCDEF",
        )

        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame, 12345678)
        self.assertEqual(bytes(frame), b"\x80\x00J\xb309\xd410123456789ABCDEF")

    def test_icmp6_fpa__assemble__echo_reply(self):
        """Test assemble method"""

        packet = Icmp6Assembler(
            type=ICMP6_ECHO_REPLY,
            code=0,
            ec_id=12345,
            ec_seq=54321,
            ec_data=b"0123456789ABCDEF",
        )

        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame, 12345678)
        self.assertEqual(bytes(frame), b"\x81\x00I\xb309\xd410123456789ABCDEF")

    def test_icmp6_fpa__assemble__nd_router_solicitation(self):
        """Test assemble method"""

        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_SOLICITATION,
            code=0,
            nd_options=[
                Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66")),
                Icmp6NdOptTLLA(MacAddress("66:55:44:33:22:11")),
            ],
        )

        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame, 12345678)
        self.assertEqual(bytes(frame), b"\x85\x00\xaf\x8c\x00\x00\x00\x00\x01\x01\x11\"3DUf\x02\x01fUD3\"\x11")
    
    def test_icmp6_fpa__assemble__nd_router_advertisement(self):
        """Test assemble method"""

        packet = Icmp6Assembler(
            type=ICMP6_ND_ROUTER_ADVERTISEMENT,
            code=0,
            ra_hop=255,
            ra_flag_m=True,
            ra_flag_o=True,
            ra_router_lifetime=12345,
            ra_reachable_time=12345678,
            ra_retrans_timer=87654321,
            nd_options=[
                Icmp6NdOptSLLA(MacAddress("11:22:33:44:55:66")),
                Icmp6NdOptTLLA(MacAddress("66:55:44:33:22:11")),
            ],
            echo_tracker=Tracker(prefix="TX"),
        )

        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame, 12345678)
        self.assertEqual(bytes(frame), b"\x86\x00\x97\x9d\xff\xc009\x00\xbcaN\x059\x7f\xb1\x01\x01\x11\"3DUf\x02\x01fUD3\"\x11")
