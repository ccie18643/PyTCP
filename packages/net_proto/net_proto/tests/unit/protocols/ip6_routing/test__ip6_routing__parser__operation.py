################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the IPv6 Routing parser happy-path operation tests.

net_proto/tests/unit/protocols/ip6_routing/test__ip6_routing__parser__operation.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto.lib.enums import IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ip6_routing.ip6_routing__enums import Ip6RoutingType
from net_proto.protocols.ip6_routing.ip6_routing__parser import Ip6RoutingParser


class TestIp6RoutingParserOperation(TestCase):
    """
    The IPv6 Routing parser happy-path operation tests.
    """

    def test__ip6_routing__parser__header(self) -> None:
        """
        Ensure the parsed header reflects the four wire bytes
        exactly (next, hdr_ext_len, routing_type, segments_left).

        Reference: RFC 8200 §4.4 (Routing Header wire format).
        """

        # Routing wire frame (8 bytes):
        #   Bytes 0-3 : 06 00 04 02 -> next=TCP, hdr_ext_len=0, RH4, sl=2
        #   Bytes 4-7 : aa bb cc dd -> type-specific data
        parser = Ip6RoutingParser(PacketRx(b"\x06\x00\x04\x02\xaa\xbb\xcc\xdd"))

        self.assertIs(parser.header.next, IpProto.TCP, msg="Parsed 'next' must equal IpProto.TCP.")
        self.assertEqual(parser.header.hdr_ext_len, 0, msg="Parsed 'hdr_ext_len' must equal 0.")
        self.assertIs(parser.header.routing_type, Ip6RoutingType.RH4, msg="Parsed 'routing_type' must equal RH4.")
        self.assertEqual(parser.header.segments_left, 2, msg="Parsed 'segments_left' must equal 2.")

    def test__ip6_routing__parser__data_preserved(self) -> None:
        """
        Ensure the type-specific data block is preserved
        byte-for-byte for Phase-2 forwarder re-emission.

        Reference: RFC 8200 §4.4 (type-specific data preservation).
        """

        # Routing wire frame:
        #   Bytes 0-3 : 06 01 04 02 -> next=TCP, hdr_ext_len=1, RH4, sl=2
        #   Bytes 4-15: 12 bytes of opaque data
        data = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55"
        frame = b"\x06\x01\x04\x02" + data
        parser = Ip6RoutingParser(PacketRx(frame))

        self.assertEqual(
            parser.data,
            data,
            msg="Routing type-specific data must round-trip byte-for-byte.",
        )

    def test__ip6_routing__parser__payload(self) -> None:
        """
        Ensure the parsed payload contains exactly the bytes
        following the declared Routing region.

        Reference: RFC 8200 §4.4 (Routing Header followed by next header).
        """

        # Routing wire frame + payload:
        #   Bytes 0-7 : 06 00 04 02 aa bb cc dd -> 8-byte RH
        #   Bytes 8+  : "PAYLOAD"
        frame = b"\x06\x00\x04\x02\xaa\xbb\xcc\xddPAYLOAD"
        parser = Ip6RoutingParser(PacketRx(frame))
        self.assertEqual(
            bytes(parser.payload),
            b"PAYLOAD",
            msg="Parsed payload must equal the post-header bytes.",
        )

    def test__ip6_routing__parser__packet_rx_ip6_routing(self) -> None:
        """
        Ensure the parser installs itself onto 'packet_rx.ip6_routing'.

        Reference: RFC 8200 §4.1 (extension-header chain order).
        """

        packet_rx = PacketRx(b"\x06\x00\x04\x02\xaa\xbb\xcc\xdd")
        parser = Ip6RoutingParser(packet_rx)
        self.assertIs(
            packet_rx.ip6_routing,
            parser,
            msg="Parser must install itself onto packet_rx.ip6_routing.",
        )

    def test__ip6_routing__parser__packet_rx_frame_advanced(self) -> None:
        """
        Ensure 'packet_rx.frame' has been advanced past the entire
        Routing region (fixed prefix + type-specific data).

        Reference: RFC 8200 §4.1 (extension-header chain order).
        """

        frame = b"\x06\x00\x04\x02\xaa\xbb\xcc\xddTCP_DATA"
        packet_rx = PacketRx(frame)
        Ip6RoutingParser(packet_rx)
        self.assertEqual(
            bytes(packet_rx.frame),
            b"TCP_DATA",
            msg="packet_rx.frame must be advanced past the Routing region.",
        )

    def test__ip6_routing__parser__rh3_accepted(self) -> None:
        """
        Ensure routing_type=3 (RPL) parses cleanly — non-RH0 types
        pass through the integrity layer untouched. The host has no
        semantic action; data preserved for forwarder re-emission.

        Reference: RFC 8200 §4.4 (non-RH0 types parsed as opaque).
        """

        # Routing wire frame (8 bytes):
        #   Bytes 0-3 : 06 00 03 02 -> next=TCP, hdr_ext_len=0, RH3, sl=2
        #   Bytes 4-7 : 11 22 33 44 -> opaque data
        parser = Ip6RoutingParser(PacketRx(b"\x06\x00\x03\x02\x11\x22\x33\x44"))
        self.assertIs(
            parser.routing_type,
            Ip6RoutingType.RH3,
            msg="RH3 must parse with routing_type=Ip6RoutingType.RH3.",
        )

    def test__ip6_routing__parser__unknown_type_accepted(self) -> None:
        """
        Ensure an IANA-unassigned routing_type parses as a
        dynamically-extended unknown enum member, with the wire
        bytes preserved for Phase-2 forwarder re-emission.

        Reference: RFC 8200 §4.4 (unrecognized routing types).
        """

        # Routing wire frame (8 bytes):
        #   Bytes 0-3 : 06 00 99 00 -> routing_type=0x99 (unknown)
        #   Bytes 4-7 : 00 00 00 00 -> data
        parser = Ip6RoutingParser(PacketRx(b"\x06\x00\x99\x00\x00\x00\x00\x00"))
        self.assertEqual(
            int(parser.routing_type),
            0x99,
            msg="Unknown routing type must round-trip its wire byte value.",
        )
        self.assertTrue(
            parser.routing_type.is_unknown,
            msg="Unknown routing type must report is_unknown=True.",
        )
