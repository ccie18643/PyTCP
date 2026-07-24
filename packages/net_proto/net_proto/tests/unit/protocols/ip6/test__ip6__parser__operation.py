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
This module contains tests for the IPv6 packet parser operation.

net_proto/tests/unit/protocols/ip6/test__ip6__parser__operation.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Ip6Header, Ip6Parser, IpProto, PacketRx
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "IPv6 header-only frame (dlen=0, hop=1).",
            # IPv6 wire frame (40 bytes, header only):
            #   Bytes 0-3   : 0x60000000 ->
            #                 ver=6, dscp=0, ecn=0, flow=0
            #   Bytes 4-5   : 0x0000 -> dlen=0
            #   Byte  6     : 0xff   -> next=IpProto.RAW
            #   Byte  7     : 0x01   -> hop=1
            #   Bytes 8-23  : src=1001:2002:3003:4004:5005:6006:7007:8008
            #   Bytes 24-39 : dst=a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b
            "_frame_rx": (
                b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
            ),
            "_results": {
                "header": Ip6Header(
                    dscp=0,
                    ecn=0,
                    flow=0,
                    dlen=0,
                    next=IpProto.RAW,
                    hop=1,
                    src=Ip6Address("1001:2002:3003:4004:5005:6006:7007:8008"),
                    dst=Ip6Address("a00a:b00b:c00c:d00d:e00e:f00f:0a0a:0b0b"),
                ),
                "payload": b"",
                "header_bytes": (
                    b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                    b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                    b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
                ),
                "payload_bytes": b"",
                "packet_bytes": (
                    b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                    b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                    b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
                ),
            },
        },
        {
            "_description": "IPv6 header with 16-byte ASCII payload and maximum flow value.",
            # IPv6 wire frame (56 bytes = 40-byte header + 16-byte payload):
            #   Bytes 0-3   : 0x69afffff ->
            #                 ver=6, dscp=38, ecn=2, flow=0xfffff (1048575)
            #   Bytes 4-5   : 0x0010 -> dlen=16
            #   Byte  6     : 0xff   -> next=IpProto.RAW
            #   Byte  7     : 0xff   -> hop=255
            #   Bytes 8-23  : src=1111:2222:3333:4444:5555:6666:7777:8888
            #   Bytes 24-39 : dst=8888:7777:6666:5555:4444:3333:2222:1111
            #   Bytes 40-55 : b"0123456789ABCDEF" (ASCII payload)
            "_frame_rx": (
                b"\x69\xaf\xff\xff\x00\x10\xff\xff\x11\x11\x22\x22\x33\x33\x44\x44"
                b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                b"\x44\x44\x33\x33\x22\x22\x11\x11\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "header": Ip6Header(
                    dscp=38,
                    ecn=2,
                    flow=1048575,
                    dlen=16,
                    next=IpProto.RAW,
                    hop=255,
                    src=Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                    dst=Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                ),
                "payload": b"0123456789ABCDEF",
                "header_bytes": (
                    b"\x69\xaf\xff\xff\x00\x10\xff\xff\x11\x11\x22\x22\x33\x33\x44\x44"
                    b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                    b"\x44\x44\x33\x33\x22\x22\x11\x11"
                ),
                "payload_bytes": b"0123456789ABCDEF",
                "packet_bytes": (
                    b"\x69\xaf\xff\xff\x00\x10\xff\xff\x11\x11\x22\x22\x33\x33\x44\x44"
                    b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                    b"\x44\x44\x33\x33\x22\x22\x11\x11\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
        },
        {
            "_description": "IPv6 at maximum dlen (65535) with 65495-byte payload.",
            # IPv6 wire frame (65535 bytes = 40-byte header + 65495-byte
            # payload). dlen=65495 is the largest value that fits inside
            # a 16-bit unsigned integer after accounting for the 40-byte
            # fixed header, mirroring the IP4 maximum-length fixture.
            #   Bytes 0-3   : 0x6ff00000 ->
            #                 ver=6, dscp=63, ecn=3, flow=0
            #   Bytes 4-5   : 0xffd7 -> dlen=65495
            #   Byte  6     : 0xff   -> next=IpProto.RAW
            #   Byte  7     : 0x80   -> hop=128
            #   Bytes 8-23  : src=1111:2222:3333:4444:5555:6666:7777:8888
            #   Bytes 24-39 : dst=8888:7777:6666:5555:4444:3333:2222:1111
            #   Bytes 40+   : 65495 bytes of 'X'
            "_frame_rx": (
                b"\x6f\xf0\x00\x00\xff\xd7\xff\x80\x11\x11\x22\x22\x33\x33\x44\x44"
                b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                b"\x44\x44\x33\x33\x22\x22\x11\x11" + b"X" * 65495
            ),
            "_results": {
                "header": Ip6Header(
                    dscp=63,
                    ecn=3,
                    flow=0,
                    dlen=65495,
                    next=IpProto.RAW,
                    hop=128,
                    src=Ip6Address("1111:2222:3333:4444:5555:6666:7777:8888"),
                    dst=Ip6Address("8888:7777:6666:5555:4444:3333:2222:1111"),
                ),
                "payload": b"X" * 65495,
                "header_bytes": (
                    b"\x6f\xf0\x00\x00\xff\xd7\xff\x80\x11\x11\x22\x22\x33\x33\x44\x44"
                    b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                    b"\x44\x44\x33\x33\x22\x22\x11\x11"
                ),
                "payload_bytes": b"X" * 65495,
                "packet_bytes": (
                    b"\x6f\xf0\x00\x00\xff\xd7\xff\x80\x11\x11\x22\x22\x33\x33\x44\x44"
                    b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                    b"\x44\x44\x33\x33\x22\x22\x11\x11" + b"X" * 65495
                ),
            },
        },
    ]
)
class TestIp6PacketParserOperation(TestCase):
    """
    The IPv6 packet parser operation tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx so it can be fed to
        Ip6Parser.
        """

        self._packet_rx = PacketRx(self._frame_rx)

    def test__ip6__parser__header(self) -> None:
        """
        Ensure the parser exposes the expected Ip6Header object.

        Reference: RFC 8200 §3 (IPv6 datagram parse — header + payload).
        """

        parser = Ip6Parser(self._packet_rx)

        self.assertEqual(
            parser.header,
            self._results["header"],
            msg=f"Unexpected parsed header for case: {self._description}",
        )

    def test__ip6__parser__header_bytes(self) -> None:
        """
        Ensure 'header_bytes' returns the first IP6__HEADER__LEN bytes
        of the frame.

        Reference: RFC 8200 §3 (IPv6 datagram parse — header + payload).
        """

        parser = Ip6Parser(self._packet_rx)

        self.assertEqual(
            bytes(parser.header_bytes),
            self._results["header_bytes"],
            msg=f"Unexpected header_bytes for case: {self._description}",
        )

    def test__ip6__parser__payload_bytes(self) -> None:
        """
        Ensure 'payload_bytes' returns the dlen-byte region that follows
        the fixed header.

        Reference: RFC 8200 §3 (IPv6 datagram parse — header + payload).
        """

        parser = Ip6Parser(self._packet_rx)

        self.assertEqual(
            bytes(parser.payload_bytes),
            self._results["payload_bytes"],
            msg=f"Unexpected payload_bytes for case: {self._description}",
        )

    def test__ip6__parser__packet_bytes(self) -> None:
        """
        Ensure 'packet_bytes' returns the full header + payload span.

        Reference: RFC 8200 §3 (IPv6 datagram parse — header + payload).
        """

        parser = Ip6Parser(self._packet_rx)

        self.assertEqual(
            bytes(parser.packet_bytes),
            self._results["packet_bytes"],
            msg=f"Unexpected packet_bytes for case: {self._description}",
        )

    def test__ip6__parser__packet_rx_ip6_backref(self) -> None:
        """
        Ensure the parser stores itself on the PacketRx as both 'ip'
        and 'ip6' so downstream handlers can look it up by either name.

        Reference: RFC 8200 §3 (IPv6 datagram parse — header + payload).
        """

        parser = Ip6Parser(self._packet_rx)

        self.assertIs(
            self._packet_rx.ip6,
            parser,
            msg=f"PacketRx.ip6 must reference the parser for case: {self._description}",
        )
        self.assertIs(
            self._packet_rx.ip,
            parser,
            msg=f"PacketRx.ip must reference the parser for case: {self._description}",
        )

    def test__ip6__parser__packet_rx_frame_advanced_to_payload(self) -> None:
        """
        Ensure the parser advances 'PacketRx.frame' past the IPv6 header
        to the payload bytes so the next-layer parser sees only what it
        is supposed to consume.

        Reference: RFC 8200 §3 (IPv6 datagram parse — header + payload).
        """

        Ip6Parser(self._packet_rx)

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
            msg=f"PacketRx.frame must be advanced to payload for case: {self._description}",
        )
