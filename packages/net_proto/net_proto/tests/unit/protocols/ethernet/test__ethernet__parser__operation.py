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
This module contains tests for the Ethernet II packet parser operation.

The parser consumes a PacketRx object, validates the frame, parses the 14-byte
Ethernet II header and advances PacketRx.frame past the header so that
upper-layer parsers can pick up the payload transparently.

net_proto/tests/unit/protocols/ethernet/test__ethernet__parser__operation.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import MacAddress
from net_proto import EthernetHeader, EthernetParser, EtherType, PacketRx
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Ethernet II frame with a 16-byte Raw payload.",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : 11:22:33:44:55:66
                #   Source MAC      : 78:89:9a:ab:bc:cd
                #   Ethertype       : 0xffff (Raw)
                #   Payload         : b"0123456789ABCDEF" (16 bytes)
                b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\xff\xff"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "header": EthernetHeader(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("78:89:9a:ab:bc:cd"),
                    type=EtherType.RAW,
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("78:89:9a:ab:bc:cd"),
                "type": EtherType.RAW,
                "payload": b"0123456789ABCDEF",
                "__len__": 14 + 16,
                "__str__": "ETHER 78:89:9a:ab:bc:cd > 11:22:33:44:55:66, type Raw, len 30 (14+16)",
            },
        },
        {
            "_description": "Ethernet II frame with a 1500-byte Raw payload (MTU-sized).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 12:13:14:15:16:17
                #   Ethertype       : 0xffff (Raw)
                #   Payload         : b"X" * 1500
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\xff\xff"
                + b"X" * 1500
            ),
            "_results": {
                "header": EthernetHeader(
                    dst=MacAddress("a1:b2:c3:d4:e5:f6"),
                    src=MacAddress("12:13:14:15:16:17"),
                    type=EtherType.RAW,
                ),
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("12:13:14:15:16:17"),
                "type": EtherType.RAW,
                "payload": b"X" * 1500,
                "__len__": 14 + 1500,
                "__str__": "ETHER 12:13:14:15:16:17 > a1:b2:c3:d4:e5:f6, type Raw, len 1514 (14+1500)",
            },
        },
        {
            "_description": "Ethernet II frame carrying an IPv4 payload (EtherType 0x0800).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : 01:02:03:04:05:06
                #   Source MAC      : 0a:0b:0c:0d:0e:0f
                #   Ethertype       : 0x0800 (IPv4)
                #   Payload         : 4 opaque bytes (parser treats as raw buffer)
                b"\x01\x02\x03\x04\x05\x06\x0a\x0b\x0c\x0d\x0e\x0f\x08\x00"
                b"\xde\xad\xbe\xef"
            ),
            "_results": {
                "header": EthernetHeader(
                    dst=MacAddress("01:02:03:04:05:06"),
                    src=MacAddress("0a:0b:0c:0d:0e:0f"),
                    type=EtherType.IP4,
                ),
                "dst": MacAddress("01:02:03:04:05:06"),
                "src": MacAddress("0a:0b:0c:0d:0e:0f"),
                "type": EtherType.IP4,
                "payload": b"\xde\xad\xbe\xef",
                "__len__": 14 + 4,
                "__str__": "ETHER 0a:0b:0c:0d:0e:0f > 01:02:03:04:05:06, type IPv4, len 18 (14+4)",
            },
        },
        {
            "_description": "Ethernet II frame carrying an IPv6 payload (EtherType 0x86dd).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : 33:33:00:00:00:01
                #   Source MAC      : aa:bb:cc:dd:ee:ff
                #   Ethertype       : 0x86dd (IPv6)
                #   Payload         : 3 opaque bytes (parser treats as raw buffer)
                b"\x33\x33\x00\x00\x00\x01\xaa\xbb\xcc\xdd\xee\xff\x86\xdd"
                b"\xca\xfe\x00"
            ),
            "_results": {
                "header": EthernetHeader(
                    dst=MacAddress("33:33:00:00:00:01"),
                    src=MacAddress("aa:bb:cc:dd:ee:ff"),
                    type=EtherType.IP6,
                ),
                "dst": MacAddress("33:33:00:00:00:01"),
                "src": MacAddress("aa:bb:cc:dd:ee:ff"),
                "type": EtherType.IP6,
                "payload": b"\xca\xfe\x00",
                "__len__": 14 + 3,
                "__str__": "ETHER aa:bb:cc:dd:ee:ff > 33:33:00:00:00:01, type IPv6, len 17 (14+3)",
            },
        },
        {
            "_description": "Ethernet II frame carrying an ARP payload (EtherType 0x0806).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 00:11:22:33:44:55
                #   Ethertype       : 0x0806 (ARP)
                #   Payload         : 2 opaque bytes (parser treats as raw buffer)
                b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x06"
                b"\x00\x01"
            ),
            "_results": {
                "header": EthernetHeader(
                    dst=MacAddress("ff:ff:ff:ff:ff:ff"),
                    src=MacAddress("00:11:22:33:44:55"),
                    type=EtherType.ARP,
                ),
                "dst": MacAddress("ff:ff:ff:ff:ff:ff"),
                "src": MacAddress("00:11:22:33:44:55"),
                "type": EtherType.ARP,
                "payload": b"\x00\x01",
                "__len__": 14 + 2,
                "__str__": "ETHER 00:11:22:33:44:55 > ff:ff:ff:ff:ff:ff, type ARP, len 16 (14+2)",
            },
        },
        {
            "_description": "Ethernet II frame with an unknown EtherType (0x9999).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : 11:22:33:44:55:66
                #   Source MAC      : 78:89:9a:ab:bc:cd
                #   Ethertype       : 0x9999 (unknown — extended into EtherType enum)
                #   Payload         : 4 opaque bytes
                b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x99\x99"
                b"\x00\x00\x00\x00"
            ),
            "_results": {
                "header": EthernetHeader(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("78:89:9a:ab:bc:cd"),
                    type=EtherType.from_int(0x9999),
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("78:89:9a:ab:bc:cd"),
                "type": EtherType.from_int(0x9999),
                "payload": b"\x00\x00\x00\x00",
                "__len__": 14 + 4,
                "__str__": "ETHER 78:89:9a:ab:bc:cd > 11:22:33:44:55:66, type 0x9999, len 18 (14+4)",
            },
        },
        {
            "_description": "Ethernet II frame with no payload (header-only, 14 bytes).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : 11:22:33:44:55:66
                #   Source MAC      : 78:89:9a:ab:bc:cd
                #   Ethertype       : 0x0800 (IPv4)
                #   Payload         : empty
                b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x08\x00"
            ),
            "_results": {
                "header": EthernetHeader(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("78:89:9a:ab:bc:cd"),
                    type=EtherType.IP4,
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("78:89:9a:ab:bc:cd"),
                "type": EtherType.IP4,
                "payload": b"",
                "__len__": 14,
                "__str__": "ETHER 78:89:9a:ab:bc:cd > 11:22:33:44:55:66, type IPv4, len 14 (14+0)",
            },
        },
    ]
)
class TestEthernetParserOperation(TestCase):
    """
    The Ethernet packet parser operation tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Parse the parameterized frame into a fresh PacketRx + parser pair.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._parser = EthernetParser(self._packet_rx)

    def test__ethernet__parser__header(self) -> None:
        """
        Ensure the parser exposes the expected EthernetHeader.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        self.assertEqual(
            self._parser.header,
            self._results["header"],
            msg=f"Unexpected header for case: {self._description}",
        )

    def test__ethernet__parser__dst_property(self) -> None:
        """
        Ensure the 'dst' property mirrors the header's destination MAC.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        self.assertEqual(
            self._parser.dst,
            self._results["dst"],
            msg=f"Unexpected 'dst' for case: {self._description}",
        )

    def test__ethernet__parser__src_property(self) -> None:
        """
        Ensure the 'src' property mirrors the header's source MAC.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        self.assertEqual(
            self._parser.src,
            self._results["src"],
            msg=f"Unexpected 'src' for case: {self._description}",
        )

    def test__ethernet__parser__type_property(self) -> None:
        """
        Ensure the 'type' property mirrors the header's EtherType.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        self.assertEqual(
            self._parser.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__ethernet__parser__len(self) -> None:
        """
        Ensure 'len()' on the parser equals header length plus payload length.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        self.assertEqual(
            len(self._parser),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ethernet__parser__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical Ethernet log line.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        self.assertEqual(
            str(self._parser),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ethernet__parser__repr_mentions_header_and_payload(self) -> None:
        """
        Ensure '__repr__()' mentions the class name and includes both the
        'header=' and 'payload=' anchors documented for every PyTCP assembler
        and parser base class.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        rendered = repr(self._parser)

        self.assertTrue(
            rendered.startswith("EthernetParser(header=EthernetHeader("),
            msg=f"Unexpected __repr__ prefix for case: {self._description} — got: {rendered!r}",
        )
        self.assertIn(
            "payload=",
            rendered,
            msg=f"__repr__ must include 'payload=' anchor for case: {self._description}",
        )

    def test__ethernet__parser__records_itself_on_packet_rx(self) -> None:
        """
        Ensure the parser assigns itself to PacketRx.ethernet so upper-layer
        parsers can locate the Ethernet header via the PacketRx.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        self.assertIs(
            self._packet_rx.ethernet,
            self._parser,
            msg=f"PacketRx.ethernet must reference the parser for case: {self._description}",
        )

    def test__ethernet__parser__advances_packet_rx_frame(self) -> None:
        """
        Ensure the parser advances PacketRx.frame past the 14-byte header so
        the next protocol parser sees only the payload.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
            msg=f"Unexpected advanced PacketRx.frame for case: {self._description}",
        )

    def test__ethernet__parser__buffer_protocol_returns_full_frame(self) -> None:
        """
        Ensure the parser exposes the complete on-wire frame (header +
        payload) through the buffer protocol.

        Reference: RFC 894 (Ethernet II frame parse — header + payload).
        """

        self.assertEqual(
            bytes(memoryview(self._parser)),
            self._frame_rx,
            msg=f"Unexpected buffer bytes for case: {self._description}",
        )
