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
This module contains tests for the Ethernet 802.3 packet parser operation.

The parser consumes a PacketRx object, validates the frame, parses the
14-byte IEEE 802.3 header and advances PacketRx.frame past the header so
that upper-layer parsers can pick up the LLC payload transparently.

net_proto/tests/unit/protocols/ethernet_802_3/test__ethernet_802_3__parser__operation.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import MacAddress
from net_proto import (
    ETHERNET_802_3__HEADER__LEN,
    ETHERNET_802_3__PACKET__MAX_LEN,
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Header,
    Ethernet8023IntegrityError,
    Ethernet8023Parser,
    PacketRx,
)


@parameterized_class(
    [
        {
            "_description": "Ethernet 802.3 frame with a 16-byte LLC payload.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : 11:22:33:44:55:66
                #   Source MAC      : 78:89:9a:ab:bc:cd
                #   Length          : 0x0010 (16 bytes)
                #   Payload         : b"0123456789ABCDEF" (16 bytes)
                b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x00\x10"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "header": Ethernet8023Header(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("78:89:9a:ab:bc:cd"),
                    dlen=16,
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("78:89:9a:ab:bc:cd"),
                "dlen": 16,
                "payload": b"0123456789ABCDEF",
                "__len__": ETHERNET_802_3__HEADER__LEN + 16,
                "__str__": "ETHER_802.3 78:89:9a:ab:bc:cd > 11:22:33:44:55:66, dlen 16, len 30 (14+16)",
            },
        },
        {
            "_description": "Ethernet 802.3 frame at MTU (1500-byte payload, 1514-byte total).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 12:13:14:15:16:17
                #   Length          : 0x05dc (1500 bytes == maximum)
                #   Payload         : b"X" * 1500
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x05\xdc"
                + b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN
            ),
            "_results": {
                "header": Ethernet8023Header(
                    dst=MacAddress("a1:b2:c3:d4:e5:f6"),
                    src=MacAddress("12:13:14:15:16:17"),
                    dlen=ETHERNET_802_3__PAYLOAD__MAX_LEN,
                ),
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("12:13:14:15:16:17"),
                "dlen": ETHERNET_802_3__PAYLOAD__MAX_LEN,
                "payload": b"X" * ETHERNET_802_3__PAYLOAD__MAX_LEN,
                "__len__": ETHERNET_802_3__PACKET__MAX_LEN,
                "__str__": (
                    "ETHER_802.3 12:13:14:15:16:17 > a1:b2:c3:d4:e5:f6, "
                    f"dlen {ETHERNET_802_3__PAYLOAD__MAX_LEN}, "
                    f"len {ETHERNET_802_3__PACKET__MAX_LEN} "
                    f"({ETHERNET_802_3__HEADER__LEN}+{ETHERNET_802_3__PAYLOAD__MAX_LEN})"
                ),
            },
        },
        {
            "_description": "Ethernet 802.3 frame with an empty payload (header-only, 14 bytes).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : 11:22:33:44:55:66
                #   Source MAC      : 78:89:9a:ab:bc:cd
                #   Length          : 0x0000 (empty payload)
                #   Frame length    : 14 bytes
                b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x00\x00"
            ),
            "_results": {
                "header": Ethernet8023Header(
                    dst=MacAddress("11:22:33:44:55:66"),
                    src=MacAddress("78:89:9a:ab:bc:cd"),
                    dlen=0,
                ),
                "dst": MacAddress("11:22:33:44:55:66"),
                "src": MacAddress("78:89:9a:ab:bc:cd"),
                "dlen": 0,
                "payload": b"",
                "__len__": ETHERNET_802_3__HEADER__LEN,
                "__str__": "ETHER_802.3 78:89:9a:ab:bc:cd > 11:22:33:44:55:66, dlen 0, len 14 (14+0)",
            },
        },
        {
            "_description": "Ethernet 802.3 frame destined to the broadcast MAC address.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 00:11:22:33:44:55
                #   Length          : 0x0002 (2 bytes)
                #   Payload         : 2 opaque bytes
                b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x00\x02"
                b"\xca\xfe"
            ),
            "_results": {
                "header": Ethernet8023Header(
                    dst=MacAddress("ff:ff:ff:ff:ff:ff"),
                    src=MacAddress("00:11:22:33:44:55"),
                    dlen=2,
                ),
                "dst": MacAddress("ff:ff:ff:ff:ff:ff"),
                "src": MacAddress("00:11:22:33:44:55"),
                "dlen": 2,
                "payload": b"\xca\xfe",
                "__len__": ETHERNET_802_3__HEADER__LEN + 2,
                "__str__": "ETHER_802.3 00:11:22:33:44:55 > ff:ff:ff:ff:ff:ff, dlen 2, len 16 (14+2)",
            },
        },
    ]
)
class TestEthernet8023ParserOperation(TestCase):
    """
    The Ethernet 802.3 packet parser operation tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Parse the parameterized frame into a fresh PacketRx + parser pair.
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._parser = Ethernet8023Parser(self._packet_rx)

    def test__ethernet_802_3__parser__header(self) -> None:
        """
        Ensure the parser exposes the expected Ethernet8023Header.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertEqual(
            self._parser.header,
            self._results["header"],
            msg=f"Unexpected header for case: {self._description}",
        )

    def test__ethernet_802_3__parser__dst_property(self) -> None:
        """
        Ensure the 'dst' property mirrors the header's destination MAC.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertEqual(
            self._parser.dst,
            self._results["dst"],
            msg=f"Unexpected 'dst' for case: {self._description}",
        )

    def test__ethernet_802_3__parser__src_property(self) -> None:
        """
        Ensure the 'src' property mirrors the header's source MAC.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertEqual(
            self._parser.src,
            self._results["src"],
            msg=f"Unexpected 'src' for case: {self._description}",
        )

    def test__ethernet_802_3__parser__dlen_property(self) -> None:
        """
        Ensure the 'dlen' property mirrors the header's declared length.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertEqual(
            self._parser.dlen,
            self._results["dlen"],
            msg=f"Unexpected 'dlen' for case: {self._description}",
        )

    def test__ethernet_802_3__parser__len(self) -> None:
        """
        Ensure 'len()' on the parser equals header length plus payload length.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertEqual(
            len(self._parser),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ethernet_802_3__parser__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical Ethernet 802.3 log line.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertEqual(
            str(self._parser),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ethernet_802_3__parser__repr_mentions_header_and_payload(self) -> None:
        """
        Ensure '__repr__()' starts with the class name and includes both the
        'header=' and 'payload=' anchors documented for every PyTCP
        assembler and parser base class.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        rendered = repr(self._parser)

        self.assertTrue(
            rendered.startswith("Ethernet8023Parser(header=Ethernet8023Header("),
            msg=(f"Unexpected __repr__ prefix for case: " f"{self._description} — got: {rendered!r}"),
        )
        self.assertIn(
            "payload=",
            rendered,
            msg=f"__repr__ must include 'payload=' anchor for case: {self._description}",
        )

    def test__ethernet_802_3__parser__records_itself_on_packet_rx(self) -> None:
        """
        Ensure the parser assigns itself to PacketRx.ethernet_802_3 so
        upper-layer parsers can locate the 802.3 header via the PacketRx.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertIs(
            self._packet_rx.ethernet_802_3,
            self._parser,
            msg=f"PacketRx.ethernet_802_3 must reference the parser for case: {self._description}",
        )

    def test__ethernet_802_3__parser__advances_packet_rx_frame(self) -> None:
        """
        Ensure the parser advances PacketRx.frame past the 14-byte header so
        the next protocol parser sees only the payload.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
            msg=f"Unexpected advanced PacketRx.frame for case: {self._description}",
        )

    def test__ethernet_802_3__parser__buffer_protocol_returns_full_frame(self) -> None:
        """
        Ensure the parser exposes the complete on-wire frame (header +
        payload) through the buffer protocol.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertEqual(
            bytes(memoryview(self._parser)),
            self._frame_rx,
            msg=f"Unexpected buffer bytes for case: {self._description}",
        )

    def test__ethernet_802_3__parser__frame_property_returns_header_slice(self) -> None:
        """
        Ensure the parser's own 'frame' property returns the bytes captured
        before PacketRx.frame was advanced — the full on-wire frame.

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        self.assertEqual(
            bytes(self._parser.frame),
            self._frame_rx,
            msg=f"Unexpected parser.frame bytes for case: {self._description}",
        )


class TestEthernet8023ParserTrailingBytes(TestCase):
    """
    The Ethernet 802.3 parser payload-slice boundary tests.
    """

    def test__ethernet_802_3__parser__rejects_frame_with_trailing_bytes(self) -> None:
        """
        Ensure the parser rejects frames whose actual payload length does
        not match the declared 'dlen' field (the 802.3 header is strict
        about declared-vs-actual length, so trailing bytes past dlen are
        a hard integrity error rather than silently ignored).

        Reference: IEEE 802.3 §3 (802.3 frame parse — header + payload).
        """

        frame_with_trailing = (
            # Ethernet 802.3
            #   Destination MAC : 11:22:33:44:55:66
            #   Source MAC      : 78:89:9a:ab:bc:cd
            #   Length          : 0x0004 (4 bytes declared)
            #   Payload bytes   : 6 (4 payload + 2 trailing)
            b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x00\x04"
            b"\xde\xad\xbe\xef\x00\x00"
        )

        with self.assertRaises(Ethernet8023IntegrityError):
            Ethernet8023Parser(PacketRx(frame_with_trailing))
