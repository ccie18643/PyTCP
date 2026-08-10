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
Module contains tests for the IPv6 Frag protocol packet parsing functionality.

net_proto/tests/unit/protocols/ip6_frag/test__ip6_frag__parser__operation.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import Any, override
from unittest import TestCase

from net_proto import Ip6FragHeader, Ip6FragParser, IpProto, PacketRx
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "IPv6 Frag header only (no payload, offset=0, flag_mf=False, id=0).",
            # IPv6 Frag wire frame (8 bytes, header only):
            #   Byte  0     : 0xff       -> next=IpProto.RAW (255)
            #   Byte  1     : 0x00       -> reserved (must be zero)
            #   Bytes 2-3   : 0x0000     -> offset=0, res=0, flag_mf=0
            #   Bytes 4-7   : 0x00000000 -> id=0
            "_frame_rx": b"\xff\x00\x00\x00\x00\x00\x00\x00",
            "_results": {
                "header": Ip6FragHeader(
                    next=IpProto.RAW,
                    offset=0,
                    flag_mf=False,
                    id=0,
                ),
                "payload": b"",
                "header_bytes": b"\xff\x00\x00\x00\x00\x00\x00\x00",
                "payload_bytes": b"",
                "packet_bytes": b"\xff\x00\x00\x00\x00\x00\x00\x00",
            },
        },
        {
            "_description": "IPv6 Frag with 16-byte ASCII payload, mid-range offset, MF set, max id.",
            # IPv6 Frag wire frame (24 bytes = 8-byte header + 16-byte payload):
            #   Byte  0     : 0xff       -> next=IpProto.RAW (255)
            #   Byte  1     : 0x00       -> reserved
            #   Bytes 2-3   : 0x0c89     -> offset=0x0c88=3208, res=0, flag_mf=1
            #                 (0x0c89 & 0xfff8 = 0x0c88; 0x0c89 & 0x0001 = 1)
            #   Bytes 4-7   : 0xffffffff -> id=4294967295 (UINT_32__MAX)
            #   Bytes 8-23  : b"0123456789ABCDEF" (ASCII payload)
            "_frame_rx": (
                b"\xff\x00\x0c\x89\xff\xff\xff\xff\x30\x31\x32\x33\x34\x35\x36\x37"
                + b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "header": Ip6FragHeader(
                    next=IpProto.RAW,
                    offset=3208,
                    flag_mf=True,
                    id=4294967295,
                ),
                "payload": b"0123456789ABCDEF",
                "header_bytes": b"\xff\x00\x0c\x89\xff\xff\xff\xff",
                "payload_bytes": b"0123456789ABCDEF",
                "packet_bytes": (
                    b"\xff\x00\x0c\x89\xff\xff\xff\xff\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
        },
        {
            "_description": "IPv6 Frag with 1422-byte payload at maximum offset (UINT_13__MAX).",
            # IPv6 Frag wire frame (1430 bytes = 8-byte header + 1422-byte payload):
            #   Byte  0     : 0xff       -> next=IpProto.RAW (255)
            #   Byte  1     : 0x00       -> reserved
            #   Bytes 2-3   : 0xfff8     -> offset=0xfff8=65528 (UINT_13__MAX),
            #                 res=0, flag_mf=0
            #   Bytes 4-7   : 0x0076adf1 -> id=7777777
            #   Bytes 8+    : 1422 bytes of 'X'
            "_frame_rx": b"\xff\x00\xff\xf8\x00\x76\xad\xf1" + b"X" * 1422,
            "_results": {
                "header": Ip6FragHeader(
                    next=IpProto.RAW,
                    offset=65528,
                    flag_mf=False,
                    id=7777777,
                ),
                "payload": b"X" * 1422,
                "header_bytes": b"\xff\x00\xff\xf8\x00\x76\xad\xf1",
                "payload_bytes": b"X" * 1422,
                "packet_bytes": b"\xff\x00\xff\xf8\x00\x76\xad\xf1" + b"X" * 1422,
            },
        },
        {
            "_description": "IPv6 Frag with last fragment marker cleared at offset=0 (reassembly start).",
            # IPv6 Frag wire frame (16 bytes = 8-byte header + 8-byte payload):
            #   Byte  0     : 0x06       -> next=IpProto.TCP (6)
            #   Byte  1     : 0x00       -> reserved
            #   Bytes 2-3   : 0x0001     -> offset=0, res=0, flag_mf=1
            #                 (first fragment of a multi-fragment datagram)
            #   Bytes 4-7   : 0xdeadbeef -> id=3735928559
            #   Bytes 8-15  : b"\x00" * 8 (placeholder TCP header bytes)
            "_frame_rx": b"\x06\x00\x00\x01\xde\xad\xbe\xef" + b"\x00" * 8,
            "_results": {
                "header": Ip6FragHeader(
                    next=IpProto.TCP,
                    offset=0,
                    flag_mf=True,
                    id=3735928559,
                ),
                "payload": b"\x00" * 8,
                "header_bytes": b"\x06\x00\x00\x01\xde\xad\xbe\xef",
                "payload_bytes": b"\x00" * 8,
                "packet_bytes": b"\x06\x00\x00\x01\xde\xad\xbe\xef" + b"\x00" * 8,
            },
        },
    ]
)
class TestIp6FragParserOperation(TestCase):
    """
    The IPv6 Frag packet parser operation tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx and stub the IPv6
        layer attribute the Frag parser reads (ip6.dlen).
        """

        self._packet_rx = PacketRx(self._frame_rx)
        self._packet_rx.ip6 = SimpleNamespace(  # type: ignore[assignment]
            dlen=len(self._frame_rx),
        )

    def test__ip6_frag__parser__header(self) -> None:
        """
        Ensure the parser exposes the expected Ip6FragHeader object.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            parser.header,
            self._results["header"],
            msg=f"Unexpected parsed header for case: {self._description}",
        )

    def test__ip6_frag__parser__next(self) -> None:
        """
        Ensure the 'next' property returns the parsed next-header IpProto.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            parser.next,
            self._results["header"].next,
            msg=f"Unexpected 'next' for case: {self._description}",
        )

    def test__ip6_frag__parser__offset(self) -> None:
        """
        Ensure the 'offset' property returns the 13-bit upper portion
        of the offset|flag_mf wire field.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            parser.offset,
            self._results["header"].offset,
            msg=f"Unexpected 'offset' for case: {self._description}",
        )

    def test__ip6_frag__parser__flag_mf(self) -> None:
        """
        Ensure the 'flag_mf' property returns bit 0 of the
        offset|flag_mf wire field as a bool.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            parser.flag_mf,
            self._results["header"].flag_mf,
            msg=f"Unexpected 'flag_mf' for case: {self._description}",
        )

    def test__ip6_frag__parser__id(self) -> None:
        """
        Ensure the 'id' property returns the parsed 32-bit datagram id.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            parser.id,
            self._results["header"].id,
            msg=f"Unexpected 'id' for case: {self._description}",
        )

    def test__ip6_frag__parser__payload(self) -> None:
        """
        Ensure the 'payload' property returns the bytes following the
        fixed 8-byte header.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            bytes(parser.payload),
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__ip6_frag__parser__header_bytes(self) -> None:
        """
        Ensure 'header_bytes' returns the first IP6_FRAG__HEADER__LEN
        bytes of the frame.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            bytes(parser.header_bytes),
            self._results["header_bytes"],
            msg=f"Unexpected 'header_bytes' for case: {self._description}",
        )

    def test__ip6_frag__parser__payload_bytes(self) -> None:
        """
        Ensure 'payload_bytes' returns the post-header payload region.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            bytes(parser.payload_bytes),
            self._results["payload_bytes"],
            msg=f"Unexpected 'payload_bytes' for case: {self._description}",
        )

    def test__ip6_frag__parser__packet_bytes(self) -> None:
        """
        Ensure 'packet_bytes' returns the full header + payload span.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            bytes(parser.packet_bytes),
            self._results["packet_bytes"],
            msg=f"Unexpected 'packet_bytes' for case: {self._description}",
        )

    def test__ip6_frag__parser__packet_rx_ip6_frag_backref(self) -> None:
        """
        Ensure the parser stores itself on the PacketRx as 'ip6_frag'
        so downstream handlers can look it up.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        parser = Ip6FragParser(self._packet_rx)

        self.assertIs(
            self._packet_rx.ip6_frag,
            parser,
            msg=f"PacketRx.ip6_frag must reference the parser for case: {self._description}",
        )

    def test__ip6_frag__parser__packet_rx_frame_advanced_to_payload(self) -> None:
        """
        Ensure the parser advances 'PacketRx.frame' past the IPv6 Frag
        header to the payload bytes so the next-layer parser sees only
        what it is supposed to consume.

        Reference: RFC 8200 §4.5 (Fragment header parse).
        """

        Ip6FragParser(self._packet_rx)

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
            msg=f"PacketRx.frame must be advanced to payload for case: {self._description}",
        )
