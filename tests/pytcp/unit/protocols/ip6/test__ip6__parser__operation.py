#!/usr/bin/env python3

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

tests/pytcp/unit/protocols/ip6/test__ip6__parser__packet.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_addr import Ip6Address
from pytcp.lib.packet import PacketRx
from pytcp.protocols.enums import IpProto
from pytcp.protocols.ip6.ip6__header import Ip6Header
from pytcp.protocols.ip6.ip6__parser import Ip6Parser
from tests.pytcp.lib.testcase__packet_rx import TestCasePacketRx


@parameterized_class(
    [
        {
            "_description": "IPv6 packet (I)",
            "_args": [
                b"\x60\x00\x00\x00\x00\x00\xff\x01\x10\x01\x20\x02\x30\x03\x40\x04"
                b"\x50\x05\x60\x06\x70\x07\x80\x08\xa0\x0a\xb0\x0b\xc0\x0c\xd0\x0d"
                b"\xe0\x0e\xf0\x0f\x0a\x0a\x0b\x0b"
            ],
            "_kwargs": {},
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
            "_description": "IPv6 packet (II)",
            "_args": [
                b"\x69\xaf\xff\xff\x00\x10\xff\xff\x11\x11\x22\x22\x33\x33\x44\x44"
                b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                b"\x44\x44\x33\x33\x22\x22\x11\x11\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_kwargs": {},
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
                "payload_bytes": (
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "packet_bytes": (
                    b"\x69\xaf\xff\xff\x00\x10\xff\xff\x11\x11\x22\x22\x33\x33\x44\x44"
                    b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                    b"\x44\x44\x33\x33\x22\x22\x11\x11\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
        },
        {
            "_description": "IPv6 packet (III)",
            "_args": [
                b"\x6f\xf0\x00\x00\xff\xd7\xff\x80\x11\x11\x22\x22\x33\x33\x44\x44"
                b"\x55\x55\x66\x66\x77\x77\x88\x88\x88\x88\x77\x77\x66\x66\x55\x55"
                b"\x44\x44\x33\x33\x22\x22\x11\x11" + b"X" * 65495
            ],
            "_kwargs": {},
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
class TestIp6PacketParserOperation(TestCasePacketRx):
    """
    The IPv6 packet parser operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__ip6__header_parser__from_bytes(self) -> None:
        """
        Ensure the IPv6 packet parser creates the proper header and payload
        objects and also updates the appropriate 'tx_packet' object fields.
        """

        ip6_parser = Ip6Parser(self._packet_rx)

        self.assertEqual(
            ip6_parser.header,
            self._results["header"],
        )

        self.assertEqual(
            ip6_parser.header_bytes,
            self._results["header_bytes"],
        )

        self.assertEqual(
            ip6_parser.payload_bytes,
            self._results["payload_bytes"],
        )

        self.assertIs(
            self._packet_rx.ip6,
            ip6_parser,
        )

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
        )
