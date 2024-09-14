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
Module contains tests for the IPv6 Frag protocol packet parsing functionality.

tests/pytcp/unit/protocols/ip6_frag/test__ip6_frag__parser__operation.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.enums import IpProto
from pytcp.protocols.ip6_frag.ip6_frag__header import Ip6FragHeader
from pytcp.protocols.ip6_frag.ip6_frag__parser import Ip6FragParser
from tests.pytcp.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": "IPv6 Frag packet (I)",
            "_args": [b"\xff\x00\x00\x00\x00\x00\x00\x00"],
            "_kwargs": {},
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
            "_description": "IPv6 Frag packet (II)",
            "_args": [
                b"\xff\x00\x0c\x89\xff\xff\xff\xff\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_kwargs": {},
            "_results": {
                "header": Ip6FragHeader(
                    next=IpProto.RAW,
                    offset=3208,
                    flag_mf=True,
                    id=4294967295,
                ),
                "payload": b"0123456789ABCDEF",
                "header_bytes": b"\xff\x00\x0c\x89\xff\xff\xff\xff",
                "payload_bytes": b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46",
                "packet_bytes": (
                    b"\xff\x00\x0c\x89\xff\xff\xff\xff\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
        },
        {
            "_description": "IPv6 Frag packet (III)",
            "_args": [b"\xff\x00\xff\xf8\x00\x76\xad\xf1" + b"X" * 1422],
            "_kwargs": {},
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
                "packet_bytes": (
                    b"\xff\x00\xff\xf8\x00\x76\xad\xf1" + b"X" * 1422
                ),
            },
        },
    ]
)
class TestIp6PacketParserOperation(TestCasePacketRxIp6):
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
        Ensure the IPv6 Frag packet parser creates the proper header and payload
        objects and also updates the appropriate 'tx_packet' object fields.
        """

        ip6_frag_parser = Ip6FragParser(self._packet_rx)

        self.assertEqual(
            ip6_frag_parser.header,
            self._results["header"],
        )

        self.assertEqual(
            ip6_frag_parser.header_bytes,
            self._results["header_bytes"],
        )

        self.assertEqual(
            ip6_frag_parser.payload_bytes,
            self._results["payload_bytes"],
        )

        self.assertIs(
            self._packet_rx.ip6_frag,
            ip6_frag_parser,
        )

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
        )
