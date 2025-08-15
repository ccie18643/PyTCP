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
This module contains tests for the UDP packet parser operation.

tests/pytcp/unit/protocols/udp/test__udp__parser__operation.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet_rx import PacketRx
from pytcp.protocols.udp.udp__header import UdpHeader
from pytcp.protocols.udp.udp__parser import UdpParser
from tests.pytcp.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4
from tests.pytcp.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6

testcases = [
    {
        "_description": "UDP packet with the empty payload.",
        "_args": [b"\xff\xff\xff\xff\x00\x08\xff\xf7"],
        "_kwargs": {},
        "_mocked_values": {},
        "_results": {
            "header": UdpHeader(
                sport=65535,
                dport=65535,
                plen=8,
                cksum=65527,
            ),
            "payload": b"",
        },
    },
    {
        "_description": "UDP packet with the non-empty payload.",
        "_args": [
            b"\x30\x39\xd4\x31\x00\x18\x2c\xa6\x30\x31\x32\x33\x34\x35\x36\x37"
            b"\x38\x39\x41\x42\x43\x44\x45\x46"
        ],
        "_kwargs": {},
        "_mocked_values": {},
        "_results": {
            "header": UdpHeader(
                sport=12345,
                dport=54321,
                plen=24,
                cksum=11430,
            ),
            "payload": b"0123456789ABCDEF",
        },
    },
    {
        "_description": "UDP packet with the maximum length payload.",
        "_args": [b"\x2b\x67\x56\xce\xff\xff\xb3\x57" + b"X" * 65527],
        "_kwargs": {},
        "_mocked_values": {},
        "_results": {
            "header": UdpHeader(
                sport=11111,
                dport=22222,
                plen=65535,
                cksum=45911,
            ),
            "payload": b"X" * 65527,
        },
    },
    {
        "_description": "UDP packet with the 'cksum' field set to '0' (valid state).",
        "_args": [b"\x30\x39\xd4\x31\x00\x08\x00\x00"],
        "_kwargs": {},
        "_mocked_values": {},
        "_results": {
            "header": UdpHeader(
                sport=12345,
                dport=54321,
                plen=8,
                cksum=0,
            ),
            "payload": b"",
        },
    },
]


@parameterized_class(testcases)
class TestUdpParserOperation__Ip4(TestCasePacketRxIp4):
    """
    The UDP packet parser operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__udp__parser__from_bytes(self) -> None:
        """
        Ensure the UDP packet parser creates the proper header and payload
        objects and also updates the appropriate 'tx_packet' object fields.
        """

        udp_parser = UdpParser(self._packet_rx)

        self.assertEqual(
            udp_parser.header,
            self._results["header"],
        )

        self.assertEqual(
            udp_parser.payload,
            self._results["payload"],
        )

        self.assertIs(
            self._packet_rx.udp,
            udp_parser,
        )

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
        )


@parameterized_class(testcases)
class TestUdpParserOperation__Ip6(TestCasePacketRxIp6):
    """
    The UDP packet parser operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__udp__parser__from_bytes(self) -> None:
        """
        Ensure the UDP packet parser creates the proper header and payload
        objects and also updates the appropriate 'tx_packet' object fields.
        """

        udp_parser = UdpParser(self._packet_rx)

        self.assertEqual(
            udp_parser.header,
            self._results["header"],
        )

        self.assertEqual(
            udp_parser.payload,
            self._results["payload"],
        )

        self.assertIs(
            self._packet_rx.udp,
            udp_parser,
        )

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
        )
