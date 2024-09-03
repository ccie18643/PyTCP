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
This module contains tests for the TCP packet parser operation.

tests/unit/protocols/tcp/test__tcp__parser__operation.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.tcp.options.tcp_option__nop import TcpOptionNop
from pytcp.protocols.tcp.options.tcp_options import TcpOptions
from pytcp.protocols.tcp.tcp__header import TcpHeader
from pytcp.protocols.tcp.tcp__parser import TcpParser
from tests.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4
from tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6

testcases = [
    {
        "_description": "TCP packet with no payload and no options (I).",
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x07\x5b\xcd\x15\x3a\xde\x68\xb1\x51\xfa\x2b\x67"
                b"\xaf\x64\x56\xce"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "header": TcpHeader(
                sport=12345,
                dport=54321,
                seq=123456789,
                ack=987654321,
                hlen=20,
                flag_ns=True,
                flag_cwr=True,
                flag_ece=True,
                flag_urg=True,
                flag_ack=True,
                flag_psh=True,
                flag_rst=False,
                flag_syn=True,
                flag_fin=False,
                win=11111,
                cksum=44900,
                urg=22222,
            ),
            "options": TcpOptions(),
            "payload": b"",
        },
    },
    {
        "_description": "TCP packet with no payload and no options (II).",
        "_args": {
            "bytes": (
                b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x50\x11\x15\xb3"
                b"\x6e\xd5\x00\x00"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "header": TcpHeader(
                sport=1111,
                dport=2222,
                seq=3333,
                ack=4444,
                hlen=20,
                flag_ns=False,
                flag_cwr=False,
                flag_ece=False,
                flag_urg=False,
                flag_ack=True,
                flag_psh=False,
                flag_rst=False,
                flag_syn=False,
                flag_fin=True,
                win=5555,
                cksum=28373,
                urg=0,
            ),
            "options": TcpOptions(),
            "payload": b"",
        },
    },
    {
        "_description": "TCP packet with no payload and options.",
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x00\x00\x00\x00\x00\x00\x00\x70\x04\x2b\x67"
                b"\x5c\x25\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "header": TcpHeader(
                sport=12345,
                dport=54321,
                seq=0,
                ack=0,
                hlen=28,
                flag_ns=False,
                flag_cwr=False,
                flag_ece=False,
                flag_urg=False,
                flag_ack=False,
                flag_psh=False,
                flag_rst=True,
                flag_syn=False,
                flag_fin=False,
                win=11111,
                cksum=23589,
                urg=0,
            ),
            "options": TcpOptions(
                *([TcpOptionNop()] * 8),
            ),
            "payload": b"",
        },
    },
    {
        "_description": "TCP packet with payload and options, no flags.",
        "_args": {
            "bytes": (
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x60\x00\xff\xff"
                b"\xcf\x26\xff\xff\x01\x01\x01\x01\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "header": TcpHeader(
                sport=65535,
                dport=65535,
                seq=4294967295,
                ack=4294967295,
                hlen=24,
                flag_ns=False,
                flag_cwr=False,
                flag_ece=False,
                flag_urg=False,
                flag_ack=False,
                flag_psh=False,
                flag_rst=False,
                flag_syn=False,
                flag_fin=False,
                win=65535,
                cksum=53030,
                urg=65535,
            ),
            "options": TcpOptions(
                *([TcpOptionNop()] * 4),
            ),
            "payload": b"0123456789ABCDEF",
        },
    },
    {
        "_description": "TCP packet with maximum payload size and no options.",
        "_args": {
            "bytes": (
                b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x51\x58\x15\xb3"
                b"\xb5\x2d\x00\x00" + b"X" * 65515
            ),
        },
        "_mocked_values": {},
        "_results": {
            "header": TcpHeader(
                sport=1111,
                dport=2222,
                seq=3333,
                ack=4444,
                hlen=20,
                flag_ns=True,
                flag_cwr=False,
                flag_ece=True,
                flag_urg=False,
                flag_ack=True,
                flag_psh=True,
                flag_rst=False,
                flag_syn=False,
                flag_fin=False,
                win=5555,
                cksum=46381,
                urg=0,
            ),
            "options": TcpOptions(),
            "payload": b"X" * 65515,
        },
    },
    {
        "_description": "TCP packet with maximum payload size and maximum options.",
        "_args": {
            "bytes": (
                b"\x04\x57\x0d\x05\x00\x00\x15\xb3\x00\x00\x1e\x61\xf0\xb8\x00\x00"
                b"\xbd\x39\x27\x0f\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                + b"X" * 65475
            ),
        },
        "_mocked_values": {},
        "_results": {
            "header": TcpHeader(
                sport=1111,
                dport=3333,
                seq=5555,
                ack=7777,
                hlen=60,
                flag_ns=False,
                flag_cwr=True,
                flag_ece=False,
                flag_urg=True,
                flag_ack=True,
                flag_psh=True,
                flag_rst=False,
                flag_syn=False,
                flag_fin=False,
                win=0,
                cksum=48441,
                urg=9999,
            ),
            "options": TcpOptions(
                *([TcpOptionNop()] * 40),
            ),
            "payload": b"X" * 65475,
        },
    },
]


@parameterized_class(testcases)
class TestTcpParserOperation__Ip4(TestCasePacketRxIp4):
    """
    The TCP packet parser operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__tcp__parser__from_bytes(self) -> None:
        """
        Ensure the TCP packet parser creates the proper header, options
        and payload objects and also updates the appropriate 'tx_packet'
        object fields.
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            tcp_parser.header,
            self._results["header"],
        )

        self.assertEqual(
            tcp_parser.payload,
            self._results["payload"],
        )

        self.assertIs(
            self._packet_rx.tcp,
            tcp_parser,
        )

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
        )


@parameterized_class(testcases)
class TestTcpParserOperation__Ip6(TestCasePacketRxIp6):
    """
    The TCP packet parser operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__tcp__parser__from_bytes(self) -> None:
        """
        Ensure the TCP packet parser creates the proper header, options
        and payload objects and also updates the appropriate 'tx_packet'
        object fields.
        """

        tcp_parser = TcpParser(self._packet_rx)

        self.assertEqual(
            tcp_parser.header,
            self._results["header"],
        )

        self.assertEqual(
            tcp_parser.payload,
            self._results["payload"],
        )

        self.assertIs(
            self._packet_rx.tcp,
            tcp_parser,
        )

        self.assertEqual(
            bytes(self._packet_rx.frame),
            self._results["payload"],
        )
