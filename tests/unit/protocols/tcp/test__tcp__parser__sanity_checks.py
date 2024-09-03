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
Module contains tests for the TCP packet sanity checks.

tests/unit/protocols/tcp/test__tcp__parser__sanity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.tcp.tcp__errors import TcpSanityError
from pytcp.protocols.tcp.tcp__parser import TcpParser
from tests.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4
from tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6

testcases = [
    {
        "_description": "The value of the 'sport' field equals 0.",
        "_args": {
            "bytes": (
                b"\x00\x00\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x10\x2b\x67"
                b"\x0d\x97\x00\x00"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": "The 'sport' field must be greater than 0. Got: 0",
        },
    },
    {
        "_description": "The value of the 'dport' field equals 0.",
        "_args": {
            "bytes": (
                b"\x30\x39\x00\x00\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x10\x2b\x67"
                b"\xb1\x8f\x00\x00"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": "The 'dport' field must be greater than 0. Got: 0",
        },
    },
    {
        "_description": "The SYN and FIN flags are set simultaneously.",
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x13\x2b\x67"
                b"\xdd\x5a\x00\x00"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": "The 'flag_syn' and 'flag_fin' must not be set simultaneously.",
        },
    },
    {
        "_description": "The SYN and RST flags are set simultaneously.",
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x16\x2b\x67"
                b"\xdd\x57\x00\x00"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": "The 'flag_syn' and 'flag_rst' must not be set simultaneously.",
        },
    },
    {
        "_description": "The FIN and RST flags are set simultaneously.",
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x15\x2b\x67"
                b"\xdd\x58\x00\x00"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": "The 'flag_fin' and 'flag_rst' must not be set simultaneously.",
        },
    },
    {
        "_description": "The ACK flag must be set when FIN flag is set.",
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x50\x01\x2b\x67"
                b"\xdd\x6c\x00\x00"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": "The 'flag_ack' must be set when 'flag_fin' is set.",
        },
    },
]


@parameterized_class(testcases)
class TestTcpParserSanityChecks__Ip4(TestCasePacketRxIp4):
    """
    The TCP packet parser sanity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__tcp__parser__from_bytes(self) -> None:
        """
        Ensure the TCP packet parser raises sanity error on crazy packets.
        """

        with self.assertRaises(TcpSanityError) as error:
            TcpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][TCP] {self._results["error_message"]}",
        )


@parameterized_class(testcases)
class TestTcpParserSanityChecks__Ip6(TestCasePacketRxIp6):
    """
    The TCP packet parser sanity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__tcp__parser__from_bytes(self) -> None:
        """
        Ensure the TCP packet parser raises sanity error on crazy packets.
        """

        with self.assertRaises(TcpSanityError) as error:
            TcpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][TCP] {self._results["error_message"]}",
        )
