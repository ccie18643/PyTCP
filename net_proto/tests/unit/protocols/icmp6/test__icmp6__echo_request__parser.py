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
Module contains tests for the ICMPv6 Echo Request message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__echo_request__parser.py

ver 3.0.4
"""


from typing import Any, cast

from net_proto import (
    Icmp6EchoReplyMessage,
    Icmp6EchoRequestMessage,
    Icmp6Parser,
    PacketRx,
)
from net_proto.tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6
from parameterized import parameterized_class  # type: ignore


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Echo Request message, empty data.",
            "_args": [b"\x80\x00\x7b\x94\x30\x39\xd4\x31"],
            "_mocked_values": {},
            "_results": {
                "message": Icmp6EchoRequestMessage(
                    cksum=31636,
                    id=12345,
                    seq=54321,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Echo Request message, non-empty data.",
            "_args": [
                b"\x80\x00\xac\xbd\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_mocked_values": {},
            "_results": {
                "message": Icmp6EchoRequestMessage(
                    cksum=44221,
                    id=12345,
                    seq=54321,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv6 Echo Request message, maximum length of data.",
            "_args": [b"\x80\x00\x33\x57\x2b\x67\x56\xce" + b"X" * 65527],
            "_mocked_values": {},
            "_results": {
                "message": Icmp6EchoRequestMessage(
                    cksum=13143,
                    id=11111,
                    seq=22222,
                    data=b"X" * 65527,
                ),
            },
        },
    ]
)
class TestIcmp6EchoRequestParser(TestCasePacketRxIp6):
    """
    The ICMPv6 Echo Request message parser tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__echo_request__parser__message(self) -> None:
        """
        Ensure the ICMPv6 Echo Request message 'message()' method
        creates a proper message object.
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        # Convert the 'data' field from memoryview to bytes so we can compare.
        object.__setattr__(
            icmp6_parser.message,
            "data",
            bytes(cast(Icmp6EchoReplyMessage, icmp6_parser.message).data),
        )

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
        )
