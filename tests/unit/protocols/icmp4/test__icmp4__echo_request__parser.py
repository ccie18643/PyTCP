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
Module contains tests for the ICMPv4 Echo Request message parser.

tests/unit/protocols/icmp4/test__icmp4__echo_request__parser.py

ver 3.0.2
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp4.icmp4__parser import Icmp4Parser
from pytcp.protocols.icmp4.message.icmp4_message__echo_request import (
    Icmp4EchoRequestMessage,
)
from tests.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Echo Request message, empty data.",
            "_args": [b"\x08\x00\xf3\x94\x30\x39\xd4\x31"],
            "_results": {
                "message": Icmp4EchoRequestMessage(
                    cksum=62356,
                    id=12345,
                    seq=54321,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Echo Request message, non-empty data.",
            "_args": [
                b"\x08\x00\x24\xbe\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_results": {
                "message": Icmp4EchoRequestMessage(
                    cksum=9406,
                    id=12345,
                    seq=54321,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMP4 Echo Request message, maximum length of data.",
            "_args": [b"\x08\x00\x1e\xcb\x2b\x67\x56\xce" + b"X" * 65507],
            "_results": {
                "message": Icmp4EchoRequestMessage(
                    cksum=7883,
                    id=11111,
                    seq=22222,
                    data=b"X" * 65507,
                ),
            },
        },
    ]
)
class TestIcmp4MessageEchoRequestParser(TestCasePacketRxIp4):
    """
    The ICMPv4 Echo Request message parser tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp4__message__echo_request__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv4 'Echo Request' message 'from_bytes()' method
        creates a proper message object.
        """

        icmp4_parser = Icmp4Parser(self._packet_rx)

        # Convert the 'data' field from memoryview to bytes so we can compare.
        object.__setattr__(
            icmp4_parser.message,
            "data",
            bytes(cast(Icmp4EchoRequestMessage, icmp4_parser.message).data),
        )

        self.assertEqual(
            icmp4_parser.message,
            self._results["message"],
        )
