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
Module contains tests for the ICMPv6 unknown message parser.

tests/unit/protocols/icmp6/test__icmp6__echo_request__parser.py

ver 3.0.2
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp6.icmp6__parser import Icmp6Parser
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Code, Icmp6Type
from pytcp.protocols.icmp6.message.icmp6_message__unknown import (
    Icmp6UnknownMessage,
)
from tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": "ICMPv6 unknown message.",
            "_args": [
                b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46"
            ],
            "_kwargs": {},
            "mocked_values": {},
            "_results": {
                "message": Icmp6UnknownMessage(
                    type=Icmp6Type.from_int(255),
                    code=Icmp6Code.from_int(255),
                    cksum=12585,
                    raw=b"0123456789ABCDEF",
                ),
            },
        },
    ]
)
class TestIcmp6UnknownParser(TestCasePacketRxIp6):
    """
    The ICMPv6 unknown message parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__unknown__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 unknown message 'from_bytes()' method creates
        a proper message object.
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        # Convert the 'raw' field from memoryview to bytes so we can compare.
        object.__setattr__(
            icmp6_parser.message,
            "raw",
            bytes(cast(Icmp6UnknownMessage, icmp6_parser.message).raw),
        )

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
        )
