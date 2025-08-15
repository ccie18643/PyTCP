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

tests/pytcp/unit/protocols/icmp4/test__icmp4__unknown__parser.py

ver 3.0.2
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet_rx import PacketRx
from pytcp.protocols.icmp4.icmp4__parser import Icmp4Parser
from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Code, Icmp4Type
from pytcp.protocols.icmp4.message.icmp4_message__unknown import (
    Icmp4UnknownMessage,
)
from tests.pytcp.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4


@parameterized_class(
    [
        {
            "_description": "ICMPv4 unknown message.",
            "_args": [
                b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46"
            ],
            "_kwargs": {},
            "_results": {
                "message": Icmp4UnknownMessage(
                    type=Icmp4Type.from_int(255),
                    code=Icmp4Code.from_int(255),
                    cksum=12585,
                    raw=b"0123456789ABCDEF",
                ),
            },
        },
    ]
)
class TestIcmp4MessageUnknownParser(TestCasePacketRxIp4):
    """
    The ICMPv4 unknown message parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp4__message__unknown__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv4 unknown message 'from_bytes()' method creates
        a proper message object.
        """

        icmp4_parser = Icmp4Parser(self._packet_rx)

        # Convert the 'raw' field from memoryview to bytes so we can compare.
        object.__setattr__(
            icmp4_parser.message,
            "raw",
            bytes(cast(Icmp4UnknownMessage, icmp4_parser.message).raw),
        )

        self.assertEqual(
            icmp4_parser.message,
            self._results["message"],
        )
