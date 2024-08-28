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
Module contains tests for the ICMPv6 Destination Unreachable message parser.

tests/unit/protocols/icmp4/test__icmp6__destination_unreachable__parser.py

ver 3.0.2
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp6.icmp6__parser import Icmp6Parser
from pytcp.protocols.icmp6.message.icmp6_message__destination_unreachable import (
    Icmp6DestinationUnreachableCode,
    Icmp6DestinationUnreachableMessage,
)
from tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Destination Unreachable (No Route) message.",
            "_args": {
                "bytes": b"\x01\x00\xfe\xff\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.NO_ROUTE,
                    cksum=65279,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Prohibited) message.",
            "_args": {
                "bytes": b"\x01\x01\xfe\xfe\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PROHIBITED,
                    cksum=65278,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Scope) message.",
            "_args": {
                "bytes": b"\x01\x02\xfe\xfd\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.SCOPE,
                    cksum=65277,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Address) message.",
            "_args": {
                "bytes": b"\x01\x03\xfe\xfc\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.ADDRESS,
                    cksum=65276,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Port) message.",
            "_args": {
                "bytes": b"\x01\x04\xfe\xfb\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=65275,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Failed Policy) message.",
            "_args": {
                "bytes": b"\x01\x05\xfe\xfa\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.FAILED_POLICY,
                    cksum=65274,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Reject Route) message.",
            "_args": {
                "bytes": b"\x01\x06\xfe\xf9\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.REJECT_ROUTE,
                    cksum=65273,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Source Routing Header) message.",
            "_args": {
                "bytes": b"\x01\x07\xfe\xf8\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.SOURCE_ROUTING_HEADER,
                    cksum=65272,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message, non-empty payload.",
            "_args": {
                "bytes": (
                    b"\x01\x04\x30\x25\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=12325,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message, maximum length payload.",
            "_args": {
                "bytes": b"\x01\x04\x6a\x67\x00\x00\x00\x00" + b"X" * 1232,
            },
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=27239,
                    data=b"X" * 1232,
                ),
            },
        },
    ]
)
class TestIcmp6MessageDestinationUnreachableParser(TestCasePacketRxIp6):
    """
    The ICMPv6 Destination Unreachable message parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__message__destination_unreachable__parser__message(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 Destination Unreachable message 'message()'
        method creates a proper message object.
        """

        icmp6_parser = Icmp6Parser(packet_rx=self._packet_rx)

        # Convert the 'data' field from memoryview to bytes so we can compare.
        object.__setattr__(
            icmp6_parser.message,
            "data",
            bytes(
                cast(
                    Icmp6DestinationUnreachableMessage, icmp6_parser.message
                ).data
            ),
        )

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
        )
