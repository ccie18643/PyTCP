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
Module contains tests for the ICMPv4 Destination Unreachable message parser.

tests/unit/protocols/icmp4/test__icmp4__destination_unreachable__parser.py

ver 3.0.2
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp4.icmp4__parser import Icmp4Parser
from pytcp.protocols.icmp4.message.icmp4_message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
    Icmp4DestinationUnreachableMessage,
)
from tests.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Destination Unreachable (Network) message.",
            "_args": {
                "bytes": b"\x03\x00\xfc\xff\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.NETWORK,
                    cksum=64767,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host) message.",
            "_args": {
                "bytes": b"\x03\x01\xfc\xfe\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST,
                    cksum=64766,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Protocol) message.",
            "_args": {
                "bytes": b"\x03\x02\xfc\xfd\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PROTOCOL,
                    cksum=64765,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Port) message.",
            "_args": {
                "bytes": b"\x03\x03\xfc\xfc\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=64764,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Fragmentation Needed) message.",
            "_args": {
                "bytes": b"\x03\x04\xf8\x4b\x00\x00\x04\xb0",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                    cksum=63563,
                    mtu=1200,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Source Route Failed) message.",
            "_args": {
                "bytes": b"\x03\x05\xfc\xfa\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.SOURCE_ROUTE_FAILED,
                    cksum=64762,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Network Unknown) message.",
            "_args": {
                "bytes": b"\x03\x06\xfc\xf9\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.NETWORK_UNKNOWN,
                    cksum=64761,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host Unknown) message.",
            "_args": {
                "bytes": b"\x03\x07\xfc\xf8\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST_UNKNOWN,
                    cksum=64760,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Source Host Isolated) message.",
            "_args": {
                "bytes": b"\x03\x08\xfc\xf7\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.SOURCE_HOST_ISOLATED,
                    cksum=64759,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Network Prohibited) message.",
            "_args": {
                "bytes": b"\x03\x09\xfc\xf6\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.NETWORK_PROHIBITED,
                    cksum=64758,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host Prohibited) message.",
            "_args": {
                "bytes": b"\x03\x0a\xfc\xf5\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST_PROHIBITED,
                    cksum=64757,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Network TOS) message.",
            "_args": {
                "bytes": b"\x03\x0b\xfc\xf4\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.NETWORK_TOS,
                    cksum=64756,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host TOS) message.",
            "_args": {
                "bytes": b"\x03\x0c\xfc\xf3\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST_TOS,
                    cksum=64755,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Communication Prohibited) message.",
            "_args": {
                "bytes": b"\x03\x0d\xfc\xf2\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.COMMUNICATION_PROHIBITED,
                    cksum=64754,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host Precedence) message.",
            "_args": {
                "bytes": b"\x03\x0e\xfc\xf1\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST_PRECEDENCE,
                    cksum=64753,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Precedence Cutoff) message.",
            "_args": {
                "bytes": b"\x03\x0f\xfc\xf0\x00\x00\x00\x00",
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PRECEDENCE_CUTOFF,
                    cksum=64752,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable message, non-empty payload.",
            "_args": {
                "bytes": (
                    b"\x03\x03\x2e\x26\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=11814,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable message, maximum length payload.",
            "_args": {
                "bytes": b"\x03\x03\x6e\x6e\x00\x00\x00\x00" + b"X" * 548,
            },
            "_results": {
                "message": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=28270,
                    data=b"X" * 548,
                ),
            },
        },
    ]
)
class TestIcmp4MessageDestinationUnreachableParser(TestCasePacketRxIp4):
    """
    The ICMPv4 Destination Unreachable message parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp4__message__destination_unreachable__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message 'from_bytes()'
        method creates a proper message object.
        """

        icmp4_parser = Icmp4Parser(self._packet_rx)

        # Convert the 'data' field from memoryview to bytes so we can compare.
        object.__setattr__(
            icmp4_parser.message,
            "data",
            bytes(
                cast(
                    Icmp4DestinationUnreachableMessage, icmp4_parser.message
                ).data
            ),
        )

        self.assertEqual(
            icmp4_parser.message,
            self._results["message"],
        )
