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

tests/unit/protocols/icmp4/test__icmp4__message__destination_unreachable__parser.py

ver 3.0.1
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.icmp4.message.icmp4_message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
    Icmp4DestinationUnreachableMessage,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Destination Unreachable (Network) message.",
            "_args": {
                "bytes": b"\x03\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.NETWORK,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host) message.",
            "_args": {
                "bytes": b"\x03\x01\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Protocol) message.",
            "_args": {
                "bytes": b"\x03\x02\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PROTOCOL,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Port) message.",
            "_args": {
                "bytes": b"\x03\x03\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Fragmentation Needed) message.",
            "_args": {
                "bytes": b"\x03\x04\x00\x00\x00\x00\x04\xb0",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                    cksum=0,
                    mtu=1200,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Source Route Failed) message.",
            "_args": {
                "bytes": b"\x03\x05\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.SOURCE_ROUTE_FAILED,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Network Unknown) message.",
            "_args": {
                "bytes": b"\x03\x06\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.NETWORK_UNKNOWN,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host Unknown) message.",
            "_args": {
                "bytes": b"\x03\x07\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST_UNKNOWN,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Source Host Isolated) message.",
            "_args": {
                "bytes": b"\x03\x08\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.SOURCE_HOST_ISOLATED,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Network Prohibited) message.",
            "_args": {
                "bytes": b"\x03\x09\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.NETWORK_PROHIBITED,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host Prohibited) message.",
            "_args": {
                "bytes": b"\x03\x0a\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST_PROHIBITED,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Network TOS) message.",
            "_args": {
                "bytes": b"\x03\x0b\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.NETWORK_TOS,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host TOS) message.",
            "_args": {
                "bytes": b"\x03\x0c\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST_TOS,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Communication Prohibited) message.",
            "_args": {
                "bytes": b"\x03\x0d\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.COMMUNICATION_PROHIBITED,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host Precedence) message.",
            "_args": {
                "bytes": b"\x03\x0e\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.HOST_PRECEDENCE,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Precedence Cutoff) message.",
            "_args": {
                "bytes": b"\x03\x0f\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PRECEDENCE_CUTOFF,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable message, non-empty payload.",
            "_args": {
                "bytes": (
                    b"\x03\x03\x00\x00\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=0,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable message, maximum length payload.",
            "_args": {
                "bytes": b"\x03\x03\x00\x00\x00\x00\x00\x00" + b"X" * 548,
            },
            "_results": {
                "from_bytes": Icmp4DestinationUnreachableMessage(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=0,
                    data=b"X" * 548,
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable message, incorrect 'type' field.",
            "_args": {
                "bytes": b"\xff\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "error": (
                    "The 'type' field must be <Icmp4Type.DESTINATION_UNREACHABLE: 3>. "
                    "Got: <Icmp4Type.UNKNOWN_255: 255>"
                ),
            },
        },
    ]
)
class TestIcmp4MessageDestinationUnreachableParser(TestCase):
    """
    The ICMPv4 Destination Unreachable message parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp4__message__destination_unreachable__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message 'from_bytes()'
        method creates a proper message object.
        """

        if "error" in self._results:
            with self.assertRaises(AssertionError) as error:
                Icmp4DestinationUnreachableMessage.from_bytes(
                    self._args["bytes"]
                )

            self.assertEqual(
                str(error.exception),
                self._results["error"],
            )

        if "from_bytes" in self._results:
            self.assertEqual(
                Icmp4DestinationUnreachableMessage.from_bytes(
                    self._args["bytes"]
                ),
                self._results["from_bytes"],
            )
