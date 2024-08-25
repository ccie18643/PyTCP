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

tests/unit/protocols/icmp4/test__icmp6__message__destination_unreachable__parser.py

ver 3.0.1
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.icmp6.message.icmp6_message__destination_unreachable import (
    Icmp6DestinationUnreachableCode,
    Icmp6DestinationUnreachableMessage,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Destination Unreachable (No Route) message.",
            "_args": {
                "bytes": b"\x01\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.NO_ROUTE,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Prohibited) message.",
            "_args": {
                "bytes": b"\x01\x01\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PROHIBITED,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Scope) message.",
            "_args": {
                "bytes": b"\x01\x02\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.SCOPE,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Address) message.",
            "_args": {
                "bytes": b"\x01\x03\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.ADDRESS,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Port) message.",
            "_args": {
                "bytes": b"\x01\x04\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Failed Policy) message.",
            "_args": {
                "bytes": b"\x01\x05\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.FAILED_POLICY,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Reject Route) message.",
            "_args": {
                "bytes": b"\x01\x06\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.REJECT_ROUTE,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Source Routing Header) message.",
            "_args": {
                "bytes": b"\x01\x07\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.SOURCE_ROUTING_HEADER,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message, non-empty payload.",
            "_args": {
                "bytes": (
                    b"\x01\x04\x00\x00\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=0,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message, maximum length payload.",
            "_args": {
                "bytes": b"\x01\x04\x00\x00\x00\x00\x00\x00" + b"X" * 1232,
            },
            "_results": {
                "from_bytes": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=0,
                    data=b"X" * 1232,
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message, incorrect 'type' field.",
            "_args": {
                "bytes": b"\xff\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "error": (
                    "The 'type' field must be <Icmp6Type.DESTINATION_UNREACHABLE: 1>. "
                    "Got: <Icmp6Type.UNKNOWN_255: 255>"
                ),
            },
        },
    ]
)
class TestIcmp6MessageDestinationUnreachableParser(TestCase):
    """
    The ICMPv6 Destination Unreachable message parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__message__destination_unreachable__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 Destination Unreachable message 'from_bytes()' method
        creates a proper message object.
        """

        if "error" in self._results:
            with self.assertRaises(AssertionError) as error:
                Icmp6DestinationUnreachableMessage.from_bytes(
                    self._args["bytes"]
                )

            self.assertEqual(
                str(error.exception),
                self._results["error"],
            )

        if "from_bytes" in self._results:
            self.assertEqual(
                Icmp6DestinationUnreachableMessage.from_bytes(
                    self._args["bytes"]
                ),
                self._results["from_bytes"],
            )
