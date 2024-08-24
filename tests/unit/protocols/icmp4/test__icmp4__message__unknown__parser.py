#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains tests for the ICMPv6 unknown message parser.

tests/unit/protocols/icmp4/test__icmp4__message__unknown__parser.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Code, Icmp4Type
from pytcp.protocols.icmp4.message.icmp4_message__unknown import (
    Icmp4UnknownMessage,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv4 unknown message, no data.",
            "_args": {
                "bytes": (
                    b"\xff\xff\x30\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
            },
            "_results": {
                "from_bytes": Icmp4UnknownMessage(
                    type=Icmp4Type.from_int(255),
                    code=Icmp4Code.from_int(255),
                    cksum=12345,
                    raw=b"0123456789ABCDEF",
                ),
            },
        },
    ]
)
class TestIcmp4MessageUnknownParser(TestCase):
    """
    The ICMPv4 unknown message parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp4__message__unknown__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv4 unknown message 'from_bytes()' method creates
        a proper message object.
        """

        self.assertEqual(
            Icmp4UnknownMessage.from_bytes(self._args["bytes"]),
            self._results["from_bytes"],
        )
