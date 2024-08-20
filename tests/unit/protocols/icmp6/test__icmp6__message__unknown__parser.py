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

tests/unit/protocols/icmp6/test__icmp6__message__echo_request__parser.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Code, Icmp6Type
from pytcp.protocols.icmp6.message.icmp6_message__unknown import (
    Icmp6UnknownMessage,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv6 unknown message, empty data.",
            "_args": {
                "bytes": b"\xff\xff\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "from_bytes": Icmp6UnknownMessage(
                    type=Icmp6Type.from_int(255),
                    code=Icmp6Code.from_int(255),
                    cksum=0,
                ),
            },
        },
    ]
)
class TestIcmp6MessageUnknownParser(TestCase):
    """
    The ICMPv6 unknown message parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__message__unknown__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 unknown message 'from_bytes()' method creates
        a proper message object.
        """

        self.assertEqual(
            Icmp6UnknownMessage.from_bytes(self._args["bytes"]),
            self._results["from_bytes"],
        )
