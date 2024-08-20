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
This module contains tests for the ICMPv6 unknown message assembler.

tests/unit/protocols/icmp6/test__icmp6__message__unknown__packets.py

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
                "type": Icmp6Type.from_int(255),
                "code": Icmp6Code.from_int(255),
                "cksum": 12345,
            },
            "_results": {
                "__str__": "ICMPv6 Unknown Message, type 255, code 255",
                "__repr__": (
                    "Icmp6UnknownMessage(type=<Icmp6Type.UNKNOWN_255: 255>, "
                    "code=<Icmp6Code.UNKNOWN_255: 255>, cksum=12345)"
                ),
                "type": Icmp6Type.from_int(255),
                "code": Icmp6Code.from_int(255),
                "cksum": 12345,
            },
        },
    ]
)
class TestIcmp6MessageUnknownAssembler(TestCase):
    """
    The ICMPv6 unknown message assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv6 unknown message assembler object with testcase
        arguments.
        """

        self._icmp6__unknown__message = Icmp6UnknownMessage(**self._args)

    def test__icmp6__message__unknown__assembler__len(self) -> None:
        """
        Ensure the ICMPv6 unknown message '__len__()' method returns
        a correct value.
        """

        with self.assertRaises(NotImplementedError):
            len(self._icmp6__unknown__message)

    def test__icmp6__message__unknown__assembler__str(self) -> None:
        """
        Ensure the ICMPv6 unknown message '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._icmp6__unknown__message),
            self._results["__str__"],
        )

    def test__icmp6__message__unknown__assembler__repr(self) -> None:
        """
        Ensure the ICMPv6 unknown message '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._icmp6__unknown__message),
            self._results["__repr__"],
        )

    def test__icmp6__message__unknown__assembler__bytes(self) -> None:
        """
        Ensure the ICMPv6 unknown message '__bytes__()' method returns
        a correct value.
        """

        with self.assertRaises(NotImplementedError):
            bytes(self._icmp6__unknown__message)

    def test__icmp6__message__unknown__assembler__type(self) -> None:
        """
        Ensure the ICMPv6 unknown message 'type' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__unknown__message.type,
            self._results["type"],
        )

    def test__icmp6__message__unknown__assembler__code(self) -> None:
        """
        Ensure the ICMPv6 unknown message 'code' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__unknown__message.code,
            self._results["code"],
        )

    def test__icmp6__message__unknown__assembler__cksum(self) -> None:
        """
        Ensure the ICMPv6 unknown message 'cksum' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__unknown__message.cksum,
            self._results["cksum"],
        )
