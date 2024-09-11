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
Module contains tests for the ICMPv4 unknown message assembler.


tests/pytcp/unit/protocols/icmp4/test__icmp4__unknown__assembler.py

ver 3.0.2
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Code, Icmp4Type
from pytcp.protocols.icmp4.message.icmp4_message__unknown import (
    Icmp4UnknownMessage,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv4 unknown message.",
            "_args": [],
            "_kwargs": {
                "type": Icmp4Type.from_int(255),
                "code": Icmp4Code.from_int(255),
                "raw": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 20,
                "__str__": (
                    "ICMPv4 Unknown Message, type 255, code 255, cksum 0, "
                    "len 20 (4+16)"
                ),
                "__repr__": (
                    "Icmp4UnknownMessage(type=<Icmp4Type.UNKNOWN_255: 255>, "
                    "code=<Icmp4Code.UNKNOWN_255: 255>, cksum=0, "
                    "raw=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
                "type": Icmp4Type.from_int(255),
                "code": Icmp4Code.from_int(255),
                "cksum": 0,
                "raw": b"0123456789ABCDEF",
            },
        },
    ]
)
class TestIcmp4UnknownAssembler(TestCase):
    """
    The ICMPv4 unknown message assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv4 unknown message assembler object with testcase
        arguments.
        """

        self._icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4UnknownMessage(*self._args, **self._kwargs)
        )

    def test__icmp4__unknown__assembler__len(self) -> None:
        """
        Ensure the ICMPv4 unknown message '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._icmp4__assembler),
            self._results["__len__"],
        )

    def test__icmp4__unknown__assembler__str(self) -> None:
        """
        Ensure the ICMPv4 unknown message '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._icmp4__assembler),
            self._results["__str__"],
        )

    def test__icmp4__unknown__assembler__repr(self) -> None:
        """
        Ensure the ICMPv4 unknown message '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._icmp4__assembler),
            self._results["__repr__"],
        )

    def test__icmp4__unknown__assembler__bytes(self) -> None:
        """
        Ensure the ICMPv4 unknown message '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._icmp4__assembler),
            self._results["__bytes__"],
        )

    def test__icmp4__unknown__assembler__type(self) -> None:
        """
        Ensure the ICMPv4 unknown message 'type' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__assembler.message.type,
            self._results["type"],
        )

    def test__icmp4__unknown__assembler__code(self) -> None:
        """
        Ensure the ICMPv4 unknown message 'code' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__assembler.message.code,
            self._results["code"],
        )

    def test__icmp4__unknown__assembler__cksum(self) -> None:
        """
        Ensure the ICMPv4 unknown message 'cksum' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__assembler.message.cksum,
            self._results["cksum"],
        )

    def test__icmp4__unknown__assembler__raw(self) -> None:
        """
        Ensure the ICMPv4 unknown message 'raw' field contains
        a correct value.
        """

        self.assertEqual(
            cast(Icmp4UnknownMessage, self._icmp4__assembler.message).raw,
            self._results["raw"],
        )
