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
Module contains tests for the ICMPv6 unknown message assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__unknown__assembler.py

ver 3.0.4
"""


from typing import Any, cast

from net_proto import (
    Icmp6Assembler,
    Icmp6Code,
    Icmp6Type,
    Icmp6UnknownMessage,
)
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase


@parameterized_class(
    [
        {
            "_description": "ICMPv6 unknown message.",
            "_args": [],
            "_kwargs": {
                "type": Icmp6Type.from_int(255),
                "code": Icmp6Code.from_int(255),
                "raw": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 20,
                "__str__": (
                    "ICMPv6 Unknown Message, type 255, code 255, cksum 0, "
                    "len 20 (4+16)"
                ),
                "__repr__": (
                    "Icmp6UnknownMessage(type=<Icmp6Type.UNKNOWN_255: 255>, "
                    "code=<Icmp6Code.UNKNOWN_255: 255>, cksum=0, "
                    "raw=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                    b"\x43\x44\x45\x46"
                ),
                "type": Icmp6Type.from_int(255),
                "code": Icmp6Code.from_int(255),
                "cksum": 0,
                "raw": b"0123456789ABCDEF",
            },
        },
    ]
)
class TestIcmp6UnknownAssembler(TestCase):
    """
    The ICMPv6 unknown message assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv6 unknown message assembler object with testcase
        arguments.
        """

        self._icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6UnknownMessage(*self._args, **self._kwargs)
        )

    def test__icmp6__unknown__assembler__len(self) -> None:
        """
        Ensure the ICMPv6 unknown message '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
        )

    def test__icmp6__unknown__assembler__str(self) -> None:
        """
        Ensure the ICMPv6 unknown message '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
        )

    def test__icmp6__unknown__assembler__repr(self) -> None:
        """
        Ensure the ICMPv6 unknown message '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
        )

    def test__icmp6__unknown__assembler__bytes(self) -> None:
        """
        Ensure the ICMPv6 unknown message '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
        )

    def test__icmp6__unknown__assembler__type(self) -> None:
        """
        Ensure the ICMPv6 unknown message 'type' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
        )

    def test__icmp6__unknown__assembler__code(self) -> None:
        """
        Ensure the ICMPv6 unknown message 'code' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
        )

    def test__icmp6__unknown__assembler__cksum(self) -> None:
        """
        Ensure the ICMPv6 unknown message 'cksum' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
        )

    def test__icmp6__unknown__assembler__raw(self) -> None:
        """
        Ensure the ICMPv6 unknown message 'raw' field contains
        a correct value.
        """

        self.assertEqual(
            cast(Icmp6UnknownMessage, self._icmp6__assembler.message).raw,
            self._results["raw"],
        )
