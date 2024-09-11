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
Module contains tests for the ICMPv6 Echo Reply message assembler.

tests/pytcp/unit/protocols/icmp6/test__icmp6__echo_reply__assembler.py

ver 3.0.2
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.icmp6.icmp6__assembler import Icmp6Assembler
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Type
from pytcp.protocols.icmp6.message.icmp6_message__echo_reply import (
    Icmp6EchoReplyCode,
    Icmp6EchoReplyMessage,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Echo Reply message, empty data.",
            "_args": [],
            "_kwargs": {
                "id": 12345,
                "seq": 54321,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Echo Reply, id 12345, seq 54321, len 8 (8+0)",
                "__repr__": (
                    "Icmp6EchoReplyMessage(code=<Icmp6EchoReplyCode.DEFAULT: 0>, "
                    "cksum=0, id=12345, seq=54321, data=b'')"
                ),
                "__bytes__": b"\x81\x00\x7a\x94\x30\x39\xd4\x31",
                "type": Icmp6Type.ECHO_REPLY,
                "code": Icmp6EchoReplyCode.DEFAULT,
                "cksum": 0,
                "id": 12345,
                "seq": 54321,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv6 Echo Reply message, non-empty data.",
            "_args": [],
            "_kwargs": {
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "ICMPv6 Echo Reply, id 12345, seq 54321, len 24 (8+16)",
                "__repr__": (
                    "Icmp6EchoReplyMessage(code=<Icmp6EchoReplyCode.DEFAULT: 0>, "
                    "cksum=0, id=12345, seq=54321, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\x81\x00\xab\xbd\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Icmp6Type.ECHO_REPLY,
                "code": Icmp6EchoReplyCode.DEFAULT,
                "cksum": 0,
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "ICMPv6 Echo Reply message, maximum length of data.",
            "_args": [],
            "_kwargs": {
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65527,
            },
            "_results": {
                "__len__": 65535,
                "__str__": "ICMPv6 Echo Reply, id 11111, seq 22222, len 65535 (8+65527)",
                "__repr__": (
                    "Icmp6EchoReplyMessage(code=<Icmp6EchoReplyCode.DEFAULT: 0>, cksum=0, "
                    f"id=11111, seq=22222, data=b'{"X" * 65527}')"
                ),
                "__bytes__": b"\x81\x00\x32\x57\x2b\x67\x56\xce" + b"X" * 65527,
                "type": Icmp6Type.ECHO_REPLY,
                "code": Icmp6EchoReplyCode.DEFAULT,
                "cksum": 0,
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65527,
            },
        },
    ]
)
class TestIcmp6EchoReplyAssembler(TestCase):
    """
    The ICMPv6 Echo Reply message assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv6 Echo Reply message assembler object
        with testcase arguments.
        """

        self._icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6EchoReplyMessage(*self._args, **self._kwargs)
        )

    def test__icmp6__echo_reply__assembler__len(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
        )

    def test__icmp6__echo_reply__assembler__str(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
        )

    def test__icmp6__echo_reply__assembler__repr(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
        )

    def test__icmp6__echo_reply__assembler__bytes(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
        )

    def test__icmp6__echo_reply__assembler__type(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message 'type' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
        )

    def test__icmp6__echo_reply__assembler__code(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message 'code' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
        )

    def test__icmp6__echo_reply__assembler__cksum(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message 'cksum' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
        )

    def test__icmp6__echo_reply__assembler__id(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message 'id' field contains
        a correct value.
        """

        self.assertEqual(
            cast(Icmp6EchoReplyMessage, self._icmp6__assembler.message).id,
            self._results["id"],
        )

    def test__icmp6__echo_reply__assembler__seq(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message 'seq' field contains
        a correct value.
        """

        self.assertEqual(
            cast(Icmp6EchoReplyMessage, self._icmp6__assembler.message).seq,
            self._results["seq"],
        )

    def test__icmp6__echo_reply__assembler__data(self) -> None:
        """
        Ensure the ICMPv6 Echo Reply message 'data' field contains
        a correct value.
        """

        self.assertEqual(
            cast(Icmp6EchoReplyMessage, self._icmp6__assembler.message).data,
            self._results["data"],
        )
