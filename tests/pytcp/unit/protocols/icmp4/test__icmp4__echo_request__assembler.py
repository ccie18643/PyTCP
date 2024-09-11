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
Module contains tests for the ICMPv4 Echo Request message assembler.

tests/pytcp/unit/protocols/icmp4/test__icmp4__echo_request__packets.py

ver 3.0.2
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Type
from pytcp.protocols.icmp4.message.icmp4_message__echo_request import (
    Icmp4EchoRequestCode,
    Icmp4EchoRequestMessage,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Echo Request packet, empty payload.",
            "_args": [],
            "_kwargs": {
                "id": 12345,
                "seq": 54321,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Echo Request, id 12345, seq 54321, len 8 (8+0)",
                "__repr__": (
                    "Icmp4EchoRequestMessage(code=<Icmp4EchoRequestCode.DEFAULT: 0>, "
                    "cksum=0, id=12345, seq=54321, data=b'')"
                ),
                "__bytes__": b"\x08\x00\xf3\x94\x30\x39\xd4\x31",
                "type": Icmp4Type.ECHO_REQUEST,
                "code": Icmp4EchoRequestCode.DEFAULT,
                "cksum": 0,
                "id": 12345,
                "seq": 54321,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Echo Request packet with payload.",
            "_args": [],
            "_kwargs": {
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "ICMPv4 Echo Request, id 12345, seq 54321, len 24 (8+16)",
                "__repr__": (
                    "Icmp4EchoRequestMessage(code=<Icmp4EchoRequestCode.DEFAULT: 0>, "
                    "cksum=0, id=12345, seq=54321, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\x08\x00\x24\xbe\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Icmp4Type.ECHO_REQUEST,
                "code": Icmp4EchoRequestCode.DEFAULT,
                "cksum": 0,
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "ICMPv4 Echo Request packet, maximum length of data.",
            "_args": [],
            "_kwargs": {
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65507,
            },
            "_results": {
                "__len__": 65515,
                "__str__": (
                    "ICMPv4 Echo Request, id 11111, seq 22222, len 65515 (8+65507)"
                ),
                "__repr__": (
                    "Icmp4EchoRequestMessage(code=<Icmp4EchoRequestCode.DEFAULT: 0>, "
                    f"cksum=0, id=11111, seq=22222, data=b'{"X" * 65507}')"
                ),
                "__bytes__": (
                    b"\x08\x00\x1e\xcb\x2b\x67\x56\xce" + b"X" * 65507
                ),
                "type": Icmp4Type.ECHO_REQUEST,
                "code": Icmp4EchoRequestCode.DEFAULT,
                "cksum": 0,
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65507,
            },
        },
    ]
)
class TestIcmp4EchoRequestAssembler(TestCase):
    """
    The ICMPv4 Echo Request message assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv4 Echo Request message assembler object
        with testcase arguments.
        """

        self._icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4EchoRequestMessage(*self._args, **self._kwargs)
        )

    def test__icmp4__echo_request__assembler__len(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._icmp4__assembler),
            self._results["__len__"],
        )

    def test__icmp4__echo_request__assembler__str(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._icmp4__assembler),
            self._results["__str__"],
        )

    def test__icmp4__echo_request__assembler__repr(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._icmp4__assembler),
            self._results["__repr__"],
        )

    def test__icmp4__echo_request__assembler__bytes(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._icmp4__assembler),
            self._results["__bytes__"],
        )

    def test__icmp4__echo_request__assembler__type(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message 'type' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__assembler.message.type,
            self._results["type"],
        )

    def test__icmp4__echo_request__assembler__code(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message 'code' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__assembler.message.code,
            self._results["code"],
        )

    def test__icmp4__echo_request__assembler__cksum(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message 'cksum' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__assembler.message.cksum,
            self._results["cksum"],
        )

    def test__icmp4__echo_request__assembler__id(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message 'id' field contains
        a correct value.
        """

        self.assertEqual(
            cast(Icmp4EchoRequestMessage, self._icmp4__assembler.message).id,
            self._results["id"],
        )

    def test__icmp4__echo_request__assembler__seq(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message 'seq' field contains
        a correct value.
        """

        self.assertEqual(
            cast(Icmp4EchoRequestMessage, self._icmp4__assembler.message).seq,
            self._results["seq"],
        )

    def test__icmp4__echo_request__assembler__data(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message 'data' field contains
        a correct value.
        """

        self.assertEqual(
            cast(Icmp4EchoRequestMessage, self._icmp4__assembler.message).data,
            self._results["data"],
        )
