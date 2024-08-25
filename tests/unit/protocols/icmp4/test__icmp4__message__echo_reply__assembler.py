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
Module contains tests for the ICMPv4 Echo Reply message assembler.

tests/unit/protocols/icmp4/test__icmp4__message__echo_reply__packets.py

ver 3.0.1
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Type
from pytcp.protocols.icmp4.message.icmp4_message__echo_reply import (
    Icmp4EchoReplyCode,
    Icmp4EchoReplyMessage,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Echo Reply message, empty data.",
            "_args": {
                "id": 12345,
                "seq": 54321,
                "cksum": 12121,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Echo Reply, id 12345, seq 54321, len 8 (8+0)",
                "__repr__": (
                    "Icmp4EchoReplyMessage(code=<Icmp4EchoReplyCode.DEFAULT: 0>, "
                    "cksum=12121, id=12345, seq=54321, data=b'')"
                ),
                "__bytes__": b"\x00\x00\x00\x00\x30\x39\xd4\x31",
                "type": Icmp4Type.ECHO_REPLY,
                "code": Icmp4EchoReplyCode.DEFAULT,
                "cksum": 12121,
                "id": 12345,
                "seq": 54321,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Echo Reply message, non-empty data.",
            "_args": {
                "cksum": 21212,
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "ICMPv4 Echo Reply, id 12345, seq 54321, len 24 (8+16)",
                "__repr__": (
                    "Icmp4EchoReplyMessage(code=<Icmp4EchoReplyCode.DEFAULT: 0>, "
                    "cksum=21212, id=12345, seq=54321, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\x00\x00\x00\x00\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Icmp4Type.ECHO_REPLY,
                "code": Icmp4EchoReplyCode.DEFAULT,
                "cksum": 21212,
                "id": 12345,
                "seq": 54321,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "ICMPv4 Echo Reply message, maximum length of data.",
            "_args": {
                "cksum": 33333,
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65507,
            },
            "_results": {
                "__len__": 65515,
                "__str__": (
                    "ICMPv4 Echo Reply, id 11111, seq 22222, len 65515 (8+65507)"
                ),
                "__repr__": (
                    "Icmp4EchoReplyMessage(code=<Icmp4EchoReplyCode.DEFAULT: 0>, "
                    f"cksum=33333, id=11111, seq=22222, data=b'{"X" * 65507}')"
                ),
                "__bytes__": (
                    b"\x00\x00\x00\x00\x2b\x67\x56\xce" + b"X" * 65507
                ),
                "type": Icmp4Type.ECHO_REPLY,
                "code": Icmp4EchoReplyCode.DEFAULT,
                "cksum": 33333,
                "id": 11111,
                "seq": 22222,
                "data": b"X" * 65507,
            },
        },
    ]
)
class TestIcmp4MessageEchoReplyAssembler(TestCase):
    """
    The ICMPv4 Echo Reply message assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv4 Echo Reply message assembler object with
        testcase arguments.
        """

        self._icmp4__echo_reply__message = Icmp4EchoReplyMessage(**self._args)

    def test__icmp4__message__echo_reply__assembler__len(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._icmp4__echo_reply__message),
            self._results["__len__"],
        )

    def test__icmp4__message__echo_reply__assembler__str(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._icmp4__echo_reply__message),
            self._results["__str__"],
        )

    def test__icmp4__message__echo_reply__assembler__repr(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._icmp4__echo_reply__message),
            self._results["__repr__"],
        )

    def test__icmp4__message__echo_reply__assembler__bytes(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._icmp4__echo_reply__message),
            self._results["__bytes__"],
        )

    def test__icmp4__message__echo_reply__assembler__type(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message 'type' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__echo_reply__message.type,
            self._results["type"],
        )

    def test__icmp4__message__echo_reply__assembler__code(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message 'code' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__echo_reply__message.code,
            self._results["code"],
        )

    def test__icmp4__message__echo_reply__assembler__cksum(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message 'cksum' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__echo_reply__message.cksum,
            self._results["cksum"],
        )

    def test__icmp4__message__echo_reply__assembler__id(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message 'id' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__echo_reply__message.id,
            self._results["id"],
        )

    def test__icmp4__message__echo_reply__assembler__seq(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message 'seq' field contains
        a correct value.

        """

        self.assertEqual(
            self._icmp4__echo_reply__message.seq,
            self._results["seq"],
        )

    def test__icmp4__message__echo_reply__assembler__data(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message 'data' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__echo_reply__message.data,
            self._results["data"],
        )
