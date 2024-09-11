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
Module contains tests for the TCP Sack (Selective ACK) option code.

tests/pytcp/unit/protocols/tcp/test__tcp__option__sack.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.tcp.options.tcp_option import TcpOptionType
from pytcp.protocols.tcp.options.tcp_option__sack import (
    TCP__OPTION__SACK__LEN,
    TCP__OPTION__SACK__MAX_BLOCK_NUM,
    TcpOptionSack,
    TcpSackBlock,
)
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError


class TestTcpOptionSackAsserts(TestCase):
    """
    The TCP Sack option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the TCP Sack option constructor.
        """

        self._args: list[Any] = [[]]
        self._kwargs: dict[str, Any] = {}

    def test__tcp__option__sack__blocks__too_many(self) -> None:
        """
        Ensure the TCP Sack option constructor raises an exception when the
        provided 'blocks' argument has too many elements.
        """

        value = TCP__OPTION__SACK__MAX_BLOCK_NUM + 1
        self._args[0] = [TcpSackBlock(0, 0)] * value

        with self.assertRaises(AssertionError) as error:
            TcpOptionSack(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'blocks' field must have at most {TCP__OPTION__SACK__MAX_BLOCK_NUM} "
            f"elements. Got: {value}",
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Sack option (I).",
            "_args": [[]],
            "_kwargs": {},
            "_results": {
                "__len__": 2,
                "__str__": "sack []",
                "__repr__": "TcpOptionSack(blocks=[])",
                "__bytes__": b"\x05\x02",
                "type": TcpOptionType.SACK,
                "length": TCP__OPTION__SACK__LEN,
                "blocks": [],
            },
        },
        {
            "_description": "The TCP Sack option (II).",
            "_args": [[TcpSackBlock(4294967295, 4294967295)]],
            "_kwargs": {},
            "_results": {
                "__len__": 10,
                "__str__": "sack [4294967295-4294967295]",
                "__repr__": (
                    "TcpOptionSack(blocks=[TcpSackBlock(left=4294967295, "
                    "right=4294967295)])"
                ),
                "__bytes__": b"\x05\x0a\xff\xff\xff\xff\xff\xff\xff\xff",
                "type": TcpOptionType.SACK,
                "length": TCP__OPTION__SACK__LEN + 8 * 1,
                "blocks": [TcpSackBlock(4294967295, 4294967295)],
            },
        },
        {
            "_description": "The TCP Sack option (III).",
            "_args": [
                [
                    TcpSackBlock(1111, 2222),
                    TcpSackBlock(3333, 4444),
                    TcpSackBlock(5555, 6666),
                ]
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 26,
                "__str__": "sack [1111-2222, 3333-4444, 5555-6666]",
                "__repr__": (
                    "TcpOptionSack(blocks=[TcpSackBlock(left=1111, right=2222), "
                    "TcpSackBlock(left=3333, right=4444), TcpSackBlock(left=5555, "
                    "right=6666)])"
                ),
                "__bytes__": (
                    b"\x05\x1a\x00\x00\x04\x57\x00\x00\x08\xae\x00\x00\x0d\x05\x00\x00"
                    b"\x11\x5c\x00\x00\x15\xb3\x00\x00\x1a\x0a"
                ),
                "type": TcpOptionType.SACK,
                "length": TCP__OPTION__SACK__LEN + 8 * 3,
                "blocks": [
                    TcpSackBlock(1111, 2222),
                    TcpSackBlock(3333, 4444),
                    TcpSackBlock(5555, 6666),
                ],
            },
        },
        {
            "_description": "The TCP Sack option (IV).",
            "_args": [
                [
                    TcpSackBlock(111, 222),
                    TcpSackBlock(333, 444),
                    TcpSackBlock(555, 666),
                    TcpSackBlock(777, 888),
                ]
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 34,
                "__str__": "sack [111-222, 333-444, 555-666, 777-888]",
                "__repr__": (
                    "TcpOptionSack(blocks=[TcpSackBlock(left=111, right=222), "
                    "TcpSackBlock(left=333, right=444), TcpSackBlock(left=555, "
                    "right=666), TcpSackBlock(left=777, right=888)])"
                ),
                "__bytes__": (
                    b"\x05\x22\x00\x00\x00\x6f\x00\x00\x00\xde\x00\x00\x01\x4d\x00\x00"
                    b"\x01\xbc\x00\x00\x02\x2b\x00\x00\x02\x9a\x00\x00\x03\x09\x00\x00"
                    b"\x03\x78"
                ),
                "type": TcpOptionType.SACK,
                "length": TCP__OPTION__SACK__LEN + 8 * 4,
                "blocks": [
                    TcpSackBlock(111, 222),
                    TcpSackBlock(333, 444),
                    TcpSackBlock(555, 666),
                    TcpSackBlock(777, 888),
                ],
            },
        },
    ]
)
class TestTcpOptionSackAssembler(TestCase):
    """
    The TCP Sack option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, TcpSackBlock]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the TCP Sack option object with testcase arguments.
        """

        self._option = TcpOptionSack(*self._args, **self._kwargs)  # type: ignore

    def test__tcp__option__sack__len(self) -> None:
        """
        Ensure the TCP Sack option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__tcp__option__sack__str(self) -> None:
        """
        Ensure the TCP Sack option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__tcp__option__sack__repr(self) -> None:
        """
        Ensure the TCP Sack option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__tcp__option__sack__bytes(self) -> None:
        """
        Ensure the TCP Sack option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__tcp__option__sack__blocks(self) -> None:
        """
        Ensure the TCP Sack option 'blocks' field contains a correct value.
        """

        self.assertEqual(
            self._option.blocks,
            self._results["blocks"],
        )

    def test__tcp__option__sack__type(self) -> None:
        """
        Ensure the TCP Sack option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
        )

    def test__tcp__option__sack__length(self) -> None:
        """
        Ensure the TCP Sack option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._option.len,
            self._results["length"],
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Sack option (I).",
            "_args": [b"\x05\x02" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": TcpOptionSack(blocks=[]),
            },
        },
        {
            "_description": "The TCP Sack option (II).",
            "_args": [b"\x05\x0a\xff\xff\xff\xff\xff\xff\xff\xff" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": TcpOptionSack(
                    blocks=[
                        TcpSackBlock(4294967295, 4294967295),
                    ],
                ),
            },
        },
        {
            "_description": "The TCP Sack option (III).",
            "_args": [
                b"\x05\x1a\x00\x00\x04\x57\x00\x00\x08\xae\x00\x00\x0d\x05\x00\x00"
                b"\x11\x5c\x00\x00\x15\xb3\x00\x00\x1a\x0a" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": TcpOptionSack(
                    blocks=[
                        TcpSackBlock(1111, 2222),
                        TcpSackBlock(3333, 4444),
                        TcpSackBlock(5555, 6666),
                    ],
                ),
            },
        },
        {
            "_description": "The TCP Sack option (IV).",
            "_args": [
                b"\x05\x22\x00\x00\x00\x6f\x00\x00\x00\xde\x00\x00\x01\x4d\x00\x00"
                b"\x01\xbc\x00\x00\x02\x2b\x00\x00\x02\x9a\x00\x00\x03\x09\x00\x00"
                b"\x03\x78" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": TcpOptionSack(
                    blocks=[
                        TcpSackBlock(111, 222),
                        TcpSackBlock(333, 444),
                        TcpSackBlock(555, 666),
                        TcpSackBlock(777, 888),
                    ],
                ),
            },
        },
        {
            "_description": "The TCP Sack option minimum length assert.",
            "_args": [b"\x05"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the TCP Sack option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The TCP Sack option incorrect 'type' field assert.",
            "_args": [b"\xff\x02"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Sack option type must be {TcpOptionType.SACK!r}. "
                    f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "The TCP Sack option length integrity check (II).",
            "_args": [b"\x05\x0a\xff\xff\xff\xff\xff\xff\xff"],
            "_kwargs": {},
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Sack option length must "
                    "be less than or equal to the length of provided bytes "
                    "(9). Got: 10"
                ),
            },
        },
        {
            "_description": "The TCP Sack option length integrity check (III).",
            "_args": [b"\x05\x0b\xff\xff\xff\xff\xff\xff\xff\xff\x00"],
            "_kwargs": {},
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Sack option blocks length "
                    "must be a multiple of 8. Got: 9"
                ),
            },
        },
    ]
)
class TestTcpOptionSackParser(TestCase):
    """
    The TCP Sack option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp__option__sack__from_bytes(self) -> None:
        """
        Ensure the TCP Sackp option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            option = TcpOptionSack.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                TcpOptionSack.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
