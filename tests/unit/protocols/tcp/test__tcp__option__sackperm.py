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
Module contains tests for the TCP Sackperm (SACK Permitted) option code.

tests/unit/protocols/tcp/test__tcp__option__sackperm.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.tcp.options.tcp_option import TcpOptionType
from pytcp.protocols.tcp.options.tcp_option__sackperm import (
    TCP__OPTION__SACKPERM__LEN,
    TcpOptionSackperm,
)
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError


class TestTcpOptionSackpermAsserts(TestCase):
    """
    The TCP Sackperm option constructor argument assert tests.
    """

    # Currently the TCP Sackperm option does not have any constructor
    # argument asserts.


@parameterized_class(
    [
        {
            "_description": "The TCP Sackperm option.",
            "_args": [],
            "_kwargs": {},
            "_results": {
                "__len__": 2,
                "__str__": "sackperm",
                "__repr__": "TcpOptionSackperm()",
                "__bytes__": b"\x04\x02",
                "type": TcpOptionType.SACKPERM,
                "len": TCP__OPTION__SACKPERM__LEN,
            },
        },
    ]
)
class TestTcpOptionSackpermAssembler(TestCase):
    """
    The TCP Sackperm option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the TCP Sackperm option object with testcase arguments.
        """

        self._option = TcpOptionSackperm(*self._args, **self._kwargs)

    def test__tcp__option__sackperm__len(self) -> None:
        """
        Ensure the TCP Sackperm option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__tcp__option__sackperm__str(self) -> None:
        """
        Ensure the TCP Sackperm option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__tcp__option__sackperm__repr(self) -> None:
        """
        Ensure the TCP Sackperm option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__tcp__option__sackperm__bytes(self) -> None:
        """
        Ensure the TCP Sackperm option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__tcp__option__sackperm__type(self) -> None:
        """
        Ensure the TCP Sackperm option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
        )

    def test__tcp__option__sackperm__lenght(self) -> None:
        """
        Ensure the TCP Sackperm option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Sackperm option.",
            "_args": [b"\x04\x02" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": TcpOptionSackperm(),
            },
        },
        {
            "_description": "The 'Sackperm' TCP option minimum length assert.",
            "_args": [b"\x04"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the TCP Sackperm option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The TCP Sackperm option 'type' incorrect field assert.",
            "_args": [b"\xff\02"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Sackperm option type must be {TcpOptionType.SACKPERM!r}. "
                    f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "The TCP Sackperm option length integrity check (I).",
            "_args": [b"\x04\01"],
            "_kwargs": {},
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Sackperm option length must be "
                    "2 bytes. Got: 1"
                ),
            },
        },
    ]
)
class TestTcpOptionSackpermParser(TestCase):
    """
    The TCP Sackperm option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp__option__sackperm__from_bytes(self) -> None:
        """
        Ensure the TCP Sackperm option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            option = TcpOptionSackperm.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                TcpOptionSackperm.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
