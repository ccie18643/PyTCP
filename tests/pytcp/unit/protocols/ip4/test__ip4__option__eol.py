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
Module contains tests for the IPv4 Eol (End of Option List) option code.

tests/pytcp/unit/protocols/ip4/test__ip4__option__eol.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.ip4.options.ip4_option import Ip4OptionType
from pytcp.protocols.ip4.options.ip4_option__eol import (
    IP4__OPTION__EOL__LEN,
    Ip4OptionEol,
)


class TestIp4OptionEolAsserts(TestCase):
    """
    The IPv4 Eol option constructor argument assert tests.
    """

    # Currently the IPv4 Eol option does not have any constructor
    # argument asserts.


@parameterized_class(
    [
        {
            "_description": "The IPv4 Eol option.",
            "_args": [],
            "_kwargs": {},
            "_results": {
                "__len__": 1,
                "__str__": "eol",
                "__repr__": "Ip4OptionEol()",
                "__bytes__": b"\x00",
                "type": Ip4OptionType.EOL,
                "len": IP4__OPTION__EOL__LEN,
            },
        },
    ]
)
class TestIp4OptionEolAssembler(TestCase):
    """
    The IPv4 Eol option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 Eol option object with testcase arguments.
        """

        self._option = Ip4OptionEol(*self._args, **self._kwargs)

    def test__ip4__option__eol__len(self) -> None:
        """
        Ensure the IPv4 Eol option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__ip4__option__eol__str(self) -> None:
        """
        Ensure the IPv4 Eol option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__ip4__option__eol__repr(self) -> None:
        """
        Ensure the IPv4 Eol option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__ip4__option__eol__bytes(self) -> None:
        """
        Ensure the IPv4 Eol option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__ip4__option__eol__type(self) -> None:
        """
        Ensure the IPv4 Eol option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
        )

    def test__ip4__option__eol__length(self) -> None:
        """
        Ensure the IPv4 Eol option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
        )


@parameterized_class(
    [
        {
            "_description": "The IPv4 Eol option.",
            "_args": [b"\x00" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Ip4OptionEol(),
            },
        },
        {
            "_description": "The IPv4 Eol option minimum length assert.",
            "_args": [b""],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the IPv4 Eol option must be 1 "
                    "byte. Got: 0"
                ),
            },
        },
        {
            "_description": "The IPv4 Eol option incorrect 'type' field assert.",
            "_args": [b"\xff"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The IPv4 Eol option type must be {Ip4OptionType.EOL!r}. "
                    f"Got: {Ip4OptionType.from_int(255)!r}"
                ),
            },
        },
    ]
)
class TestIp4OptionEolParser(TestCase):
    """
    The IPv4 Eol option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__ip4__option__eol__from_bytes(self) -> None:
        """
        Ensure the IPv4 Eol option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            option = Ip4OptionEol.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Ip4OptionEol.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
