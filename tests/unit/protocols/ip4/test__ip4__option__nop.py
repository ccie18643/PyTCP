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
Module contains tests for the IPv4 Nop (No Operation) option code.

tests/unit/protocols/ip4/test__ip4__option__nop.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.ip4.options.ip4_option import Ip4OptionType
from pytcp.protocols.ip4.options.ip4_option__nop import (
    IP4__OPTION_NOP__LEN,
    Ip4OptionNop,
)


class TestIp4OptionNopAsserts(TestCase):
    """
    The IPv4 Nop option constructor argument assert tests.
    """

    # Currently the IPv4 Nop option does not have any constructor
    # argument asserts.


@parameterized_class(
    [
        {
            "_description": "The IPv4 Nop option.",
            "_args": {},
            "_results": {
                "__len__": 1,
                "__str__": "nop",
                "__repr__": "Ip4OptionNop()",
                "__bytes__": b"\x01",
                "type": Ip4OptionType.NOP,
                "len": IP4__OPTION_NOP__LEN,
            },
        },
    ]
)
class TestIp4OptionNopAssembler(TestCase):
    """
    The IPv4 Nop option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 Nop option object with testcase arguments.
        """

        self._ip4_option_nop = Ip4OptionNop(**self._args)

    def test__ip4__option__nop__len(self) -> None:
        """
        Ensure the IPv4 Nop option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._ip4_option_nop),
            self._results["__len__"],
        )

    def test__ip4__option__nop__str(self) -> None:
        """
        Ensure the IPv4 Nop option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._ip4_option_nop),
            self._results["__str__"],
        )

    def test__ip4__option__nop__repr(self) -> None:
        """
        Ensure the IPv4 Nop option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._ip4_option_nop),
            self._results["__repr__"],
        )

    def test__ip4__option__nop__bytes(self) -> None:
        """
        Ensure the IPv4 Nop option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._ip4_option_nop),
            self._results["__bytes__"],
        )

    def test__ip4__option__nop__type(self) -> None:
        """
        Ensure the IPv4 Nop option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._ip4_option_nop.type,
            self._results["type"],
        )

    def test__ip4__option__nop__lenght(self) -> None:
        """
        Ensure the IPv4 Nop option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._ip4_option_nop.len,
            self._results["len"],
        )


@parameterized_class(
    [
        {
            "_description": "The IPv4 Nop option.",
            "_args": {
                "bytes": b"\x01",
            },
            "_results": {
                "option": Ip4OptionNop(),
            },
        },
        {
            "_description": "The IPv4 Nop option minimum length assert.",
            "_args": {
                "bytes": b"",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the IPv4 Nop option must be 1 "
                    "byte. Got: 0"
                ),
            },
        },
        {
            "_description": "The IPv4 Nop option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The IPv4 Nop option type must be {Ip4OptionType.NOP!r}. "
                    f"Got: {Ip4OptionType.from_int(255)!r}"
                ),
            },
        },
    ]
)
class TestIp4OptionNopParser(TestCase):
    """
    The IPv4 Nop option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ip4__option__nop__from_bytes(self) -> None:
        """
        Ensure the IPv4 Nop option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            ip4_option_nop = Ip4OptionNop.from_bytes(
                self._args["bytes"] + b"ZH0PA"
            )

            self.assertEqual(
                ip4_option_nop,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Ip4OptionNop.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
