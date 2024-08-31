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
Module contains tests for the IPv4 options support code.

tests/unit/protocols/ip4/test__ip4__options.py

ver 3.0.1
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.ip4.options.ip4_option import Ip4Option
from pytcp.protocols.ip4.options.ip4_option__eol import Ip4OptionEol
from pytcp.protocols.ip4.options.ip4_option__nop import Ip4OptionNop
from pytcp.protocols.ip4.options.ip4_options import Ip4Options


@parameterized_class(
    [
        {
            "_description": "The Ip4 options (I).",
            "_args": [
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionEol(),
            ],
            "_results": {
                "__len__": 4,
                "__str__": "nop, nop, nop, eol",
                "__repr__": (
                    "Ip4Options(options=[Ip4OptionNop(), Ip4OptionNop(), "
                    "Ip4OptionNop(), Ip4OptionEol()])"
                ),
                "__bytes__": b"\x01\x01\x01\x00",
            },
        },
    ]
)
class TestIp4OptionsAssembler(TestCase):
    """
    The 'Ip4Options' class assembler tests.
    """

    _description: str
    _args: list[Ip4Option]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the 'Ip4Options' class object with testcase arguments.
        """

        self._ip4_options = Ip4Options(*self._args)

    def test__ip4_options__len(self) -> None:
        """
        Ensure the 'Ip4Options' class '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._ip4_options),
            self._results["__len__"],
        )

    def test__ip4_options__str(self) -> None:
        """
        Ensure the 'Ip4Options' class '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip4_options),
            self._results["__str__"],
        )

    def test__ip4_options__repr(self) -> None:
        """
        Ensure the 'Ip4Options' class '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip4_options),
            self._results["__repr__"],
        )

    def test__ip4_options__bytes(self) -> None:
        """
        Ensure the 'Ip4Options' class '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._ip4_options),
            self._results["__bytes__"],
        )


@parameterized_class(
    [
        {
            "_description": "The IPv4 options (I).",
            "_args": {
                "bytes": b"\x01\x01\x01\x00",
            },
            "_results": {
                "options": Ip4Options(
                    Ip4OptionNop(),
                    Ip4OptionNop(),
                    Ip4OptionNop(),
                    Ip4OptionEol(),
                ),
            },
        },
    ]
)
class TestIp4OptionsParser(TestCase):
    """
    The 'Ip4Options' class parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ip4_options__from_bytes(self) -> None:
        """
        Ensure the 'Ip4Options' class parser creates the proper option object.
        """

        ip4_options = Ip4Options.from_bytes(self._args["bytes"])

        self.assertEqual(
            ip4_options,
            self._results["options"],
        )
