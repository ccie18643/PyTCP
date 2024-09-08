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
Module contains tests for the DHCPv4 End option code.

tests/unit/protocols/dhcp4/test__dhcp4__option__end.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.dhcp4.options.dhcp4_option import Dhcp4OptionType
from pytcp.protocols.dhcp4.options.dhcp4_option__end import (
    DHCP4__OPTION__END__LEN,
    Dhcp4OptionEnd,
)


class TestDhcp4OptionEndAsserts(TestCase):
    """
    The DHCPv4 End option constructor argument assert tests.
    """

    # Currently the DHCPv4 End option does not have any constructor
    # argument asserts.


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Eond option.",
            "_args": {},
            "_results": {
                "__len__": 1,
                "__str__": "end",
                "__repr__": "Dhcp4OptionEnd()",
                "__bytes__": b"\xff",
                "type": Dhcp4OptionType.END,
                "len": DHCP4__OPTION__END__LEN,
            },
        },
    ]
)
class TestDhcp4OptionEndAssembler(TestCase):
    """
    The DHCPv4 End option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 End option object with testcase arguments.
        """

        self._option = Dhcp4OptionEnd(**self._args)

    def test__dhcp4__option__end__len(self) -> None:
        """
        Ensure the DHCPv4 End option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__dhcp4__option__end__str(self) -> None:
        """
        Ensure the DHCPv4 End option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__dhcp4__option__end__repr(self) -> None:
        """
        Ensure the DHCPv4 End option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__dhcp4__option__end__bytes(self) -> None:
        """
        Ensure the DHCPv4 End option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__dhcp4__option__end__type(self) -> None:
        """
        Ensure the DHCPv4 End option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
        )

    def test__dhcp4__option__end__length(self) -> None:
        """
        Ensure the DHCPv4 End option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 End option.",
            "_args": {
                "bytes": b"\xff",
            },
            "_results": {
                "option": Dhcp4OptionEnd(),
            },
        },
        {
            "_description": "The DHCPv4 End option minimum length assert.",
            "_args": {
                "bytes": b"",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the DHCPv4 End option must be 1 "
                    "byte. Got: 0"
                ),
            },
        },
        {
            "_description": "The DHCPv4 End option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xfe",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 End option type must be {Dhcp4OptionType.END!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
    ]
)
class TestDhcp4OptionEndParser(TestCase):
    """
    The DHCPv4 End option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__end__from_bytes(self) -> None:
        """
        Ensure the DHCPv4 End option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionEnd.from_bytes(self._args["bytes"] + b"ZH0PA")

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionEnd.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
