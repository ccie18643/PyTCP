#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains tests for the unknown IPv4 option code.

tests/unit/protocols/tcp/test__ip4__option__unknown.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_8__MAX, UINT_8__MIN
from pytcp.protocols.ip4.ip4__errors import Ip4IntegrityError
from pytcp.protocols.ip4.options.ip4_option import Ip4OptionType
from pytcp.protocols.ip4.options.ip4_option__unknown import Ip4OptionUnknown


class TestIp4OptionUnknownAsserts(TestCase):
    """
    The unknown IPv4 option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the IPv4 unknown option constructor.
        """

        self._option_args = {
            "type": Ip4OptionType.from_int(255),
            "len": 2,
            "data": b"",
        }

    def test__ip4__option__unknown__type__not_Ip4OptionType(self) -> None:
        """
        Ensure the IPv4 unknown option constructor raises an exception when the
        provided 'type' argument is not a Ip4OptionType.
        """

        self._option_args["type"] = value = "not a Ip4OptionType"

        with self.assertRaises(AssertionError) as error:
            Ip4OptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be a Ip4OptionType. Got: {type(value)!r}",
        )

    def test__ip4__option__unknown__len__under_min(self) -> None:
        """
        Ensure the Pv4 unknown option constructor raises an exception when the
        provided 'len' argument is lower than the minimum supported value.
        """

        self._option_args["len"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4OptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )

    def test__ip4__option__unknown__len__over_max(self) -> None:
        """
        Ensure the IPv4 unknown option constructor raises an exception when the
        provided 'len' argument is higher than the maximum supported value.
        """

        self._option_args["len"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4OptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )


@parameterized_class(
    [
        {
            "_description": "The unknown IPv4 option.",
            "_args": {
                "type": Ip4OptionType.from_int(255),
                "len": 18,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 18,
                "__str__": "unk-255-18",
                "__repr__": (
                    "Ip4OptionUnknown(type=<Ip4OptionType.UNKNOWN_255: 255>, len=18, "
                    "data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
                "type": Ip4OptionType.from_int(255),
                "len": 18,
                "data": b"0123456789ABCDEF",
            },
        },
    ]
)
class TestIp4OptionUnknownAssembler(TestCase):
    """
    The unknown IPv4 option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the unknown IPv4 option object with testcase arguments.
        """

        self._ip4_option_unknown = Ip4OptionUnknown(**self._args)

    def test__ip4_option_unknown__len(self) -> None:
        """
        Ensure the unknown IPv4 option '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._ip4_option_unknown),
            self._results["__len__"],
        )

    def test__ip4_option_unknown__str(self) -> None:
        """
        Ensure the unknown IPv4 option '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip4_option_unknown),
            self._results["__str__"],
        )

    def test__ip4_option_unknown__repr(self) -> None:
        """
        Ensure the unknown IPv4 option '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip4_option_unknown),
            self._results["__repr__"],
        )

    def test__ip4_option_unknown__bytes(self) -> None:
        """
        Ensure the unknown IPv4 option '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._ip4_option_unknown),
            self._results["__bytes__"],
        )

    def test__ip4_option_unknonwn__type(self) -> None:
        """
        Ensure the unknown IPv4 option 'type' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_option_unknown.type,
            self._results["type"],
        )

    def test__ip4_option_unknonwn__len(self) -> None:
        """
        Ensure the unknown IPv4 option 'len' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_option_unknown.len,
            self._results["len"],
        )

    def test__ip4_option_unknonwn__data(self) -> None:
        """
        Ensure the unknown IPv4 option 'data' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_option_unknown.data,
            self._results["data"],
        )


@parameterized_class(
    [
        {
            "_description": "The unknown IPv4 option.",
            "_args": {
                "bytes": (
                    b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "option": Ip4OptionUnknown(
                    type=Ip4OptionType.from_int(255),
                    len=18,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "The unknown IPv4 option minimum length assert.",
            "_args": {
                "bytes": b"\xff",
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The unknown IPv4 option incorrect 'type' field (0) assert.",
            "_args": {
                "bytes": (
                    b"\x00\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The unknown IPv4 option incorrect 'type' field (1) assert.",
            "_args": {
                "bytes": (
                    b"\x01\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The unknown IPv4 option length integrity check (II).",
            "_args": {
                "bytes": (
                    b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45"
                ),
            },
            "_results": {
                "error": Ip4IntegrityError,
                "error_message": "Invalid unknown option length (II).",
            },
        },
    ]
)
class TestIp4OptionUnknownParser(TestCase):
    """
    The unknown IPv4 option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__ip4_option_unknown__from_bytes(self) -> None:
        """
        Ensure the unknown IPv4 option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            ip4_option_unknown = Ip4OptionUnknown.from_bytes(
                self._args["bytes"]
            )

            self.assertEqual(
                ip4_option_unknown,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Ip4OptionUnknown.from_bytes(self._args["bytes"])

            if "error_message" in self._results:
                self.assertEqual(
                    str(error.exception),
                    f"[INTEGRITY ERROR][IPv4] {self._results['error_message']}",
                )
