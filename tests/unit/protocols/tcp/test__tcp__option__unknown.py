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
This module contains tests for the unknown TCP option code.

tests/unit/protocols/tcp/test__tcp__option__unknown.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_8__MAX, UINT_8__MIN
from pytcp.protocols.tcp.options.tcp_option import TcpOptionType
from pytcp.protocols.tcp.options.tcp_option__unknown import TcpOptionUnknown
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError


class TestTcpOptionUnknownAsserts(TestCase):
    """
    The unknown TCP option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the TCP unknown option constructor.
        """

        self._option_args = {
            "type": TcpOptionType.from_int(255),
            "len": 2,
            "data": b"",
        }

    def test__tcp__option__unknown__type__not_TcpOptionType(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when the
        provided 'type' argument is not a TcpOptionType.
        """

        self._option_args["type"] = value = "not a TcpOptionType"

        with self.assertRaises(AssertionError) as error:
            TcpOptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be a TcpOptionType. Got: {type(value)!r}",
        )

    def test__tcp__option__unknown__len__under_min(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when the
        provided 'len' argument is lower than the minimum supported value.
        """

        self._option_args["len"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__unknown__len__over_max(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when the
        provided 'len' argument is higher than the maximum supported value.
        """

        self._option_args["len"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionUnknown(**self._option_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )


@parameterized_class(
    [
        {
            "_description": "The unknown TCP option.",
            "_args": {
                "type": TcpOptionType.from_int(255),
                "len": 18,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 18,
                "__str__": "unk-255-18",
                "__repr__": (
                    "TcpOptionUnknown(type=<TcpOptionType.UNKNOWN_255: 255>, len=18, "
                    "data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
                "type": TcpOptionType.from_int(255),
                "len": 18,
                "data": b"0123456789ABCDEF",
            },
        },
    ]
)
class TestTcpOptionUnknownAssembler(TestCase):
    """
    The unknown TCP option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the unknown TCP option object with testcase arguments.
        """

        self._tcp_option_unknown = TcpOptionUnknown(**self._args)

    def test__tcp__option__unknown__len(self) -> None:
        """
        Ensure the unknown TCP option '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._tcp_option_unknown),
            self._results["__len__"],
        )

    def test__tcp__option__unknown__str(self) -> None:
        """
        Ensure the unknown TCP option '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._tcp_option_unknown),
            self._results["__str__"],
        )

    def test__tcp__option__unknown__repr(self) -> None:
        """
        Ensure the unknown TCP option '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._tcp_option_unknown),
            self._results["__repr__"],
        )

    def test__tcp__option__unknown__bytes(self) -> None:
        """
        Ensure the unknown TCP option '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._tcp_option_unknown),
            self._results["__bytes__"],
        )

    def test__tcp_option_unknonwn__type(self) -> None:
        """
        Ensure the unknown TCP option 'type' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_option_unknown.type,
            self._results["type"],
        )

    def test__tcp_option_unknonwn__len(self) -> None:
        """
        Ensure the unknown TCP option 'len' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_option_unknown.len,
            self._results["len"],
        )

    def test__tcp_option_unknonwn__data(self) -> None:
        """
        Ensure the unknown TCP option 'data' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_option_unknown.data,
            self._results["data"],
        )


@parameterized_class(
    [
        {
            "_description": "The unknown TCP option.",
            "_args": {
                "bytes": (
                    b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "option": TcpOptionUnknown(
                    type=TcpOptionType.from_int(255),
                    len=18,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "The unknown TCP option minimum length assert.",
            "_args": {
                "bytes": b"\xff",
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (0) assert.",
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
            "_description": "The unknown TCP option incorrect 'type' field (1) assert.",
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
            "_description": "The unknown TCP option incorrect 'type' field (3) assert.",
            "_args": {
                "bytes": (
                    b"\x03\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (4) assert.",
            "_args": {
                "bytes": (
                    b"\x04\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (5) assert.",
            "_args": {
                "bytes": (
                    b"\x05\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (8) assert.",
            "_args": {
                "bytes": (
                    b"\x08\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The unknown TCP option length integrity check (II).",
            "_args": {
                "bytes": (
                    b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45"
                ),
            },
            "_results": {
                "error": TcpIntegrityError,
                "error_message": "Invalid unknown option length (II).",
            },
        },
    ]
)
class TestTcpOptionUnknownParser(TestCase):
    """
    The unknown TCP option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp__option__unknown__from_bytes(self) -> None:
        """
        Ensure the unknown TCP option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            tcp_option_unknown = TcpOptionUnknown.from_bytes(
                self._args["bytes"]
            )

            self.assertEqual(
                tcp_option_unknown,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                TcpOptionUnknown.from_bytes(self._args["bytes"])

            if "error_message" in self._results:
                self.assertEqual(
                    str(error.exception),
                    f"[INTEGRITY ERROR][TCP] {self._results['error_message']}",
                )
