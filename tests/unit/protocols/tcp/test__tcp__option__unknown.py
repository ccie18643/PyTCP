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
Module contains tests for the unknown TCP option code.

tests/unit/protocols/tcp/test__tcp__option__unknown.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_8__MAX, UINT_8__MIN
from pytcp.protocols.tcp.options.tcp_option import (
    TCP__OPTION__LEN,
    TcpOptionType,
)
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

        self._option_kwargs = {
            "type": TcpOptionType.from_int(255),
            "len": 8,
            "data": b"012345",
        }

    def test__tcp__option__unknown__type__not_TcpOptionType(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when
        the provided 'type' argument is not a TcpOptionType.
        """

        self._option_kwargs["type"] = value = "not a TcpOptionType"

        with self.assertRaises(AssertionError) as error:
            TcpOptionUnknown(**self._option_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be a TcpOptionType. Got: {type(value)!r}",
        )

    def test__tcp__option__unknown__type__core_value(
        self,
    ) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when
        the provided 'type' argument is a core TcpOptionType.
        """

        for type in TcpOptionType.get_known_values():
            self._option_kwargs["type"] = value = TcpOptionType(type)

            with self.assertRaises(AssertionError) as error:
                TcpOptionUnknown(**self._option_kwargs)  # type: ignore

            self.assertEqual(
                str(error.exception),
                "The 'type' field must not be a core TcpOptionType. "
                f"Got: {value!r}",
            )

    def test__tcp__option__unknown__len__under_min(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when
        the provided 'len' argument is lower than the minimum supported
        value.
        """

        self._option_kwargs["len"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionUnknown(**self._option_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__unknown__len__over_max(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when
        the provided 'len' argument is higher than the maximum supported
        value.
        """

        self._option_kwargs["len"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionUnknown(**self._option_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'len' field must be an 8-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__unknown__len__mismatch(self) -> None:
        """
        Ensure the TCP unknown option constructor raises an exception when
        the provided 'len' argument is different than the length of the
        'data' field.
        """

        self._option_kwargs["len"] = value = (
            TCP__OPTION__LEN + len(self._option_kwargs["data"]) + 1  # type: ignore
        )

        with self.assertRaises(AssertionError) as error:
            TcpOptionUnknown(**self._option_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            (
                "The 'len' field must reflect the length of the 'data' field. "
                f"Got: {value} != {TCP__OPTION__LEN + len(self._option_kwargs['data'])}"  # type: ignore
            ),
        )


@parameterized_class(
    [
        {
            "_description": "The unknown TCP option.",
            "_args": [],
            "_kwargs": {
                "type": TcpOptionType.from_int(255),
                "len": 18,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 18,
                "__str__": "unk-255-18",
                "__repr__": (
                    f"TcpOptionUnknown(type={TcpOptionType.from_int(255)!r}, "
                    "len=18, data=b'0123456789ABCDEF')"
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
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the unknown TCP option object with testcase arguments.
        """

        self._option = TcpOptionUnknown(*self._args, **self._kwargs)

    def test__tcp__option__unknown__len(self) -> None:
        """
        Ensure the unknown TCP option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__tcp__option__unknown__str(self) -> None:
        """
        Ensure the unknown TCP option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__tcp__option__unknown__repr(self) -> None:
        """
        Ensure the unknown TCP option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__tcp__option__unknown__bytes(self) -> None:
        """
        Ensure the unknown TCP option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__tcp__option__unknown__type(self) -> None:
        """
        Ensure the unknown TCP option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
        )

    def test__tcp__option__unknown__length(self) -> None:
        """
        Ensure the unknown TCP option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
        )

    def test__tcp__option__unknown__data(self) -> None:
        """
        Ensure the unknown TCP option 'data' field contains a correct value.
        """

        self.assertEqual(
            self._option.data,
            self._results["data"],
        )


@parameterized_class(
    [
        {
            "_description": "The unknown TCP option.",
            "_kwargs": {
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
            "_kwargs": {
                "bytes": b"\xff",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the unknown TCP option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (Eol) assert.",
            "_kwargs": {
                "bytes": (
                    b"\x00\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown TCP option type must not be known. "
                    "Got: <TcpOptionType.EOL: 0>"
                ),
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (Nop) assert.",
            "_kwargs": {
                "bytes": (
                    b"\x01\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown TCP option type must not be known. "
                    f"Got: {TcpOptionType.NOP!r}"
                ),
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (Mss) assert.",
            "_kwargs": {
                "bytes": (
                    b"\x02\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown TCP option type must not be known. "
                    f"Got: {TcpOptionType.MSS!r}"
                ),
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (Wscale) assert.",
            "_kwargs": {
                "bytes": (
                    b"\x03\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown TCP option type must not be known. "
                    f"Got: {TcpOptionType.WSCALE!r}"
                ),
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (Sackperm) assert.",
            "_kwargs": {
                "bytes": (
                    b"\x04\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown TCP option type must not be known. "
                    f"Got: {TcpOptionType.SACKPERM!r}"
                ),
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (Sack) assert.",
            "_kwargs": {
                "bytes": (
                    b"\x05\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown TCP option type must not be known. "
                    f"Got: {TcpOptionType.SACK!r}"
                ),
            },
        },
        {
            "_description": "The unknown TCP option incorrect 'type' field (Timestamps) assert.",
            "_kwargs": {
                "bytes": (
                    b"\x08\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45\x46"
                ),
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The unknown TCP option type must not be known. "
                    f"Got: {TcpOptionType.TIMESTAMPS!r}"
                ),
            },
        },
        {
            "_description": "The unknown TCP option length integrity check (II).",
            "_kwargs": {
                "bytes": (
                    b"\xff\x12\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44"
                    b"\x45"
                ),
            },
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The unknown TCP option length must be "
                    "less than or equal to the length of provided bytes (17). Got: 18"
                ),
            },
        },
    ]
)
class TestTcpOptionUnknownParser(TestCase):
    """
    The unknown TCP option parser tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp__option__unknown__from_bytes(self) -> None:
        """
        Ensure the unknown TCP option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            option = TcpOptionUnknown.from_bytes(self._kwargs["bytes"])

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                TcpOptionUnknown.from_bytes(self._kwargs["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
