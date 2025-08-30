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
Module contains tests for the TCP Timestamps option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__timestamps.py

ver 3.0.4
"""


from typing import Any

from net_proto import (
    TCP__OPTION__TIMESTAMPS__LEN,
    UINT_32__MAX,
    UINT_32__MIN,
    TcpIntegrityError,
    TcpOptionTimestamps,
    TcpOptionType,
)
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase


class TestTcpOptionTimestampsAsserts(TestCase):
    """
    The TCP Timestamps option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the TCP Timestamps option constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "tsval": 0,
            "tsecr": 0,
        }

    def test__tcp__option__timestamps__tsval__under_min(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception when
        the provided 'tsval' argument is lower than the minimum supported value.
        """

        self._kwargs["tsval"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tsval' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__timestamps__tsval__over_max(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception when
        the provided 'tsval' argument is higher than the maximum supported value.
        """

        self._kwargs["tsval"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tsval' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__timestamps__tsecr__under_min(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception when
        the provided 'tsecr' argument is lower than the minimum supported value.
        """

        self._kwargs["tsecr"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tsecr' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__timestamps__tsecr__over_max(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception when
        the provided 'tsecr' argument is higher than the maximum supported value.
        """

        self._kwargs["tsecr"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tsecr' field must be a 32-bit unsigned integer. Got: {value}",
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Timestamps option (I).",
            "_args": [],
            "_kwargs": {
                "tsval": 4294967295,
                "tsecr": 4294967295,
            },
            "_results": {
                "__len__": 10,
                "__str__": "timestamps 4294967295/4294967295",
                "__repr__": (
                    "TcpOptionTimestamps(tsval=4294967295, tsecr=4294967295)"
                ),
                "__bytes__": b"\x08\x0a\xff\xff\xff\xff\xff\xff\xff\xff",
                "type": TcpOptionType.TIMESTAMPS,
                "len": TCP__OPTION__TIMESTAMPS__LEN,
                "tsval": 4294967295,
                "tsecr": 4294967295,
            },
        },
        {
            "_description": "The TCP Timestamps option (II).",
            "_args": [],
            "_kwargs": {
                "tsval": 1111111111,
                "tsecr": 2222222222,
            },
            "_results": {
                "__len__": 10,
                "__str__": "timestamps 1111111111/2222222222",
                "__repr__": (
                    "TcpOptionTimestamps(tsval=1111111111, tsecr=2222222222)"
                ),
                "__bytes__": b"\x08\x0a\x42\x3a\x35\xc7\x84\x74\x6b\x8e",
                "type": TcpOptionType.TIMESTAMPS,
                "len": TCP__OPTION__TIMESTAMPS__LEN,
                "tsval": 1111111111,
                "tsecr": 2222222222,
            },
        },
    ]
)
class TestTcpOptionTimestampsAssembler(TestCase):
    """
    The TCP Timestamps option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the TCP Timestamps option object with testcase arguments.
        """

        self._option = TcpOptionTimestamps(*self._args, **self._kwargs)

    def test__tcp__option__timestamps__len(self) -> None:
        """
        Ensure the TCP Timestamps option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__tcp__option__timestamps__str(self) -> None:
        """
        Ensure the TCP Timestamps option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__tcp__option__timestamps__repr(self) -> None:
        """
        Ensure the TCP Timestamps option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__tcp__option__timestamps__bytes(self) -> None:
        """
        Ensure the TCP Timestamps option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__tcp__option__timestamps__type(self) -> None:
        """
        Ensure the TCP Timestamps option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
        )

    def test__tcp__option__timestamps__length(self) -> None:
        """
        Ensure the TCP Timestamps option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
        )

    def test__tcp__option__timestamps__tsval(self) -> None:
        """
        Ensure the TCP Timestamps option 'tsval' field contains a correct value.
        """

        self.assertEqual(
            self._option.tsval,
            self._results["tsval"],
        )

    def test__tcp__option__timestamps__tsecr(self) -> None:
        """
        Ensure the TCP Timestamps option 'tsecr' field contains a correct value.
        """

        self.assertEqual(
            self._option.tsecr,
            self._results["tsecr"],
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Timestamps option (I).",
            "_args": [b"\x08\x0a\xff\xff\xff\xff\xff\xff\xff\xff" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": TcpOptionTimestamps(
                    tsval=4294967295, tsecr=4294967295
                ),
            },
        },
        {
            "_description": "The TCP Timestamps option (II).",
            "_args": [b"\x08\x0a\x42\x3a\x35\xc7\x84\x74\x6b\x8e" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": TcpOptionTimestamps(
                    tsval=1111111111, tsecr=2222222222
                ),
            },
        },
        {
            "_description": "The TCP Timestamps option minimum length assert.",
            "_args": [b"\x08"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the TCP Timestamps option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The TCP Timestamps option incorrect 'type' field assert.",
            "_args": [b"\xff\x0a\x00\x00\x00\x00\x00\x00\x00\x00"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Timestamps option type must be {TcpOptionType.TIMESTAMPS!r}. "
                    f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "The TCP Timestamps option length integrity check (I).",
            "_args": [b"\x08\x09\x00\x00\x00\x00\x00\x00\x00\x00"],
            "_kwargs": {},
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Timestamps option length "
                    "must be 10 bytes. Got: 9"
                ),
            },
        },
        {
            "_description": "The TCP Timestamps option length integrity check (II).",
            "_args": [b"\x08\x0a\x00\x00\x00\x00\x00\x00\x00"],
            "_kwargs": {},
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Timestamps option length "
                    "must be less than or equal to the length of provided "
                    "bytes (9). Got: 10"
                ),
            },
        },
    ]
)
class TestTcpOptionTimestampsParser(TestCase):
    """
    The TCP Timestamps option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp__option__timestamps__from_bytes(self) -> None:
        """
        Ensure the TCP Timestamps option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = TcpOptionTimestamps.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                TcpOptionTimestamps.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
