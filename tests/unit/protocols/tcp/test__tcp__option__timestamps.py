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
This module contains tests for the TCP Timestamps option code.

tests/unit/protocols/tcp/test__tcp__option__timestamps.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_32__MAX, UINT_32__MIN
from pytcp.protocols.tcp.options.tcp_option__timestamps import (
    TcpOptionTimestamps,
)
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError


class TestTcpOptionTimestampsAsserts(TestCase):
    """
    The TCP Timestamps option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the TCP Timestamps option constructor.
        """

        self._option_args = {
            "tsval": 0,
            "tsecr": 0,
        }

    def test__tcp__option__timestamps__tsval__under_min(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception when the
        provided 'tsval' argument is lower than the minimum supported value.
        """

        self._option_args["tsval"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(**self._option_args)

        self.assertEqual(
            str(error.exception),
            f"The 'tsval' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__timestamps__tsval__over_max(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception when the
        provided 'tsval' argument is higher than the maximum supported value.
        """

        self._option_args["tsval"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(**self._option_args)

        self.assertEqual(
            str(error.exception),
            f"The 'tsval' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__timestamps__tsecr__under_min(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception when the
        provided 'tsecr' argument is lower than the minimum supported value.
        """

        self._option_args["tsecr"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(**self._option_args)

        self.assertEqual(
            str(error.exception),
            f"The 'tsecr' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__timestamps__tsecr__over_max(self) -> None:
        """
        Ensure the TCP Timestamps option constructor raises an exception when the
        provided 'tsecr' argument is higher than the maximum supported value.
        """

        self._option_args["tsecr"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionTimestamps(**self._option_args)

        self.assertEqual(
            str(error.exception),
            f"The 'tsecr' field must be a 32-bit unsigned integer. Got: {value}",
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Timestamps option (I).",
            "_args": {
                "tsval": 4294967295,
                "tsecr": 4294967295,
            },
            "_results": {
                "__len__": 10,
                "__str__": "timestamps 4294967295/4294967295",
                "__repr__": "TcpOptionTimestamps(tsval=4294967295, tsecr=4294967295)",
                "__bytes__": b"\x08\x0a\xff\xff\xff\xff\xff\xff\xff\xff",
                "tsval": 4294967295,
                "tsecr": 4294967295,
            },
        },
        {
            "_description": "The TCP Timestamps option (II).",
            "_args": {
                "tsval": 1111111111,
                "tsecr": 2222222222,
            },
            "_results": {
                "__len__": 10,
                "__str__": "timestamps 1111111111/2222222222",
                "__repr__": "TcpOptionTimestamps(tsval=1111111111, tsecr=2222222222)",
                "__bytes__": b"\x08\x0a\x42\x3a\x35\xc7\x84\x74\x6b\x8e",
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
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the TCP Timestamps option object with testcase arguments.
        """

        self._tcp_option_timestamps = TcpOptionTimestamps(**self._args)

    def test__tcp_option_timestamps__len(self) -> None:
        """
        Ensure the TCP Timestamps option '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._tcp_option_timestamps),
            self._results["__len__"],
        )

    def test__tcp_option_timestamps__str(self) -> None:
        """
        Ensure the TCP Timestamps option '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._tcp_option_timestamps),
            self._results["__str__"],
        )

    def test__tcp_option_timestamps__repr(self) -> None:
        """
        Ensure the TCP Timestamps option '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._tcp_option_timestamps),
            self._results["__repr__"],
        )

    def test__tcp_option_timestamps__bytes(self) -> None:
        """
        Ensure the TCP Timestamps option '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._tcp_option_timestamps),
            self._results["__bytes__"],
        )

    def test__tcp_option_timestamps__tsval(self) -> None:
        """
        Ensure the TCP Timestamps option 'tsval' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_option_timestamps.tsval,
            self._results["tsval"],
        )

    def test__tcp_option_timestamps__tsecr(self) -> None:
        """
        Ensure the TCP Timestamps option 'tsecr' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_option_timestamps.tsecr,
            self._results["tsecr"],
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Timestamps option (I).",
            "_args": {
                "bytes": b"\x08\x0a\xff\xff\xff\xff\xff\xff\xff\xff",
            },
            "_results": {
                "option": TcpOptionTimestamps(
                    tsval=4294967295, tsecr=4294967295
                ),
            },
        },
        {
            "_description": "The TCP Timestamps option (I).",
            "_args": {
                "bytes": b"\x08\x0a\x42\x3a\x35\xc7\x84\x74\x6b\x8e",
            },
            "_results": {
                "option": TcpOptionTimestamps(
                    tsval=1111111111, tsecr=2222222222
                ),
            },
        },
        {
            "_description": "The TCP Timestamps option minimum length assert.",
            "_args": {
                "bytes": b"\x08",
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The TCP Timestamps option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff\x0a\x00\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The TCP Timestamps option length integrity check (I).",
            "_args": {
                "bytes": b"\x08\x09\x00\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "error": TcpIntegrityError,
                "error_message": "Invalid Timestamps option length (I).",
            },
        },
        {
            "_description": "The TCP Timestamps option length integrity check (II).",
            "_args": {
                "bytes": b"\x08\x0a\x00\x00\x00\x00\x00\x00\x00",
            },
            "_results": {
                "error": TcpIntegrityError,
                "error_message": "Invalid Timestamps option length (II).",
            },
        },
    ]
)
class TestTcpOptionTimestampsParser(TestCase):
    """
    The TCP Timestamps option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp_option_timestamps__from_bytes(self) -> None:
        """
        Ensure the TCP Timestamps option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            tcp_option_timestamps = TcpOptionTimestamps.from_bytes(
                self._args["bytes"]
            )

            self.assertEqual(
                tcp_option_timestamps,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                TcpOptionTimestamps.from_bytes(self._args["bytes"])

            if "error_message" in self._results:
                self.assertEqual(
                    str(error.exception),
                    f"[INTEGRITY ERROR][TCP] {self._results['error_message']}",
                )
