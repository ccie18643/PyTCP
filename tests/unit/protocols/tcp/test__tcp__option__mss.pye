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
Module contains tests for the TCP Mss (Maximum Segment Size) option code.

tests/unit/protocols/tcp/test__tcp__option__mss.py

ver 3.0.1
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.protocols.tcp.options.tcp_option import TcpOptionType
from pytcp.protocols.tcp.options.tcp_option__mss import (
    TCP__OPTION_MSS__LEN,
    TcpOptionMss,
)
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError


class TestTcpOptionMssAsserts(TestCase):
    """
    The TCP Mss option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the TCP Mss option constructor.
        """

        self._option_args = {
            "mss": 0,
        }

    def test__tcp__option__mss__mss__under_min(self) -> None:
        """
        Ensure the TCP Mss option constructor raises an exception when the
        provided 'mss' argument is lower than the minimum supported value.
        """

        self._option_args["mss"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionMss(**self._option_args)

        self.assertEqual(
            str(error.exception),
            f"The 'mss' field must be a 16-bit unsigned integer. Got: {value}",
        )

    def test__tcp__option__mss__mss__over_max(self) -> None:
        """
        Ensure the TCP Mss option constructor raises an exception when the
        provided 'mss' argument is higher than the maximum supported value.
        """

        self._option_args["mss"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionMss(**self._option_args)

        self.assertEqual(
            str(error.exception),
            f"The 'mss' field must be a 16-bit unsigned integer. Got: {value}",
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Mss option.",
            "_args": {
                "mss": 65535,
            },
            "_results": {
                "__len__": 4,
                "__str__": "mss 65535",
                "__repr__": "TcpOptionMss(mss=65535)",
                "__bytes__": b"\x02\x04\xff\xff",
                "type": TcpOptionType.MSS,
                "len": TCP__OPTION_MSS__LEN,
                "mss": 65535,
            },
        },
    ]
)
class TestTcpOptionMssAssembler(TestCase):
    """
    The TCP Mss option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the TCP Mss option object with testcase arguments.
        """

        self._tcp_option_mss = TcpOptionMss(**self._args)

    def test__tcp__option__mss__len(self) -> None:
        """
        Ensure the TCP Mss option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._tcp_option_mss),
            self._results["__len__"],
        )

    def test__tcp__option__mss__str(self) -> None:
        """
        Ensure the TCP Mss option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._tcp_option_mss),
            self._results["__str__"],
        )

    def test__tcp__option__mss__repr(self) -> None:
        """
        Ensure the TCP Mss option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._tcp_option_mss),
            self._results["__repr__"],
        )

    def test__tcp__option__mss__bytes(self) -> None:
        """
        Ensure the TCP Mss option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._tcp_option_mss),
            self._results["__bytes__"],
        )

    def test__tcp__option__mss__mss(self) -> None:
        """
        Ensure the TCP Mss option 'mss' field contains a correct value.
        """

        self.assertEqual(
            self._tcp_option_mss.mss,
            self._results["mss"],
        )

    def test__tcp__option__mss__type(self) -> None:
        """
        Ensure the TCP Mss option 'type' field contains a correct value.
        """

        self.assertEqual(
            self._tcp_option_mss.type,
            self._results["type"],
        )

    def test__tcp__option__mss__length(self) -> None:
        """
        Ensure the TCP Mss option 'len' field contains a correct value.
        """

        self.assertEqual(
            self._tcp_option_mss.len,
            self._results["len"],
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Mss option.",
            "_args": {
                "bytes": b"\x02\x04\xff\xff",
            },
            "_results": {
                "option": TcpOptionMss(mss=65535),
            },
        },
        {
            "_description": "The TCP Mss option minimum length assert.",
            "_args": {
                "bytes": b"\x02",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the TCP Mss option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The TCP Mss option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff\04\xff\xff",
            },
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The TCP Mss option type must be {TcpOptionType.MSS!r}. "
                    f"Got: {TcpOptionType.from_int(255)!r}"
                ),
            },
        },
        {
            "_description": "The TCP Mss option length integrity check (I).",
            "_args": {
                "bytes": b"\x02\03\xff\xff",
            },
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Mss option length must be "
                    "4 bytes. Got: 3"
                ),
            },
        },
        {
            "_description": "The TCP Mss option length integrity check (II).",
            "_args": {
                "bytes": b"\x02\04\xff",
            },
            "_results": {
                "error": TcpIntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][TCP] The TCP Mss option length must be "
                    "less than or equal to the length of provided bytes "
                    "(3). Got: 4"
                ),
            },
        },
    ]
)
class TestTcpOptionMssParser(TestCase):
    """
    The TCP Mss option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp__option__mss__from_bytes(self) -> None:
        """
        Ensure the TCP Mss option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            tcp_option_mss = TcpOptionMss.from_bytes(
                self._args["bytes"] + b"ZH0PA"
            )

            self.assertEqual(
                tcp_option_mss,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                TcpOptionMss.from_bytes(self._args["bytes"])

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
