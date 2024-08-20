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
This module contains tests for the TCP Wscale (Window Scale) option code.

tests/unit/protocols/tcp/test__tcp__option__wscale.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.int_checks import UINT_8__MIN
from pytcp.protocols.tcp.options.tcp_option__wscale import (
    TCP__OPTION_WSCALE__MAX_VALUE,
    TcpOptionWscale,
)
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError


class TestTcpOptionWscaleAsserts(TestCase):
    """
    The TCP Wscale option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the TCP Wscale option constructor.
        """

        self._option_args = {
            "wscale": 0,
        }

    def test__tcp__option__wscale__wscale__under_min(self) -> None:
        """
        Ensure the TCP Wscale option constructor raises an exception when the
        provided 'wscale' argument is lower than the minimum supported value.
        """

        self._option_args["wscale"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionWscale(**self._option_args)

        self.assertEqual(
            str(error.exception),
            "The 'wscale' field must be a 8-bit unsigned integer less than "
            f"or equal to {TCP__OPTION_WSCALE__MAX_VALUE}. Got: {value}",
        )

    def test__tcp__option__wscale__wscale__over_max(self) -> None:
        """
        Ensure the TCP Wscale option constructor raises an exception when the
        provided 'wscale' argument is higher than the maximum supported value.
        """

        self._option_args["wscale"] = value = TCP__OPTION_WSCALE__MAX_VALUE + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionWscale(**self._option_args)

        self.assertEqual(
            str(error.exception),
            "The 'wscale' field must be a 8-bit unsigned integer less than "
            f"or equal to {TCP__OPTION_WSCALE__MAX_VALUE}. Got: {value}",
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Wscale option.",
            "_args": {
                "wscale": 14,
            },
            "_results": {
                "__len__": 3,
                "__str__": "wscale 14",
                "__repr__": "TcpOptionWscale(wscale=14)",
                "__bytes__": b"\x03\x03\x0e",
                "wscale": 14,
            },
        },
    ]
)
class TestTcpOptionWscaleAssembler(TestCase):
    """
    The TCP Wscale option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the TCP Wscale option object with testcase arguments.
        """

        self._tcp_option_wscale = TcpOptionWscale(**self._args)

    def test__tcp_option_wscale__len(self) -> None:
        """
        Ensure the TCP Wscale option '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._tcp_option_wscale),
            self._results["__len__"],
        )

    def test__tcp_option_wscale__str(self) -> None:
        """
        Ensure the TCP Wscale option '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._tcp_option_wscale),
            self._results["__str__"],
        )

    def test__tcp_option_wscale__repr(self) -> None:
        """
        Ensure the TCP Wscale option '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._tcp_option_wscale),
            self._results["__repr__"],
        )

    def test__tcp_option_wscale__bytes(self) -> None:
        """
        Ensure the TCP Wscale option '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._tcp_option_wscale),
            self._results["__bytes__"],
        )

    def test__tcp_option_wscale__wscale(self) -> None:
        """
        Ensure the TCP Wscale option 'wscale' property returns a correct value.
        """

        self.assertEqual(
            self._tcp_option_wscale.wscale,
            self._results["wscale"],
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Wscale option.",
            "_args": {
                "bytes": b"\x03\x03\x0e",
            },
            "_results": {
                "option": TcpOptionWscale(wscale=14),
            },
        },
        {
            "_description": "The TCP Wscale option minimum length assert.",
            "_args": {
                "bytes": b"\x03",
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The TCP Wscale option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff\03\x0e",
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The TCP Wscale option length integrity check (I).",
            "_args": {
                "bytes": b"\x03\02\x0e",
            },
            "_results": {
                "error": TcpIntegrityError,
                "error_message": "Invalid Wscale option length (I).",
            },
        },
        {
            "_description": "The TCP Wscale option length integrity check (II).",
            "_args": {
                "bytes": b"\x03\03",
            },
            "_results": {
                "error": TcpIntegrityError,
                "error_message": "Invalid Wscale option length (II).",
            },
        },
        {
            "_description": "The TCP Wscale option maximum value correction.",
            "_args": {
                "bytes": b"\x03\x03\xff",
            },
            "_results": {
                "option": TcpOptionWscale(wscale=14),
            },
        },
    ]
)
class TestTcpOptionWscaleParser(TestCase):
    """
    The TCP Wscale option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp_option_wscale__from_bytes(self) -> None:
        """
        Ensure the TCP Wscale option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            tcp_option_wscale = TcpOptionWscale.from_bytes(self._args["bytes"])

            self.assertEqual(
                tcp_option_wscale,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                TcpOptionWscale.from_bytes(self._args["bytes"])

            if "error_message" in self._results:
                self.assertEqual(
                    str(error.exception),
                    f"[INTEGRITY ERROR][TCP] {self._results['error_message']}",
                )
