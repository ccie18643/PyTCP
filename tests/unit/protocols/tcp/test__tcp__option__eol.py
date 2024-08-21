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
This module contains tests for the TCP Eol (End of Option List) option code.

tests/unit/protocols/tcp/test__tcp__option__eol.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.tcp.options.tcp_option__eol import TcpOptionEol


class TestTcpOptionEolAsserts(TestCase):
    """
    The TCP Eol option constructor argument assert tests.
    """

    # Currently the TCP Eol option does not have any constructor argument asserts.


@parameterized_class(
    [
        {
            "_description": "The TCP Eol option.",
            "_args": {},
            "_results": {
                "__len__": 1,
                "__str__": "eol",
                "__repr__": "TcpOptionEol()",
                "__bytes__": b"\x00",
            },
        },
    ]
)
class TestTcpOptionEolAssembler(TestCase):
    """
    The TCP Eol option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the TCP Eol option object with testcase arguments.
        """

        self._tcp_option_eol = TcpOptionEol(**self._args)

    def test__tcp__option__eol__len(self) -> None:
        """
        Ensure the TCP Eol option '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._tcp_option_eol),
            self._results["__len__"],
        )

    def test__tcp__option__eol__str(self) -> None:
        """
        Ensure the TCP Eol option '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._tcp_option_eol),
            self._results["__str__"],
        )

    def test__tcp__option__eol__repr(self) -> None:
        """
        Ensure the TCP Eol option '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._tcp_option_eol),
            self._results["__repr__"],
        )

    def test__tcp__option__eol__bytes(self) -> None:
        """
        Ensure the TCP Eol option '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._tcp_option_eol),
            self._results["__bytes__"],
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Eol option.",
            "_args": {
                "bytes": b"\x00",
            },
            "_results": {
                "option": TcpOptionEol(),
            },
        },
        {
            "_description": "The TCP Eol option minimum length assert.",
            "_args": {
                "bytes": b"",
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The TCP Eol option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff",
            },
            "_results": {
                "error": AssertionError,
            },
        },
    ]
)
class TestTcpOptionEolParser(TestCase):
    """
    The TCP Eol option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp__option__eol__from_bytes(self) -> None:
        """
        Ensure the TCP Eol option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            tcp_option_eol = TcpOptionEol.from_bytes(self._args["bytes"])

            self.assertEqual(
                tcp_option_eol,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]):
                TcpOptionEol.from_bytes(self._args["bytes"])
