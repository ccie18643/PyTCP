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
This module contains tests for the TCP Nop (No Operation) option code.

tests/unit/protocols/tcp/test__tcp__option__nop.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.protocols.tcp.options.tcp_option__nop import TcpOptionNop


class TestTcpOptionNopAsserts(TestCase):
    """
    The TCP Nop option constructor argument assert tests.
    """

    # Currently the TCP Nop option does not have any constructor argument asserts.


@parameterized_class(
    [
        {
            "_description": "The TCP Nop option.",
            "_args": {},
            "_results": {
                "__len__": 1,
                "__str__": "nop",
                "__repr__": "TcpOptionNop()",
                "__bytes__": b"\x01",
            },
        },
    ]
)
class TestTcpOptionNopAssembler(TestCase):
    """
    The TCP Nop option assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the TCP Nop option object with testcase arguments.
        """

        self._tcp_option_nop = TcpOptionNop(**self._args)

    def test__tcp_option_nop__len(self) -> None:
        """
        Ensure the TCP Nop option '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._tcp_option_nop),
            self._results["__len__"],
        )

    def test__tcp_option_nop__str(self) -> None:
        """
        Ensure the TCP Nop option '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._tcp_option_nop),
            self._results["__str__"],
        )

    def test__tcp_option_nop__repr(self) -> None:
        """
        Ensure the TCP Nop option '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._tcp_option_nop),
            self._results["__repr__"],
        )

    def test__tcp_option_nop__bytes(self) -> None:
        """
        Ensure the TCP Nop option '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._tcp_option_nop),
            self._results["__bytes__"],
        )


@parameterized_class(
    [
        {
            "_description": "The TCP Nop option.",
            "_args": {
                "bytes": b"\x01",
            },
            "_results": {
                "option": TcpOptionNop(),
            },
        },
        {
            "_description": "The TCP Nop option minimum length assert.",
            "_args": {
                "bytes": b"",
            },
            "_results": {
                "error": AssertionError,
            },
        },
        {
            "_description": "The TCP Nop option incorrect 'type' field assert.",
            "_args": {
                "bytes": b"\xff",
            },
            "_results": {
                "error": AssertionError,
            },
        },
    ]
)
class TestTcpOptionNopParser(TestCase):
    """
    The TCP Nop option parser tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__tcp_option_nop__from_bytes(self) -> None:
        """
        Ensure the TCP Nop option parser creates the proper option object
        or throws assertion error.
        """

        if "option" in self._results:
            tcp_option_nop = TcpOptionNop.from_bytes(self._args["bytes"])

            self.assertEqual(
                tcp_option_nop,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]):
                TcpOptionNop.from_bytes(self._args["bytes"])
