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
This module contains tests for the Raw protocol packet assembling functionality.

tests/unit/protocols/raw/test__raw__assembler__packets.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.tracker import Tracker
from pytcp.protocols.raw.raw__assembler import RawAssembler


@parameterized_class(
    [
        {
            "_description": "Raw packet with no payload.",
            "_args": {
                "raw__payload": b"",
            },
            "_results": {
                "__len__": 0,
                "__str__": "Raw, len 0",
                "__repr__": "RawAssembler(raw__payload=b'')",
                "__bytes__": b"",
                "payload": b"",
            },
        },
    ]
)
class TestRawAssemblerOperation(TestCase):
    """
    The Raw packet assembler operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the Raw packet assembler object with testcase arguments.
        """

        self._raw__assembler = RawAssembler(**self._args)

    def test__raw__assembler__len(self) -> None:
        """
        Ensure the Raw packet assembler '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._raw__assembler),
            self._results["__len__"],
        )

    def test__raw__assembler__str(self) -> None:
        """
        Ensure the Raw packet assembler '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._raw__assembler),
            self._results["__str__"],
        )

    def test__raw__assembler__repr(self) -> None:
        """
        Ensure the Raw packet assembler '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._raw__assembler),
            self._results["__repr__"],
        )

    def test__raw__assembler__bytes(self) -> None:
        """
        Ensure the Raw packet assembler '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._raw__assembler),
            self._results["__bytes__"],
        )

    def test__udp__assembler__payload(self) -> None:
        """
        Ensure the Raw packet assembler 'payload' property returns a correct
        value.
        """

        self.assertEqual(
            self._raw__assembler.payload,
            (self._results["payload"]),
        )


class TestRawAssemblerMisc(TestCase):
    """
    The Raw packet assembler miscellaneous functions tests.
    """

    def test__raw__assembler__echo_tracker(self) -> None:
        """
        Ensure the Raw packet assembler 'tracker' property returns
        the correct value.
        """

        echo_tracker = Tracker(prefix="RX")

        raw__assembler = RawAssembler(echo_tracker=echo_tracker)

        self.assertEqual(
            raw__assembler.tracker.echo_tracker,
            echo_tracker,
        )
