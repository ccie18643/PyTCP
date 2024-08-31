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
Module contains tests for the function computing Internet Checksum.

tests/unit/lib/test__lib__internet_checksum.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.inet_cksum import inet_cksum


@parameterized_class(
    [
        {
            "_description": "Compute checksum.",
            "_args": {
                "data": (
                    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                    * 80
                ),
                "init": 0,
            },
            "_results": {"inet_cksum": 0x2D2D},
        },
        {
            "_description": "Compute checksum.",
            "_args": {
                "data": b"\xFF" * 1500,
                "init": 0,
            },
            "_results": {"inet_cksum": 0x0000},
        },
        {
            "_description": "Compute checksum.",
            "_args": {
                "data": b"\x00" * 1500,
                "init": 0,
            },
            "_results": {"inet_cksum": 0xFFFF},
        },
        {
            "_description": "Compute checksum.",
            "_args": {
                "data": b"\xF7\x24\x09" * 100 + b"\x35\x67\x0F\x00" * 250,
                "init": 0,
            },
            "_results": {"inet_cksum": 0xF1E5},
        },
        {
            "_description": "Compute checksum.",
            "_args": {
                "data": (
                    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                    * 80
                ),
                "init": 0x03DF,
            },
            "_results": {"inet_cksum": 0x294E},
        },
        {
            "_description": "Compute checksum.",
            "_args": {
                "data": b"\xFF" * 1500,
                "init": 0x0015,
            },
            "_results": {"inet_cksum": 0xFFEA},
        },
        {
            "_description": "Compute checksum.",
            "_args": {
                "data": b"\x00" * 1500,
                "init": 0xF3FF,
            },
            "_results": {"inet_cksum": 0x0C00},
        },
        {
            "_description": "Compute checksum.",
            "_args": {
                "data": b"\xF7\x24\x09" * 100 + b"\x35\x67\x0F\x00" * 250,
                "init": 0x7314,
            },
            "_results": {"inet_cksum": 0x7ED1},
        },
        {
            "_description": "Compute checksum.",
            "_args": {
                "data": b"\x07" * 9999,
                "init": 0xA3DC,
            },
            "_results": {"inet_cksum": 0x1AE9},
        },
    ]
)
class TestLibInetChecksum(TestCase):
    """
    Internet Checksum tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__lib__inet_cksum(self) -> None:
        """
        Ensure the 'inet_cksum()' function returns the expected checksum.
        """

        self.assertEqual(
            inet_cksum(**self._args),
            self._results["inet_cksum"],
        )
