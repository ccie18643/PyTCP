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
This module contains tests for the 'Buffer' type alias.

net_addr/tests/unit/test__buffer.py

ver 3.0.10
"""

from typing import TypeAliasType, get_args
from unittest import TestCase

from net_addr import Buffer


class TestBuffer(TestCase):
    """
    The Buffer type alias tests.
    """

    def test__buffer__is_type_alias(self) -> None:
        """
        Ensure the 'Buffer' is a PEP 695 type alias.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            Buffer,
            TypeAliasType,
            msg="'Buffer' must be defined as a PEP 695 type alias.",
        )

    def test__buffer__name(self) -> None:
        """
        Ensure the 'Buffer' type alias exposes the expected name.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            Buffer.__name__,
            "Buffer",
            msg="'Buffer' alias must be named 'Buffer'.",
        )

    def test__buffer__members(self) -> None:
        """
        Ensure the 'Buffer' type alias resolves to the bytes/bytearray/memoryview union.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            set(get_args(Buffer.__value__)),
            {bytes, bytearray, memoryview},
            msg="'Buffer' alias must cover bytes, bytearray and memoryview.",
        )

    def test__buffer__accepts_bytes(self) -> None:
        """
        Ensure 'bytes' value satisfies the 'Buffer' type at runtime.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        value: Buffer = b"\x01\x02\x03"
        self.assertIsInstance(
            value,
            get_args(Buffer.__value__),
            msg="'bytes' must be a valid Buffer value.",
        )

    def test__buffer__accepts_bytearray(self) -> None:
        """
        Ensure 'bytearray' value satisfies the 'Buffer' type at runtime.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        value: Buffer = bytearray(b"\x01\x02\x03")
        self.assertIsInstance(
            value,
            get_args(Buffer.__value__),
            msg="'bytearray' must be a valid Buffer value.",
        )

    def test__buffer__accepts_memoryview(self) -> None:
        """
        Ensure 'memoryview' value satisfies the 'Buffer' type at runtime.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        value: Buffer = memoryview(b"\x01\x02\x03")
        self.assertIsInstance(
            value,
            get_args(Buffer.__value__),
            msg="'memoryview' must be a valid Buffer value.",
        )

    def test__buffer__rejects_foreign_type(self) -> None:
        """
        Ensure that foreign types like 'str' and 'int' are not part of the
        'Buffer' type alias.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotIsInstance(
            "hello",
            get_args(Buffer.__value__),
            msg="'str' must not be a valid Buffer value.",
        )
        self.assertNotIsInstance(
            12345,
            get_args(Buffer.__value__),
            msg="'int' must not be a valid Buffer value.",
        )
