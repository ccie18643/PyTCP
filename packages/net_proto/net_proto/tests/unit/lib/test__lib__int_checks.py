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
This module contains tests for integer range checks and alignment helpers.

net_proto/tests/unit/lib/test__lib__int_checks.py

ver 3.0.8
"""

from typing import Any, Callable
from unittest import TestCase

from net_proto.lib.int_checks import (
    UINT_2__MAX,
    UINT_2__MIN,
    UINT_4__MAX,
    UINT_4__MIN,
    UINT_6__MAX,
    UINT_6__MIN,
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_13__MAX,
    UINT_13__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_20__MAX,
    UINT_20__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
    is_4_byte_alligned,
    is_8_byte_alligned,
    is_uint2,
    is_uint4,
    is_uint6,
    is_uint8,
    is_uint13,
    is_uint16,
    is_uint20,
    is_uint32,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestNetProtoLibIntChecksConstants(TestCase):
    """
    The NetProto lib int_checks constants tests.
    """

    def test__net_proto__lib__int_checks__uint2_constants(self) -> None:
        """
        Ensure the UINT_2 constants expose the expected range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(UINT_2__MIN, 0x00)
        self.assertEqual(UINT_2__MAX, 0x03)

    def test__net_proto__lib__int_checks__uint4_constants(self) -> None:
        """
        Ensure the UINT_4 constants expose the expected range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(UINT_4__MIN, 0x0)
        self.assertEqual(UINT_4__MAX, 0xF)

    def test__net_proto__lib__int_checks__uint6_constants(self) -> None:
        """
        Ensure the UINT_6 constants expose the expected range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(UINT_6__MIN, 0x00)
        self.assertEqual(UINT_6__MAX, 0x3F)

    def test__net_proto__lib__int_checks__uint8_constants(self) -> None:
        """
        Ensure the UINT_8 constants expose the expected range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(UINT_8__MIN, 0x00)
        self.assertEqual(UINT_8__MAX, 0xFF)

    def test__net_proto__lib__int_checks__uint13_constants(self) -> None:
        """
        Ensure the UINT_13 constants expose the expected range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(UINT_13__MIN, 0x0000)
        self.assertEqual(UINT_13__MAX, 0x1FFF)

    def test__net_proto__lib__int_checks__uint16_constants(self) -> None:
        """
        Ensure the UINT_16 constants expose the expected range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(UINT_16__MIN, 0x0000)
        self.assertEqual(UINT_16__MAX, 0xFFFF)

    def test__net_proto__lib__int_checks__uint20_constants(self) -> None:
        """
        Ensure the UINT_20 constants expose the expected range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(UINT_20__MIN, 0x00000)
        self.assertEqual(UINT_20__MAX, 0xFFFFF)

    def test__net_proto__lib__int_checks__uint32_constants(self) -> None:
        """
        Ensure the UINT_32 constants expose the expected range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(UINT_32__MIN, 0x00000000)
        self.assertEqual(UINT_32__MAX, 0xFFFFFFFF)


@parameterized_class(
    [
        {
            "_description": "is_uint2: below the min range.",
            "_checker": is_uint2,
            "_min": UINT_2__MIN,
            "_max": UINT_2__MAX,
        },
        {
            "_description": "is_uint4: below the min range.",
            "_checker": is_uint4,
            "_min": UINT_4__MIN,
            "_max": UINT_4__MAX,
        },
        {
            "_description": "is_uint6: below the min range.",
            "_checker": is_uint6,
            "_min": UINT_6__MIN,
            "_max": UINT_6__MAX,
        },
        {
            "_description": "is_uint8: below the min range.",
            "_checker": is_uint8,
            "_min": UINT_8__MIN,
            "_max": UINT_8__MAX,
        },
        {
            "_description": "is_uint13: below the min range.",
            "_checker": is_uint13,
            "_min": UINT_13__MIN,
            "_max": UINT_13__MAX,
        },
        {
            "_description": "is_uint16: below the min range.",
            "_checker": is_uint16,
            "_min": UINT_16__MIN,
            "_max": UINT_16__MAX,
        },
        {
            "_description": "is_uint20: below the min range.",
            "_checker": is_uint20,
            "_min": UINT_20__MIN,
            "_max": UINT_20__MAX,
        },
        {
            "_description": "is_uint32: below the min range.",
            "_checker": is_uint32,
            "_min": UINT_32__MIN,
            "_max": UINT_32__MAX,
        },
    ]
)
class TestNetProtoLibIntChecksUintBoundaries(TestCase):
    """
    The NetProto lib int_checks unsigned-integer boundary tests.
    """

    _description: str
    _checker: Callable[[int], bool]
    _min: int
    _max: int

    def test__net_proto__lib__int_checks__uint__min(self) -> None:
        """
        Ensure the checker returns True at the minimum value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            type(self)._checker(self._min),
            msg=f"{self._description}: minimum value must pass the check.",
        )

    def test__net_proto__lib__int_checks__uint__max(self) -> None:
        """
        Ensure the checker returns True at the maximum value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            type(self)._checker(self._max),
            msg=f"{self._description}: maximum value must pass the check.",
        )

    def test__net_proto__lib__int_checks__uint__below_min(self) -> None:
        """
        Ensure the checker returns False one below the minimum value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            type(self)._checker(self._min - 1),
            msg=f"{self._description}: value below the minimum must fail the check.",
        )

    def test__net_proto__lib__int_checks__uint__above_max(self) -> None:
        """
        Ensure the checker returns False one above the maximum value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            type(self)._checker(self._max + 1),
            msg=f"{self._description}: value above the maximum must fail the check.",
        )

    def test__net_proto__lib__int_checks__uint__midpoint(self) -> None:
        """
        Ensure the checker returns True for a value inside the range.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        midpoint = (self._min + self._max) // 2
        self.assertTrue(
            type(self)._checker(midpoint),
            msg=f"{self._description}: midpoint value must pass the check.",
        )


@parameterized_class(
    [
        {
            "_description": "Check alignment for 0.",
            "_args": [0],
            "_results": {"is_4_byte_alligned": True, "is_8_byte_alligned": True},
        },
        {
            "_description": "Check alignment for 1.",
            "_args": [1],
            "_results": {"is_4_byte_alligned": False, "is_8_byte_alligned": False},
        },
        {
            "_description": "Check alignment for 2.",
            "_args": [2],
            "_results": {"is_4_byte_alligned": False, "is_8_byte_alligned": False},
        },
        {
            "_description": "Check alignment for 3.",
            "_args": [3],
            "_results": {"is_4_byte_alligned": False, "is_8_byte_alligned": False},
        },
        {
            "_description": "Check alignment for 4.",
            "_args": [4],
            "_results": {"is_4_byte_alligned": True, "is_8_byte_alligned": False},
        },
        {
            "_description": "Check alignment for 7.",
            "_args": [7],
            "_results": {"is_4_byte_alligned": False, "is_8_byte_alligned": False},
        },
        {
            "_description": "Check alignment for 8.",
            "_args": [8],
            "_results": {"is_4_byte_alligned": True, "is_8_byte_alligned": True},
        },
        {
            "_description": "Check alignment for 12.",
            "_args": [12],
            "_results": {"is_4_byte_alligned": True, "is_8_byte_alligned": False},
        },
        {
            "_description": "Check alignment for 16.",
            "_args": [16],
            "_results": {"is_4_byte_alligned": True, "is_8_byte_alligned": True},
        },
        {
            "_description": "Check alignment for 64.",
            "_args": [64],
            "_results": {"is_4_byte_alligned": True, "is_8_byte_alligned": True},
        },
        {
            "_description": "Check alignment for 0xFFFFFFFF.",
            "_args": [0xFFFFFFFF],
            "_results": {"is_4_byte_alligned": False, "is_8_byte_alligned": False},
        },
    ]
)
class TestNetProtoLibIntChecksAlignment(TestCase):
    """
    The NetProto lib int_checks alignment helpers tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__net_proto__lib__int_checks__is_4_byte_alligned(self) -> None:
        """
        Ensure the 'is_4_byte_alligned()' function reports 4-byte alignment correctly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            is_4_byte_alligned(*self._args),
            self._results["is_4_byte_alligned"],
            msg=f"Unexpected 4-byte alignment result for: {self._description}.",
        )

    def test__net_proto__lib__int_checks__is_8_byte_alligned(self) -> None:
        """
        Ensure the 'is_8_byte_alligned()' function reports 8-byte alignment correctly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            is_8_byte_alligned(*self._args),
            self._results["is_8_byte_alligned"],
            msg=f"Unexpected 8-byte alignment result for: {self._description}.",
        )
