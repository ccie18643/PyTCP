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
This module contains tests for the 'NameEnum' base class.

pytcp/tests/unit/lib/test__lib__name_enum.py

ver 3.0.8
"""

from enum import IntEnum, auto
from typing import Any
from unittest import TestCase

from pytcp.lib.name_enum import NameEnum
from pytcp.tests.lib.parameterized import parameterized_class


class _SampleNameEnum(NameEnum):
    """
    A minimal 'NameEnum' subclass used only by the tests in this module.
    """

    ALPHA = auto()
    BETA = auto()
    GAMMA = 42


class TestNameEnumSubclassing(TestCase):
    """
    The 'NameEnum' subclassing / identity tests.
    """

    def test__name_enum__is_int_enum_subclass(self) -> None:
        """
        Ensure 'NameEnum' derives from 'IntEnum' so its members retain
        full integer semantics (comparison, arithmetic, JSON serialization).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(NameEnum, IntEnum),
            msg="NameEnum must derive from enum.IntEnum.",
        )

    def test__name_enum__subclass_member_is_int(self) -> None:
        """
        Ensure members of a 'NameEnum' subclass are still 'int' instances,
        so downstream code can compare them against raw wire-level integers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            _SampleNameEnum.ALPHA,
            int,
            msg="A NameEnum member must remain an 'int' instance (IntEnum contract).",
        )


@parameterized_class(
    [
        {
            "_description": "The first auto() member.",
            "_member": _SampleNameEnum.ALPHA,
            "_results": {
                "__str__": "ALPHA",
                "name": "ALPHA",
                "value": 1,
            },
        },
        {
            "_description": "The second auto() member.",
            "_member": _SampleNameEnum.BETA,
            "_results": {
                "__str__": "BETA",
                "name": "BETA",
                "value": 2,
            },
        },
        {
            "_description": "An explicit-value member.",
            "_member": _SampleNameEnum.GAMMA,
            "_results": {
                "__str__": "GAMMA",
                "name": "GAMMA",
                "value": 42,
            },
        },
    ]
)
class TestNameEnumStr(TestCase):
    """
    The 'NameEnum.__str__()' happy-path tests.
    """

    _description: str
    _member: _SampleNameEnum
    _results: dict[str, Any]

    def test__name_enum__str(self) -> None:
        """
        Ensure 'NameEnum.__str__()' returns the member's own 'name'
        attribute verbatim (not the stdlib 'ClassName.MEMBER' form).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._member),
            self._results["__str__"],
            msg=f"Unexpected str() output for case: {self._description}",
        )

    def test__name_enum__name(self) -> None:
        """
        Ensure the member's 'name' attribute equals the expected label,
        matching the string that '__str__()' is required to return.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._member.name,
            self._results["name"],
            msg=f"Unexpected .name for case: {self._description}",
        )

    def test__name_enum__value(self) -> None:
        """
        Ensure the member's integer 'value' attribute equals the expected
        integer, so a future reordering of auto() members would be caught.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._member.value,
            self._results["value"],
            msg=f"Unexpected .value for case: {self._description}",
        )


class TestNameEnumStrDiffersFromDefault(TestCase):
    """
    The 'NameEnum.__str__()' vs stdlib 'IntEnum.__str__()' comparison tests.
    """

    def test__name_enum__str_does_not_use_qualified_form(self) -> None:
        """
        Ensure the overridden 'NameEnum.__str__()' returns only the member
        name, not the '<ClassName>.<MEMBER>' form produced by the stdlib
        'IntEnum' default. Guards against an accidental override removal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotIn(
            ".",
            str(_SampleNameEnum.ALPHA),
            msg="NameEnum.__str__() must not contain a '.' separator; the "
            "stdlib 'ClassName.MEMBER' form is explicitly overridden.",
        )
