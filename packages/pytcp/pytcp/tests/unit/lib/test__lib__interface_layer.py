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
This module contains tests for the 'InterfaceLayer' enum.

pytcp/tests/unit/lib/test__lib__interface_layer.py

ver 3.0.10
"""

from enum import Enum
from unittest import TestCase

from pytcp.lib.interface_layer import InterfaceLayer


class TestInterfaceLayer(TestCase):
    """
    The 'InterfaceLayer' enum tests.
    """

    def test__interface_layer__is_enum_subclass(self) -> None:
        """
        Ensure 'InterfaceLayer' is a plain 'Enum' subclass (not an 'IntEnum'),
        so its members compare by identity only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(InterfaceLayer, Enum),
            msg="InterfaceLayer must derive from enum.Enum.",
        )

    def test__interface_layer__has_exactly_l2_l3_and_loopback(self) -> None:
        """
        Ensure the enum exposes exactly the three canonical members 'L2'
        (TAP), 'L3' (TUN), and 'LOOPBACK' (lo), so an accidental addition
        is caught immediately.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            {member.name for member in InterfaceLayer},
            {"L2", "L3", "LOOPBACK"},
            msg="InterfaceLayer must expose exactly 'L2', 'L3', and 'LOOPBACK'.",
        )

    def test__interface_layer__l2_value(self) -> None:
        """
        Ensure 'InterfaceLayer.L2' carries the first 'auto()' value so the
        enum's ordering stays stable across releases.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            InterfaceLayer.L2.value,
            1,
            msg="InterfaceLayer.L2 must be the first auto() value (1).",
        )

    def test__interface_layer__l3_value(self) -> None:
        """
        Ensure 'InterfaceLayer.L3' carries the second 'auto()' value so the
        enum's ordering stays stable across releases.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            InterfaceLayer.L3.value,
            2,
            msg="InterfaceLayer.L3 must be the second auto() value (2).",
        )

    def test__interface_layer__loopback_value(self) -> None:
        """
        Ensure 'InterfaceLayer.LOOPBACK' carries the third 'auto()' value so
        the enum's ordering stays stable across releases.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            InterfaceLayer.LOOPBACK.value,
            3,
            msg="InterfaceLayer.LOOPBACK must be the third auto() value (3).",
        )

    def test__interface_layer__members_are_distinct(self) -> None:
        """
        Ensure the 'L2', 'L3', and 'LOOPBACK' members are distinct enum
        singletons so code that branches on identity never collapses any
        two layers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len({InterfaceLayer.L2, InterfaceLayer.L3, InterfaceLayer.LOOPBACK}),
            3,
            msg="InterfaceLayer.L2, L3, and LOOPBACK must be distinct singletons.",
        )

    def test__interface_layer__l2_lookup_by_name(self) -> None:
        """
        Ensure 'InterfaceLayer['L2']' resolves to the same singleton as
        the attribute access, so reflective lookups stay consistent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            InterfaceLayer["L2"],
            InterfaceLayer.L2,
            msg="InterfaceLayer['L2'] must return the same singleton as the attribute.",
        )

    def test__interface_layer__l3_lookup_by_name(self) -> None:
        """
        Ensure 'InterfaceLayer['L3']' resolves to the same singleton as
        the attribute access, so reflective lookups stay consistent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            InterfaceLayer["L3"],
            InterfaceLayer.L3,
            msg="InterfaceLayer['L3'] must return the same singleton as the attribute.",
        )

    def test__interface_layer__loopback_lookup_by_name(self) -> None:
        """
        Ensure 'InterfaceLayer['LOOPBACK']' resolves to the same singleton
        as the attribute access, so reflective lookups stay consistent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            InterfaceLayer["LOOPBACK"],
            InterfaceLayer.LOOPBACK,
            msg="InterfaceLayer['LOOPBACK'] must return the same singleton as the attribute.",
        )
