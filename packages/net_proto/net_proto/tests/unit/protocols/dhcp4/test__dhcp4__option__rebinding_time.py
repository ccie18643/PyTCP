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
Module contains tests for the DHCPv4 Rebinding (T2) Time Value
option (RFC 2132 §9.8) wire-format codec.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__rebinding_time.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    UINT_32__MAX,
    UINT_32__MIN,
    Dhcp4IntegrityError,
    Dhcp4OptionRebindingTime,
    Dhcp4OptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp4OptionRebindingTimeAsserts(TestCase):
    """
    The DHCPv4 Rebinding Time option constructor argument assert tests.
    """

    def test__dhcp4__option__rebinding_time__over_max(self) -> None:
        """
        Ensure the constructor raises when 'rebinding_time' exceeds
        UINT_32__MAX.

        Reference: RFC 2132 §9.8 (32-bit unsigned value).
        """

        value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRebindingTime(value)

        self.assertEqual(
            str(error.exception),
            f"The 'rebinding_time' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected 'rebinding_time' over-max assert message.",
        )

    def test__dhcp4__option__rebinding_time__under_min(self) -> None:
        """
        Ensure the constructor raises when 'rebinding_time' is
        below zero.

        Reference: RFC 2132 §9.8 (32-bit unsigned value).
        """

        value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRebindingTime(value)

        self.assertEqual(
            str(error.exception),
            f"The 'rebinding_time' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected 'rebinding_time' under-min assert message.",
        )


@parameterized_class(
    [
        {
            "_description": "Zero seconds.",
            "_args": [0],
            "_results": {
                "__len__": 6,
                "__str__": "rebinding_time 0",
                "__repr__": "Dhcp4OptionRebindingTime(rebinding_time=0)",
                "__bytes__": b"\x3b\x04\x00\x00\x00\x00",
                "rebinding_time": 0,
            },
        },
        {
            "_description": "3150 seconds (typical T2 for 3600 s lease).",
            "_args": [3150],
            "_results": {
                "__len__": 6,
                "__str__": "rebinding_time 3150",
                "__repr__": "Dhcp4OptionRebindingTime(rebinding_time=3150)",
                "__bytes__": b"\x3b\x04\x00\x00\x0c\x4e",
                "rebinding_time": 3150,
            },
        },
        {
            "_description": "UINT_32__MAX upper bound.",
            "_args": [0xFFFFFFFF],
            "_results": {
                "__len__": 6,
                "__str__": "rebinding_time 4294967295",
                "__repr__": "Dhcp4OptionRebindingTime(rebinding_time=4294967295)",
                "__bytes__": b"\x3b\x04\xff\xff\xff\xff",
                "rebinding_time": 0xFFFFFFFF,
            },
        },
    ]
)
class TestDhcp4OptionRebindingTimeAssembler(TestCase):
    """
    The DHCPv4 Rebinding Time option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the SUT.
        """

        self._option = Dhcp4OptionRebindingTime(*self._args)

    def test__dhcp4__option__rebinding_time__bytes(self) -> None:
        """
        Ensure 'bytes(option)' matches the wire-format sequence.

        Reference: RFC 2132 §9.8 (wire-format diagram).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__dhcp4__option__rebinding_time__from_buffer(self) -> None:
        """
        Ensure 'from_buffer' round-trips back to the original
        'rebinding_time' value.

        Reference: RFC 2132 §9.8 (wire-format round-trip).
        """

        parsed = Dhcp4OptionRebindingTime.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            parsed.rebinding_time,
            self._results["rebinding_time"],
            msg=f"Unexpected round-trip rebinding_time for case: {self._description}",
        )

    def test__dhcp4__option__rebinding_time__str(self) -> None:
        """
        Ensure '__str__' renders the documented short form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )


class TestDhcp4OptionRebindingTimeIntegrity(TestCase):
    """
    The DHCPv4 Rebinding Time option integrity-check tests.
    """

    def test__dhcp4__option__rebinding_time__bad_length(self) -> None:
        """
        Ensure 'from_buffer' raises when the TLV's length byte
        does not equal the documented 4-byte value width.

        Reference: RFC 2132 §9.8 (length = 4).
        """

        bad_buffer = b"\x3b\x05\x00\x00\x0c\x4e\x00"  # length=5 (wrong; must be 4)

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionRebindingTime.from_buffer(bad_buffer)

        self.assertIn(
            "length value must be 6 bytes",
            str(error.exception),
            msg="Bad-length Rebinding Time option must raise Dhcp4IntegrityError.",
        )

    def test__dhcp4__option__rebinding_time__wrong_type(self) -> None:
        """
        Ensure 'from_buffer' refuses a buffer whose first byte is
        not 'Dhcp4OptionType.REBINDING_TIME'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        bad_buffer = b"\x33\x04\x00\x00\x0c\x4e"  # type=51 (Lease Time)

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRebindingTime.from_buffer(bad_buffer)

        self.assertIn(
            f"option type must be {Dhcp4OptionType.REBINDING_TIME!r}",
            str(error.exception),
            msg="Wrong-type buffer must trigger the type assertion.",
        )
