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
Module contains tests for the DHCPv4 Renewal (T1) Time Value
option (RFC 2132 §9.7) wire-format codec.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__renewal_time.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    UINT_32__MAX,
    UINT_32__MIN,
    Dhcp4IntegrityError,
    Dhcp4OptionRenewalTime,
    Dhcp4OptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp4OptionRenewalTimeAsserts(TestCase):
    """
    The DHCPv4 Renewal Time option constructor argument assert tests.
    """

    def test__dhcp4__option__renewal_time__over_max(self) -> None:
        """
        Ensure the constructor raises when 'renewal_time' exceeds
        UINT_32__MAX.

        Reference: RFC 2132 §9.7 (32-bit unsigned value).
        """

        value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRenewalTime(value)

        self.assertEqual(
            str(error.exception),
            f"The 'renewal_time' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected 'renewal_time' over-max assert message.",
        )

    def test__dhcp4__option__renewal_time__under_min(self) -> None:
        """
        Ensure the constructor raises when 'renewal_time' is below
        zero.

        Reference: RFC 2132 §9.7 (32-bit unsigned value).
        """

        value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRenewalTime(value)

        self.assertEqual(
            str(error.exception),
            f"The 'renewal_time' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected 'renewal_time' under-min assert message.",
        )


@parameterized_class(
    [
        {
            "_description": "Zero seconds.",
            "_args": [0],
            "_results": {
                "__len__": 6,
                "__str__": "renewal_time 0",
                "__repr__": "Dhcp4OptionRenewalTime(renewal_time=0)",
                "__bytes__": b"\x3a\x04\x00\x00\x00\x00",
                "renewal_time": 0,
            },
        },
        {
            "_description": "1800 seconds (typical T1 for 3600 s lease).",
            "_args": [1800],
            "_results": {
                "__len__": 6,
                "__str__": "renewal_time 1800",
                "__repr__": "Dhcp4OptionRenewalTime(renewal_time=1800)",
                "__bytes__": b"\x3a\x04\x00\x00\x07\x08",
                "renewal_time": 1800,
            },
        },
        {
            "_description": "UINT_32__MAX upper bound.",
            "_args": [0xFFFFFFFF],
            "_results": {
                "__len__": 6,
                "__str__": "renewal_time 4294967295",
                "__repr__": "Dhcp4OptionRenewalTime(renewal_time=4294967295)",
                "__bytes__": b"\x3a\x04\xff\xff\xff\xff",
                "renewal_time": 0xFFFFFFFF,
            },
        },
    ]
)
class TestDhcp4OptionRenewalTimeAssembler(TestCase):
    """
    The DHCPv4 Renewal Time option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the SUT.
        """

        self._option = Dhcp4OptionRenewalTime(*self._args)

    def test__dhcp4__option__renewal_time__bytes(self) -> None:
        """
        Ensure 'bytes(option)' matches the wire-format sequence.

        Reference: RFC 2132 §9.7 (wire-format diagram).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__dhcp4__option__renewal_time__from_buffer(self) -> None:
        """
        Ensure 'from_buffer' round-trips back to the original
        'renewal_time' value.

        Reference: RFC 2132 §9.7 (wire-format round-trip).
        """

        parsed = Dhcp4OptionRenewalTime.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            parsed.renewal_time,
            self._results["renewal_time"],
            msg=f"Unexpected round-trip renewal_time for case: {self._description}",
        )

    def test__dhcp4__option__renewal_time__str(self) -> None:
        """
        Ensure '__str__' renders the documented short form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )


class TestDhcp4OptionRenewalTimeIntegrity(TestCase):
    """
    The DHCPv4 Renewal Time option integrity-check tests.
    """

    def test__dhcp4__option__renewal_time__bad_length(self) -> None:
        """
        Ensure 'from_buffer' raises when the TLV's length byte
        does not equal the documented 4-byte value width.

        Reference: RFC 2132 §9.7 (length = 4).
        """

        bad_buffer = b"\x3a\x05\x00\x00\x07\x08\x00"  # length=5 (wrong; must be 4)

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionRenewalTime.from_buffer(bad_buffer)

        self.assertIn(
            "length value must be 6 bytes",
            str(error.exception),
            msg="Bad-length Renewal Time option must raise Dhcp4IntegrityError.",
        )

    def test__dhcp4__option__renewal_time__wrong_type(self) -> None:
        """
        Ensure 'from_buffer' refuses a buffer whose first byte is
        not 'Dhcp4OptionType.RENEWAL_TIME'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        bad_buffer = b"\x33\x04\x00\x00\x07\x08"  # type=51 (Lease Time)

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRenewalTime.from_buffer(bad_buffer)

        self.assertIn(
            f"option type must be {Dhcp4OptionType.RENEWAL_TIME!r}",
            str(error.exception),
            msg="Wrong-type buffer must trigger the type assertion.",
        )
