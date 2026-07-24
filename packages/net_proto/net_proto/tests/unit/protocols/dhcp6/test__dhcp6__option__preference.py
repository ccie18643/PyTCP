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
This module contains tests for the DHCPv6 Preference option.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__preference.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase

from net_proto import (
    UINT_8__MAX,
    UINT_8__MIN,
    Dhcp6IntegrityError,
    Dhcp6OptionPreference,
    Dhcp6OptionType,
)


class TestDhcp6OptionPreferenceAsserts(TestCase):
    """
    The DHCPv6 Preference option constructor assert tests.
    """

    def test__dhcp6__option__preference__under_min(self) -> None:
        """
        Ensure the constructor raises when 'preference' is below the
        minimum 8-bit value.

        Reference: RFC 8415 §21.8 (Preference option).
        """

        value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionPreference(value)

        self.assertEqual(
            str(error.exception),
            f"The 'preference' field must be an 8-bit unsigned integer. Got: {value}",
            msg="Unexpected under-min assert message.",
        )

    def test__dhcp6__option__preference__over_max(self) -> None:
        """
        Ensure the constructor raises when 'preference' is above the
        maximum 8-bit value.

        Reference: RFC 8415 §21.8 (Preference option).
        """

        value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionPreference(value)

        self.assertEqual(
            str(error.exception),
            f"The 'preference' field must be an 8-bit unsigned integer. Got: {value}",
            msg="Unexpected over-max assert message.",
        )


class TestDhcp6OptionPreferenceAssembler(TestCase):
    """
    The DHCPv6 Preference option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a reference DHCPv6 Preference option (255 — the
        highest-priority short-circuit value).
        """

        self._option = Dhcp6OptionPreference(255)

    def test__dhcp6__option__preference__len(self) -> None:
        """
        Ensure '__len__()' returns the fixed 5-byte option length.

        Reference: RFC 8415 §21.8 (option-len 1 + 4-byte header).
        """

        self.assertEqual(len(self._option), 5, msg="Unexpected option length.")

    def test__dhcp6__option__preference__str(self) -> None:
        """
        Ensure '__str__()' renders the preference value.

        Reference: RFC 8415 §21.8 (Preference option).
        """

        self.assertEqual(str(self._option), "preference 255", msg="Unexpected log string.")

    def test__dhcp6__option__preference__bytes(self) -> None:
        """
        Ensure '__bytes__()' serialises to the option code, length, and
        single preference octet.

        Reference: RFC 8415 §21.8 (OPTION_PREFERENCE = 7, option-len = 1).
        """

        # DHCPv6 Preference option (5 bytes):
        #   Bytes 0-1 : 0x0007 -> option-code OPTION_PREFERENCE
        #   Bytes 2-3 : 0x0001 -> option-len 1
        #   Byte  4   : 0xff   -> pref-value 255
        self.assertEqual(bytes(self._option), b"\x00\x07\x00\x01\xff", msg="Unexpected wire bytes.")


class TestDhcp6OptionPreferenceParser(TestCase):
    """
    The DHCPv6 Preference option parser tests.
    """

    def test__dhcp6__option__preference__from_buffer(self) -> None:
        """
        Ensure 'from_buffer' round-trips the preference value.

        Reference: RFC 8415 §21.8 (Preference option).
        """

        option = Dhcp6OptionPreference.from_buffer(memoryview(b"\x00\x07\x00\x01\x80"))

        self.assertEqual(option.preference, 128, msg="Unexpected parsed preference value.")
        self.assertIs(option.type, Dhcp6OptionType.PREFERENCE, msg="Unexpected parsed option type.")

    def test__dhcp6__option__preference__from_buffer__wrong_length(self) -> None:
        """
        Ensure 'from_buffer' rejects an option whose length field is not 1.

        Reference: RFC 8415 §21.8 (option-len must be 1).
        """

        with self.assertRaises(Dhcp6IntegrityError):
            Dhcp6OptionPreference.from_buffer(memoryview(b"\x00\x07\x00\x02\x80\x00"))


class TestDhcp6OptionPreferenceWrongType(TestCase):
    """
    The DHCPv6 Preference option wrong-code-word parser tests.
    """

    def test__dhcp6__option__preference__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the option code word equals
        Dhcp6OptionType.PREFERENCE and rejects a code below it, pinning the
        equality check against a '<=' relaxation.

        Reference: RFC 8415 §21.8 (Preference option code 7).
        """

        with self.assertRaises(AssertionError):
            Dhcp6OptionPreference.from_buffer(b"\x00\x00\x00\x01\xff")

    def test__dhcp6__option__preference__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects an option code word above
        Dhcp6OptionType.PREFERENCE, pinning the equality check against a
        '>=' relaxation.

        Reference: RFC 8415 §21.8 (Preference option code 7).
        """

        with self.assertRaises(AssertionError):
            Dhcp6OptionPreference.from_buffer(b"\xff\xff\x00\x01\xff")
