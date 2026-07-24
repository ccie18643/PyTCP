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
Module contains tests for the DHCPv6 Elapsed Time option.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__elapsed_time.py

ver 3.0.9
"""

from dataclasses import FrozenInstanceError
from typing import override
from unittest import TestCase

from net_proto import (
    UINT_16__MAX,
    UINT_16__MIN,
    Dhcp6IntegrityError,
    Dhcp6OptionElapsedTime,
    Dhcp6OptionType,
)


class TestDhcp6OptionElapsedTimeAsserts(TestCase):
    """
    The DHCPv6 Elapsed Time option constructor assert tests.
    """

    def test__dhcp6__option__elapsed_time__under_min(self) -> None:
        """
        Ensure the constructor raises an exception when 'elapsed_time' is
        below the minimum 16-bit value.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionElapsedTime(value)

        self.assertEqual(
            str(error.exception),
            f"The 'elapsed_time' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected under-min assert message.",
        )

    def test__dhcp6__option__elapsed_time__over_max(self) -> None:
        """
        Ensure the constructor raises an exception when 'elapsed_time' is
        above the maximum 16-bit value.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionElapsedTime(value)

        self.assertEqual(
            str(error.exception),
            f"The 'elapsed_time' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected over-max assert message.",
        )


class TestDhcp6OptionElapsedTimeAssembler(TestCase):
    """
    The DHCPv6 Elapsed Time option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a reference DHCPv6 Elapsed Time option (1234 hundredths).
        """

        self._option = Dhcp6OptionElapsedTime(1234)

    def test__dhcp6__option__elapsed_time__len(self) -> None:
        """
        Ensure '__len__()' returns the fixed 6-byte option length.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertEqual(len(self._option), 6, msg="Unexpected option length.")

    def test__dhcp6__option__elapsed_time__str(self) -> None:
        """
        Ensure '__str__()' renders the elapsed-time value.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertEqual(str(self._option), "elapsed_time 1234", msg="Unexpected log string.")

    def test__dhcp6__option__elapsed_time__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        DHCPv6 Elapsed Time option [RFC 8415]:
          option-code  : 0x0008 (OPTION_ELAPSED_TIME)
          option-len   : 0x0002 (2)
          elapsed-time : 0x04d2 (1234)

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertEqual(
            bytes(self._option),
            b"\x00\x08\x00\x02\x04\xd2",
            msg="Unexpected wire image.",
        )

    def test__dhcp6__option__elapsed_time__type(self) -> None:
        """
        Ensure the 'type' field is OPTION_ELAPSED_TIME.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertIs(
            self._option.type,
            Dhcp6OptionType.ELAPSED_TIME,
            msg="Unexpected option type.",
        )

    def test__dhcp6__option__elapsed_time__field(self) -> None:
        """
        Ensure the 'elapsed_time' field reflects the constructor argument.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertEqual(self._option.elapsed_time, 1234, msg="Unexpected elapsed_time value.")

    def test__dhcp6__option__elapsed_time__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option, ignoring
        trailing bytes.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertEqual(
            Dhcp6OptionElapsedTime.from_buffer(bytes(self._option) + b"TRAIL"),
            self._option,
            msg="Roundtrip must preserve equality.",
        )


class TestDhcp6OptionElapsedTimeParserErrors(TestCase):
    """
    The DHCPv6 Elapsed Time option parser error tests.
    """

    def test__dhcp6__option__elapsed_time__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        4-byte code+len header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionElapsedTime.from_buffer(b"\x00\x08\x00")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv6 Elapsed Time option must be 4 bytes. Got: 3",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp6__option__elapsed_time__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option code is not
        OPTION_ELAPSED_TIME.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionElapsedTime.from_buffer(b"\x00\x06\x00\x02\x00\x01")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv6 Elapsed Time option type must be {Dhcp6OptionType.ELAPSED_TIME!r}. "
            f"Got: {Dhcp6OptionType.ORO!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp6__option__elapsed_time__wrong_type_above(self) -> None:
        """
        Ensure 'from_buffer()' also rejects an option code word ABOVE
        OPTION_ELAPSED_TIME, pinning the code-equality assert against a
        '>=' relaxation (the existing wrong-type case only exercises a
        code below it).

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        with self.assertRaises(AssertionError):
            Dhcp6OptionElapsedTime.from_buffer(b"\xff\xff\x00\x02\x00\x01")

    def test__dhcp6__option__elapsed_time__wrong_length(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length is not exactly 2 octets.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionElapsedTime.from_buffer(b"\x00\x08\x00\x04\x00\x00\x00\x00")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Elapsed Time option length value must be 6 bytes. Got: 8",
            msg="Unexpected wrong-length integrity error message.",
        )

    def test__dhcp6__option__elapsed_time__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the buffer does
        not even contain the 4-byte header plus a wrong-but-bounded length.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionElapsedTime.from_buffer(b"\x00\x08\x00\x02")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Elapsed Time option length value must be less "
            "than or equal to the length of provided bytes (4). Got: 6",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp6OptionElapsedTimeBehavior(TestCase):
    """
    The DHCPv6 Elapsed Time option behavioral tests.
    """

    def test__dhcp6__option__elapsed_time__equality(self) -> None:
        """
        Ensure two options with equal values compare equal.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertEqual(
            Dhcp6OptionElapsedTime(100),
            Dhcp6OptionElapsedTime(100),
            msg="Options with identical values must compare equal.",
        )

    def test__dhcp6__option__elapsed_time__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        option = Dhcp6OptionElapsedTime(100)

        with self.assertRaises(FrozenInstanceError):
            option.elapsed_time = 200  # type: ignore[misc]
