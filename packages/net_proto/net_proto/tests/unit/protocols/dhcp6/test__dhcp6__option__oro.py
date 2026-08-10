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
Module contains tests for the DHCPv6 Option Request option.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__oro.py

ver 3.0.10
"""

from dataclasses import FrozenInstanceError
from typing import override
from unittest import TestCase

from net_proto import (
    Dhcp6IntegrityError,
    Dhcp6OptionOro,
    Dhcp6OptionType,
)


class TestDhcp6OptionOroAsserts(TestCase):
    """
    The DHCPv6 Option Request option constructor assert tests.
    """

    def test__dhcp6__option__oro__not_list(self) -> None:
        """
        Ensure the constructor raises an exception when 'requested_options' is
        not a list.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        value = "not a list"

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionOro(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'requested_options' field must be a list. Got: {type(value)!r}",
            msg="Unexpected not-a-list assert message.",
        )

    def test__dhcp6__option__oro__element_not_option_type(self) -> None:
        """
        Ensure the constructor raises an exception when an element is not a
        Dhcp6OptionType.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS, "bad"])  # type: ignore[list-item]

        self.assertEqual(
            str(error.exception),
            "The 'requested_options' field must be a list of Dhcp6OptionType elements. "
            f"Got: {[Dhcp6OptionType, str]!r}",
            msg="Unexpected element-type assert message.",
        )

    def test__dhcp6__option__oro__empty(self) -> None:
        """
        Ensure the constructor raises an exception when 'requested_options' is
        empty.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionOro([])

        self.assertEqual(
            str(error.exception),
            "The 'requested_options' field must carry at least 1 requested option code " "(RFC 8415 §21.7). Got: 0",
            msg="Unexpected empty-list assert message.",
        )


class TestDhcp6OptionOroAssembler(TestCase):
    """
    The DHCPv6 Option Request option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a reference DHCPv6 Option Request option (DNS + domain list).
        """

        self._option = Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS, Dhcp6OptionType.from_int(24)])

    def test__dhcp6__option__oro__len(self) -> None:
        """
        Ensure '__len__()' returns code + len + 2 octets per requested option.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertEqual(len(self._option), 8, msg="Unexpected option length.")

    def test__dhcp6__option__oro__str(self) -> None:
        """
        Ensure '__str__()' renders the requested option names.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertEqual(
            str(self._option),
            "oro ['DNS_SERVERS', 'UNKNOWN_24']",
            msg="Unexpected log string.",
        )

    def test__dhcp6__option__oro__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        DHCPv6 Option Request option [RFC 8415]:
          option-code : 0x0006 (OPTION_ORO)
          option-len  : 0x0004 (2 requested codes)
          codes       : 0x0017 (23, DNS_SERVERS), 0x0018 (24, DOMAIN_LIST)

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertEqual(
            bytes(self._option),
            b"\x00\x06\x00\x04\x00\x17\x00\x18",
            msg="Unexpected wire image.",
        )

    def test__dhcp6__option__oro__type(self) -> None:
        """
        Ensure the 'type' field is OPTION_ORO.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertIs(self._option.type, Dhcp6OptionType.ORO, msg="Unexpected option type.")

    def test__dhcp6__option__oro__field(self) -> None:
        """
        Ensure the 'requested_options' field reflects the constructor argument.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertEqual(
            self._option.requested_options,
            [Dhcp6OptionType.DNS_SERVERS, Dhcp6OptionType.from_int(24)],
            msg="Unexpected requested_options.",
        )

    def test__dhcp6__option__oro__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option, ignoring
        trailing bytes.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertEqual(
            Dhcp6OptionOro.from_buffer(bytes(self._option) + b"TRAIL"),
            self._option,
            msg="Roundtrip must preserve equality.",
        )


class TestDhcp6OptionOroParserErrors(TestCase):
    """
    The DHCPv6 Option Request option parser error tests.
    """

    def test__dhcp6__option__oro__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        4-byte code+len header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionOro.from_buffer(b"\x00\x06\x00")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv6 Option Request option must be 4 bytes. Got: 3",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp6__option__oro__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option code is not OPTION_ORO.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionOro.from_buffer(b"\x00\x08\x00\x02\x00\x01")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv6 Option Request option type must be {Dhcp6OptionType.ORO!r}. "
            f"Got: {Dhcp6OptionType.ELAPSED_TIME!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp6__option__oro__zero_length(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length is below one requested code.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionOro.from_buffer(b"\x00\x06\x00\x00")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Option Request option must carry at least "
            "one requested option code (RFC 8415 §21.7). Got: 0",
            msg="Unexpected zero-length integrity error message.",
        )

    def test__dhcp6__option__oro__odd_length(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length is not a multiple of 2 octets.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionOro.from_buffer(b"\x00\x06\x00\x03\x00\x17\x00")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Option Request option length value "
            "(less header) must be a multiple of 2. Got: 1",
            msg="Unexpected odd-length integrity error message.",
        )

    def test__dhcp6__option__oro__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionOro.from_buffer(b"\x00\x06\x00\x04\x00\x17")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Option Request option length value must be "
            "less than or equal to the length of provided bytes (6). Got: 8",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp6OptionOroBehavior(TestCase):
    """
    The DHCPv6 Option Request option behavioral tests.
    """

    def test__dhcp6__option__oro__equality(self) -> None:
        """
        Ensure two options with equal requested-option lists compare equal.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertEqual(
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
            msg="Options with identical lists must compare equal.",
        )

    def test__dhcp6__option__oro__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        option = Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS])

        with self.assertRaises(FrozenInstanceError):
            option.requested_options = []  # type: ignore[misc]


class TestDhcp6OptionOroWrongType(TestCase):
    """
    The DHCPv6 Option Request option wrong-code-word parser tests.
    """

    def test__dhcp6__option__oro__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the option code word equals
        Dhcp6OptionType.ORO and rejects a code below it, pinning the
        equality check against a '<=' relaxation.

        Reference: RFC 8415 §21.7 (Option Request option code 6).
        """

        with self.assertRaises(AssertionError):
            Dhcp6OptionOro.from_buffer(b"\x00\x00\x00\x04\x00\x17\x00\x07")

    def test__dhcp6__option__oro__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects an option code word above
        Dhcp6OptionType.ORO, pinning the equality check against a
        '>=' relaxation.

        Reference: RFC 8415 §21.7 (Option Request option code 6).
        """

        with self.assertRaises(AssertionError):
            Dhcp6OptionOro.from_buffer(b"\xff\xff\x00\x04\x00\x17\x00\x07")
