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
Module contains tests for the DHCPv6 Status Code option.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__status_code.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import override
from unittest import TestCase

from net_proto import (
    Dhcp6IntegrityError,
    Dhcp6OptionStatusCode,
    Dhcp6OptionType,
    Dhcp6StatusCode,
)


class TestDhcp6OptionStatusCodeAsserts(TestCase):
    """
    The DHCPv6 Status Code option constructor assert tests.
    """

    def test__dhcp6__option__status_code__code_not_status_code(self) -> None:
        """
        Ensure the constructor raises an exception when 'status_code' is not a
        Dhcp6StatusCode.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        value = 2

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionStatusCode(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'status_code' field must be a Dhcp6StatusCode. Got: {type(value)!r}",
            msg="Unexpected status_code type assert message.",
        )

    def test__dhcp6__option__status_code__message_not_str(self) -> None:
        """
        Ensure the constructor raises an exception when 'status_message' is not
        a string.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        value = b"not a string"

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionStatusCode(Dhcp6StatusCode.SUCCESS, value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'status_message' field must be a string. Got: {type(value)!r}",
            msg="Unexpected status_message type assert message.",
        )


class TestDhcp6OptionStatusCodeAssembler(TestCase):
    """
    The DHCPv6 Status Code option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a reference DHCPv6 Status Code option with a message.
        """

        self._option = Dhcp6OptionStatusCode(Dhcp6StatusCode.NO_ADDRS_AVAIL, "no addrs")

    def test__dhcp6__option__status_code__len(self) -> None:
        """
        Ensure '__len__()' returns code + len + 2-octet status + message.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertEqual(len(self._option), 14, msg="Unexpected option length.")

    def test__dhcp6__option__status_code__str(self) -> None:
        """
        Ensure '__str__()' renders the status name and message.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertEqual(
            str(self._option),
            "status_code NoAddrsAvail (no addrs)",
            msg="Unexpected log string.",
        )

    def test__dhcp6__option__status_code__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        DHCPv6 Status Code option [RFC 8415]:
          option-code    : 0x000d (OPTION_STATUS_CODE)
          option-len     : 0x000a (2-octet code + 8-octet message)
          status-code    : 0x0002 (NoAddrsAvail)
          status-message : "no addrs"

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertEqual(
            bytes(self._option),
            b"\x00\x0d\x00\x0a\x00\x02no addrs",
            msg="Unexpected wire image.",
        )

    def test__dhcp6__option__status_code__type(self) -> None:
        """
        Ensure the 'type' field is OPTION_STATUS_CODE.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertIs(self._option.type, Dhcp6OptionType.STATUS_CODE, msg="Unexpected option type.")

    def test__dhcp6__option__status_code__fields(self) -> None:
        """
        Ensure the 'status_code' and 'status_message' fields reflect the
        constructor arguments.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertIs(self._option.status_code, Dhcp6StatusCode.NO_ADDRS_AVAIL, msg="Unexpected status_code.")
        self.assertEqual(self._option.status_message, "no addrs", msg="Unexpected status_message.")

    def test__dhcp6__option__status_code__empty_message(self) -> None:
        """
        Ensure a status code with no message assembles to the 6-byte form and
        renders without a parenthesised message.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        option = Dhcp6OptionStatusCode(Dhcp6StatusCode.SUCCESS)

        self.assertEqual(bytes(option), b"\x00\x0d\x00\x02\x00\x00", msg="Unexpected empty-message wire image.")
        self.assertEqual(str(option), "status_code Success", msg="Unexpected empty-message log string.")

    def test__dhcp6__option__status_code__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option, ignoring
        trailing bytes.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertEqual(
            Dhcp6OptionStatusCode.from_buffer(bytes(self._option) + b"TRAIL"),
            self._option,
            msg="Roundtrip must preserve equality.",
        )

    def test__dhcp6__option__status_code__unknown_code(self) -> None:
        """
        Ensure 'from_buffer()' materialises an unknown status code as an
        UNKNOWN ProtoEnum member rather than raising.

        Reference: RFC 8415 §21.13 (Status Code option; unknown handling).
        """

        option = Dhcp6OptionStatusCode.from_buffer(b"\x00\x0d\x00\x02\x00\x63")

        self.assertTrue(option.status_code.is_unknown, msg="Unknown status code must materialise as UNKNOWN.")
        self.assertEqual(int(option.status_code), 0x63, msg="Unknown status code must preserve its wire value.")


class TestDhcp6OptionStatusCodeParserErrors(TestCase):
    """
    The DHCPv6 Status Code option parser error tests.
    """

    def test__dhcp6__option__status_code__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        4-byte code+len header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionStatusCode.from_buffer(b"\x00\x0d\x00")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv6 Status Code option must be 4 bytes. Got: 3",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp6__option__status_code__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option code is not
        OPTION_STATUS_CODE.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionStatusCode.from_buffer(b"\x00\x06\x00\x02\x00\x17")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv6 Status Code option type must be {Dhcp6OptionType.STATUS_CODE!r}. "
            f"Got: {Dhcp6OptionType.ORO!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp6__option__status_code__missing_status_field(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length is below the 2-octet status-code field.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionStatusCode.from_buffer(b"\x00\x0d\x00\x01\x00")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Status Code option must carry the 2-octet "
            "status-code field (RFC 8415 §21.13). Got: 1",
            msg="Unexpected missing-status integrity error message.",
        )

    def test__dhcp6__option__status_code__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionStatusCode.from_buffer(b"\x00\x0d\x00\x0a\x00\x02\x41\x42")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Status Code option length value must be less "
            "than or equal to the length of provided bytes (8). Got: 14",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp6OptionStatusCodeBehavior(TestCase):
    """
    The DHCPv6 Status Code option behavioral tests.
    """

    def test__dhcp6__option__status_code__equality(self) -> None:
        """
        Ensure two options with equal code and message compare equal.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertEqual(
            Dhcp6OptionStatusCode(Dhcp6StatusCode.SUCCESS, "ok"),
            Dhcp6OptionStatusCode(Dhcp6StatusCode.SUCCESS, "ok"),
            msg="Options with identical fields must compare equal.",
        )

    def test__dhcp6__option__status_code__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        option = Dhcp6OptionStatusCode(Dhcp6StatusCode.SUCCESS)

        with self.assertRaises(FrozenInstanceError):
            option.status_message = "changed"  # type: ignore[misc]
