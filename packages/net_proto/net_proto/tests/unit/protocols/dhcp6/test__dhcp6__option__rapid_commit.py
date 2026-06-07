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
Module contains tests for the DHCPv6 Rapid Commit option.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__rapid_commit.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase

from net_proto import (
    Dhcp6IntegrityError,
    Dhcp6OptionRapidCommit,
    Dhcp6OptionType,
)


class TestDhcp6OptionRapidCommitAssembler(TestCase):
    """
    The DHCPv6 Rapid Commit option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the zero-length DHCPv6 Rapid Commit option.
        """

        self._option = Dhcp6OptionRapidCommit()

    def test__dhcp6__option__rapid_commit__len(self) -> None:
        """
        Ensure '__len__()' returns the fixed 4-byte header-only length.

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        self.assertEqual(len(self._option), 4, msg="Unexpected option length.")

    def test__dhcp6__option__rapid_commit__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical name.

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        self.assertEqual(str(self._option), "rapid_commit", msg="Unexpected log string.")

    def test__dhcp6__option__rapid_commit__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        DHCPv6 Rapid Commit option [RFC 8415]:
          option-code : 0x000e (OPTION_RAPID_COMMIT)
          option-len  : 0x0000 (no data)

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        self.assertEqual(bytes(self._option), b"\x00\x0e\x00\x00", msg="Unexpected wire image.")

    def test__dhcp6__option__rapid_commit__type(self) -> None:
        """
        Ensure the 'type' field is OPTION_RAPID_COMMIT.

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        self.assertIs(
            self._option.type,
            Dhcp6OptionType.RAPID_COMMIT,
            msg="Unexpected option type.",
        )

    def test__dhcp6__option__rapid_commit__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option, ignoring
        trailing bytes.

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        self.assertEqual(
            Dhcp6OptionRapidCommit.from_buffer(bytes(self._option) + b"TRAIL"),
            self._option,
            msg="Roundtrip must preserve equality.",
        )


class TestDhcp6OptionRapidCommitParserErrors(TestCase):
    """
    The DHCPv6 Rapid Commit option parser error tests.
    """

    def test__dhcp6__option__rapid_commit__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        4-byte code+len header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionRapidCommit.from_buffer(b"\x00\x0e\x00")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv6 Rapid Commit option must be 4 bytes. Got: 3",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp6__option__rapid_commit__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option code is not
        OPTION_RAPID_COMMIT.

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionRapidCommit.from_buffer(b"\x00\x06\x00\x00")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv6 Rapid Commit option type must be {Dhcp6OptionType.RAPID_COMMIT!r}. "
            f"Got: {Dhcp6OptionType.ORO!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp6__option__rapid_commit__nonzero_length(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length is not zero.

        Reference: RFC 8415 §21.14 (Rapid Commit option; option-len MUST be 0).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionRapidCommit.from_buffer(b"\x00\x0e\x00\x01\x00")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 Rapid Commit option length value "
            "must be 0 (RFC 8415 §21.14). Got: 1",
            msg="Unexpected nonzero-length integrity error message.",
        )


class TestDhcp6OptionRapidCommitBehavior(TestCase):
    """
    The DHCPv6 Rapid Commit option behavioral tests.
    """

    def test__dhcp6__option__rapid_commit__equality(self) -> None:
        """
        Ensure two Rapid Commit options compare equal.

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        self.assertEqual(
            Dhcp6OptionRapidCommit(),
            Dhcp6OptionRapidCommit(),
            msg="Two Rapid Commit options must compare equal.",
        )
