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
This module contains tests for the IPv4 packet assembler constructor argument asserts.

net_proto/tests/unit/protocols/ip4/test__ip4__assembler__asserts.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto import (
    IP4__OPTIONS__MAX_LEN,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip4OptionEol,
    Ip4OptionNop,
    Ip4Options,
)


class TestIp4AssemblerAsserts(TestCase):
    """
    The IPv4 packet assembler constructor argument assert tests.
    """

    def test__ip4__assembler__options_len__over_max(self) -> None:
        """
        Ensure the constructor rejects 'ip4__options' longer than
        IP4__OPTIONS__MAX_LEN bytes.

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4Assembler(
                ip4__options=Ip4Options(
                    *([Ip4OptionNop()] * (IP4__OPTIONS__MAX_LEN + 1)),
                ),
            )

        self.assertEqual(
            str(error.exception),
            f"The IPv4 options length must be less than or equal to {IP4__OPTIONS__MAX_LEN}.",
            msg="Unexpected assertion message for over-max 'ip4__options'.",
        )

    def test__ip4__assembler__options_len__at_max_accepted(self) -> None:
        """
        Ensure the constructor accepts 'ip4__options' whose length equals
        IP4__OPTIONS__MAX_LEN bytes (boundary case).

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        options = Ip4Options(*([Ip4OptionNop()] * IP4__OPTIONS__MAX_LEN))

        assembler = Ip4Assembler(ip4__options=options)

        self.assertEqual(
            assembler.options,
            options,
            msg="Assembler must accept options exactly at IP4__OPTIONS__MAX_LEN.",
        )

    def test__ip4__assembler__options_len__not_4_bytes_alligned(self) -> None:
        """
        Ensure the constructor rejects 'ip4__options' whose length is not
        a multiple of 4 bytes.

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4Assembler(
                ip4__options=Ip4Options(
                    *([Ip4OptionNop()] * 17),
                ),
            )

        self.assertEqual(
            str(error.exception),
            "The IPv4 options length must be 4-byte aligned.",
            msg="Unexpected assertion message for non-4-byte-aligned 'ip4__options'.",
        )

    def test__ip4__assembler__options__eol__not_last(self) -> None:
        """
        Ensure the constructor rejects an options list where the 'Eol'
        option is not the final entry.

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4Assembler(
                ip4__options=Ip4Options(
                    Ip4OptionNop(),
                    Ip4OptionNop(),
                    Ip4OptionEol(),
                    Ip4OptionNop(),
                ),
            )

        self.assertEqual(
            str(error.exception),
            "The IPv4 EOL option must be the last option.",
            msg="Unexpected assertion message for misplaced 'Eol' option.",
        )

    def test__ip4__assembler__options__eol__last_accepted(self) -> None:
        """
        Ensure the constructor accepts an options list where the 'Eol'
        option is the last entry.

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        options = Ip4Options(
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionEol(),
        )

        assembler = Ip4Assembler(ip4__options=options)

        self.assertEqual(
            assembler.options,
            options,
            msg="Assembler must accept options with trailing 'Eol' option.",
        )

    def test__ip4__assembler__options__no_eol_accepted(self) -> None:
        """
        Ensure the constructor accepts an options list that does not
        contain an 'Eol' option at all.

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        options = Ip4Options(Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop())

        assembler = Ip4Assembler(ip4__options=options)

        self.assertEqual(
            assembler.options,
            options,
            msg="Assembler must accept options without any 'Eol' option.",
        )


class TestIp4FragAssemblerAsserts(TestCase):
    """
    The IPv4 (Frag) packet assembler constructor argument assert tests.
    """

    def test__ip4_frag__assembler__options_len__over_max(self) -> None:
        """
        Ensure the (Frag) constructor rejects 'ip4_frag__options' longer
        than IP4__OPTIONS__MAX_LEN bytes.

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4FragAssembler(
                ip4_frag__options=Ip4Options(
                    *([Ip4OptionNop()] * (IP4__OPTIONS__MAX_LEN + 1)),
                ),
            )

        self.assertEqual(
            str(error.exception),
            f"The IPv4 options length must be less than or equal to {IP4__OPTIONS__MAX_LEN}.",
            msg="Unexpected assertion message for over-max 'ip4_frag__options'.",
        )

    def test__ip4_frag__assembler__options_len__at_max_accepted(self) -> None:
        """
        Ensure the (Frag) constructor accepts 'ip4_frag__options' whose
        length equals IP4__OPTIONS__MAX_LEN bytes (boundary case).

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        options = Ip4Options(*([Ip4OptionNop()] * IP4__OPTIONS__MAX_LEN))

        assembler = Ip4FragAssembler(ip4_frag__options=options)

        self.assertEqual(
            assembler.options,
            options,
            msg="Frag assembler must accept options exactly at IP4__OPTIONS__MAX_LEN.",
        )

    def test__ip4_frag__assembler__options_len__not_4_bytes_alligned(self) -> None:
        """
        Ensure the (Frag) constructor rejects 'ip4_frag__options' whose
        length is not a multiple of 4 bytes.

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4FragAssembler(
                ip4_frag__options=Ip4Options(
                    *([Ip4OptionNop()] * 17),
                ),
            )

        self.assertEqual(
            str(error.exception),
            "The IPv4 options length must be 4-byte aligned.",
            msg="Unexpected assertion message for non-4-byte-aligned 'ip4_frag__options'.",
        )

    def test__ip4_frag__assembler__options__eol__not_last(self) -> None:
        """
        Ensure the (Frag) constructor rejects an options list where the
        'Eol' option is not the final entry.

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4FragAssembler(
                ip4_frag__options=Ip4Options(
                    Ip4OptionNop(),
                    Ip4OptionNop(),
                    Ip4OptionEol(),
                    Ip4OptionNop(),
                ),
            )

        self.assertEqual(
            str(error.exception),
            "The IPv4 EOL option must be the last option.",
            msg="Unexpected assertion message for misplaced 'Eol' option in Frag assembler.",
        )

    def test__ip4_frag__assembler__options__eol__last_accepted(self) -> None:
        """
        Ensure the (Frag) constructor accepts an options list where the
        'Eol' option is the last entry.

        Reference: RFC 791 §3.1 (IPv4 header field constraints).
        """

        options = Ip4Options(
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionEol(),
        )

        assembler = Ip4FragAssembler(ip4_frag__options=options)

        self.assertEqual(
            assembler.options,
            options,
            msg="Frag assembler must accept options with trailing 'Eol' option.",
        )
