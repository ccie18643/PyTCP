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
This module contains tests for the TCP packet assembler constructor argument asserts.

net_proto/tests/unit/protocols/tcp/test__tcp__assembler__asserts.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto import (
    TCP__OPTIONS__MAX_LEN,
    TcpAssembler,
    TcpOptionEol,
    TcpOptionNop,
    TcpOptions,
)


class TestTcpAssemblerAsserts(TestCase):
    """
    The TCP packet assembler constructor argument assert tests.
    """

    def test__tcp__assembler__defaults_accepted(self) -> None:
        """
        Ensure the default-constructed assembler (no kwargs) is accepted;
        this guards the negative tests from silent regressions that would
        make the baseline invalid.

        Reference: RFC 9293 §3.1 (TCP header field constraints).
        """

        assembler = TcpAssembler()

        self.assertEqual(
            len(assembler.options),
            0,
            msg="Default-constructed assembler must have an empty options container.",
        )

    def test__tcp__assembler__options_len__over_max(self) -> None:
        """
        Ensure the TCP packet assembler constructor raises an exception
        when the length of the provided 'tcp__options' argument is higher
        than TCP__OPTIONS__MAX_LEN.

        Reference: RFC 9293 §3.1 (TCP header field constraints).
        """

        with self.assertRaises(AssertionError) as error:
            TcpAssembler(
                tcp__options=TcpOptions(
                    *([TcpOptionNop()] * (TCP__OPTIONS__MAX_LEN + 4)),
                )
            )

        self.assertEqual(
            str(error.exception),
            f"The TCP options length must be less than or equal to {TCP__OPTIONS__MAX_LEN}.",
            msg="Unexpected assertion message for over-max options length.",
        )

    def test__tcp__assembler__options_len__exact_max_accepted(self) -> None:
        """
        Ensure the TCP packet assembler constructor accepts a 'tcp__options'
        whose serialized length is exactly TCP__OPTIONS__MAX_LEN (the
        inclusive upper boundary).

        Reference: RFC 9293 §3.1 (TCP header field constraints).
        """

        assembler = TcpAssembler(
            tcp__options=TcpOptions(
                *([TcpOptionNop()] * TCP__OPTIONS__MAX_LEN),
            )
        )

        self.assertEqual(
            len(assembler.options),
            TCP__OPTIONS__MAX_LEN,
            msg="Assembler must accept options exactly TCP__OPTIONS__MAX_LEN bytes long.",
        )

    def test__tcp__assembler__options_len__not_4_bytes_alligned(self) -> None:
        """
        Ensure the TCP packet assembler constructor raises an exception
        when the length of the provided 'tcp__options' argument is not
        4-byte aligned.

        Reference: RFC 9293 §3.1 (TCP header field constraints).
        """

        with self.assertRaises(AssertionError) as error:
            TcpAssembler(
                tcp__options=TcpOptions(
                    *([TcpOptionNop()] * (TCP__OPTIONS__MAX_LEN - 1)),
                )
            )

        self.assertEqual(
            str(error.exception),
            "The TCP options length must be 4-byte aligned.",
            msg="Unexpected assertion message for non-4-byte-aligned options.",
        )

    def test__tcp__assembler__options__eol__not_last(self) -> None:
        """
        Ensure the TCP packet assembler constructor raises an exception
        when the 'Eol' option is not the last option in the options list.

        Reference: RFC 9293 §3.1 (TCP header field constraints).
        """

        with self.assertRaises(AssertionError) as error:
            TcpAssembler(
                tcp__options=TcpOptions(
                    TcpOptionNop(),
                    TcpOptionNop(),
                    TcpOptionEol(),
                    TcpOptionNop(),
                )
            )

        self.assertEqual(
            str(error.exception),
            "The TCP EOL option must be the last option.",
            msg="Unexpected assertion message for Eol not being the last option.",
        )

    def test__tcp__assembler__options__eol__as_last_accepted(self) -> None:
        """
        Ensure the TCP packet assembler constructor accepts an Eol option
        when it is the last option in the options list.

        Reference: RFC 9293 §3.1 (TCP header field constraints).
        """

        assembler = TcpAssembler(
            tcp__options=TcpOptions(
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionNop(),
                TcpOptionEol(),
            )
        )

        self.assertEqual(
            len(assembler.options),
            4,
            msg="Assembler must accept an options list ending with Eol.",
        )
