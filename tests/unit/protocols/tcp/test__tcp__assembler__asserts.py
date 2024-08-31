#!/usr/bin/env python3

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

tests/unit/protocols/tcp/test__tcp_assembler__asserts.py

ver 3.0.2
"""


from testslide import TestCase

from pytcp.protocols.tcp.options.tcp_option__eol import TcpOptionEol
from pytcp.protocols.tcp.options.tcp_option__nop import TcpOptionNop
from pytcp.protocols.tcp.options.tcp_options import (
    TCP__OPTIONS__MAX_LEN,
    TcpOptions,
)
from pytcp.protocols.tcp.tcp__assembler import TcpAssembler


class TestTcpAssemblerAsserts(TestCase):
    """
    The TCP packet assembler constructor argument assert tests.
    """

    def test__tcp__assembler__options_len__over_max(self) -> None:
        """
        Ensure the TCP packet assembler constructor raises an exception when
        the length of the provided 'tcp__options' argument is higher than the
        maximum supported value.
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
        )

    def test__tcp__assembler__options_len__not_4_bytes_alligned(self) -> None:
        """
        Ensure the TCP packet assembler constructor raises an exception when
        the length of the provided 'tcp__options' argument is not 4 bytes
        aligned.
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
        )

    def test__tcp__assembler__options__eol__not_last(self) -> None:
        """
        Ensure the TCP packet assembler constructor raises an exception when the
        'Eol' option is not the last option.
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
            str(error.exception), "The TCP EOL option must be the last option."
        )
