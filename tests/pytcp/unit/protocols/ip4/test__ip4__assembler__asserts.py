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
This module contains tests for the IPv4 packet assembler constructor argument asserts.

tests/pytcp/unit/protocols/ip4/test__ip4__assembler__asserts.py

ver 3.0.2
"""


from testslide import TestCase

from pytcp.protocols.ip4.ip4__assembler import Ip4Assembler, Ip4FragAssembler
from pytcp.protocols.ip4.options.ip4_option__eol import Ip4OptionEol
from pytcp.protocols.ip4.options.ip4_option__nop import Ip4OptionNop
from pytcp.protocols.ip4.options.ip4_options import (
    IP4__OPTIONS__MAX_LEN,
    Ip4Options,
)


class TestIp4AssemblerAsserts(TestCase):
    """
    The IPv4 packet assembler constructor argument assert tests.
    """

    def test__ip4__assembler__options_len__over_max(self) -> None:
        """
        Ensure the IPv4 packet assembler constructor raises an exception when
        the length of the provided 'ip4__options' argument length is higher
        than the maximum supported value.
        """

        with self.assertRaises(AssertionError) as error:
            Ip4Assembler(
                ip4__options=Ip4Options(
                    *([Ip4OptionNop()] * (IP4__OPTIONS__MAX_LEN + 1)),
                )
            )

        self.assertEqual(
            str(error.exception),
            f"The IPv4 options length must be less than or equal to {IP4__OPTIONS__MAX_LEN}.",
        )

    def test__ip4__assembler__options_len__not_4_bytes_alligned(self) -> None:
        """
        Ensure the IPv4 packet assembler constructor raises an exception when
        the length of the provided 'ip4__options' argument is not 4 bytes
        aligned.
        """

        with self.assertRaises(AssertionError):
            Ip4Assembler(
                ip4__options=Ip4Options(
                    *([Ip4OptionNop()] * (16 + 1)),
                )
            )

    def test__ip4__assembler__options__eol__not_last(self) -> None:
        """
        Ensure the IPv4 packet assembler constructor raises an exception when the
        'Eol' option is not the last option.
        """

        with self.assertRaises(AssertionError) as error:
            Ip4Assembler(
                ip4__options=Ip4Options(
                    Ip4OptionNop(),
                    Ip4OptionNop(),
                    Ip4OptionEol(),
                    Ip4OptionNop(),
                )
            )

        self.assertEqual(
            str(error.exception), "The IPv4 EOL option must be the last option."
        )


class TestIp4FragAssemblerAsserts(TestCase):
    """
    The IPv4 (Frag) packet assembler constructor argument assert tests.
    """

    def test__ip4_frag__assembler__options_len__over_max(self) -> None:
        """
        Ensure the (IPv4) Frag packet assembler constructor raises an exception
        when the length of the provided 'ip4__options' argument length is higher
        than the maximum supported value.
        """

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(
                ip4_frag__options=Ip4Options(
                    *([Ip4OptionNop()] * (IP4__OPTIONS__MAX_LEN + 1)),
                )
            )

    def test__ip4_frag__assembler__options_len__not_4_bytes_alligned(
        self,
    ) -> None:
        """
        Ensure the (IPv4) Frag packet assembler constructor raises an exception
        when the length of the provided 'ip4_frag__options' argument is not
        4 bytes aligned.
        """

        with self.assertRaises(AssertionError):
            Ip4FragAssembler(
                ip4_frag__options=Ip4Options(
                    *([Ip4OptionNop()] * (16 + 1)),
                )
            )

    def test__ip4_frag__assembler__options__eol__not_last(self) -> None:
        """
        Ensure the IPv4 (Frag) packet assembler constructor raises an exception
        when the 'Eol' option is not the last option.
        """

        with self.assertRaises(AssertionError) as error:
            Ip4Assembler(
                ip4__options=Ip4Options(
                    Ip4OptionNop(),
                    Ip4OptionNop(),
                    Ip4OptionEol(),
                    Ip4OptionNop(),
                )
            )

        self.assertEqual(
            str(error.exception), "The IPv4 EOL option must be the last option."
        )
