#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains tests for the ICMPv6 unknown message assembler & parser
arguments.

tests/unit/protocols/icmp6/test__icmp6__message__unknown__asserts.py

ver 3.0.0
"""


from testslide import TestCase

from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Code, Icmp6Type
from pytcp.protocols.icmp6.message.icmp6_message__unknown import (
    Icmp6UnknownMessage,
)


class TestIcmp6MessageUnknownAsserts(TestCase):
    """
    The ICMPv6 unknown message assembler & parser constructor argument
    assert tests.
    """

    def test__icmp6__message__unknown__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv6 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is lower than
        the minimum supported value.
        """

        with self.assertRaises(AssertionError):
            Icmp6UnknownMessage(
                type=Icmp6Type.from_int(255),
                code=Icmp6Code.from_int(255),
                cksum=UINT_16__MIN - 1,
            )

    def test__icmp6__message__unknown__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv6 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is higher than
        the maximum supported value.
        """

        with self.assertRaises(AssertionError):
            Icmp6UnknownMessage(
                type=Icmp6Type.from_int(255),
                code=Icmp6Code.from_int(255),
                cksum=UINT_16__MAX + 1,
            )
