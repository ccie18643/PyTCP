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
This module contains tests for the ICMPv4 unknown message assembler
asserts.

tests/unit/protocols/icmp4/test__icmp4__message__unknown__asserts.py

ver 3.0.0
"""


from testslide import TestCase

from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Code, Icmp4Type
from pytcp.protocols.icmp4.message.icmp4_message__unknown import (
    Icmp4UnknownMessage,
)


class TestIcmp4MessageUnknownArgAsserts(TestCase):
    """
    The ICMPv4 unknown message assembler & parser constructors argument
    assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv4 unknown message
        constructor.
        """

        self._message_args = {
            "type": Icmp4Type.from_int(255),
            "code": Icmp4Code.from_int(255),
            "cksum": 0,
        }

    def test__icmp4__message__unknown__type__not_Icmp4Type(self) -> None:
        """
        Ensure the ICMPv4 message constructor raises an exception when the
        provided 'type' argument is not an Icmp4Type.
        """

        self._message_args["type"] = value = "not an Icmp4Type"

        with self.assertRaises(AssertionError) as error:
            Icmp4UnknownMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an Icmp4Type. Got: {type(value)!r}",
        )

    def test__icmp4__message__unknown__code__not_Icmp4Code(self) -> None:
        """
        Ensure the ICMPv4 message constructor raises an exception when the
        provided 'code' argument is not an Icmp4Code.
        """

        self._message_args["code"] = value = "not an Icmp4Code"

        with self.assertRaises(AssertionError) as error:
            Icmp4UnknownMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4Code. Got: {type(value)!r}",
        )

    def test__icmp4__message__echo_request__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv4 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is lower than the
        minimum supported value.
        """

        self._message_args["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4UnknownMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp4__message__echo_request__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv4 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is higher than the
        maximum supported value.
        """

        self._message_args["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4UnknownMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )
