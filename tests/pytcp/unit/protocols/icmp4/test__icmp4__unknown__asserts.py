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
Module contains tests for the ICMPv4 unknown message assembler & parser asserts.

tests/pytcp/unit/protocols/icmp4/test__icmp4__unknown__asserts.py

ver 3.0.2
"""


from typing import Any

from testslide import TestCase

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Code, Icmp4Type
from pytcp.protocols.icmp4.message.icmp4_message__unknown import (
    Icmp4UnknownMessage,
)


class TestIcmp4UnknownAssemblerAsserts(TestCase):
    """
    The ICMPv4 unknown message assembler constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv4 unknown message
        constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "type": Icmp4Type.from_int(255),
            "code": Icmp4Code.from_int(255),
            "cksum": 0,
            "raw": b"",
        }

    def test__icmp4__unknown__type__not_Icmp4Type(self) -> None:
        """
        Ensure the ICMPv4 message constructor raises an exception
        when the provided 'type' argument is not an Icmp4Type.
        """

        self._kwargs["type"] = value = "not an Icmp4Type"

        with self.assertRaises(AssertionError) as error:
            Icmp4UnknownMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an Icmp4Type. Got: {type(value)!r}",
        )

    def test__icmp4__unknown__code__not_Icmp4Code(self) -> None:
        """
        Ensure the ICMPv4 message constructor raises an exception
        when the provided 'code' argument is not an Icmp4Code.
        """

        self._kwargs["code"] = value = "not an Icmp4Code"

        with self.assertRaises(AssertionError) as error:
            Icmp4UnknownMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4Code. Got: {type(value)!r}",
        )

    def test__icmp4__echo_request__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv4 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is lower than
        the minimum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4UnknownMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__echo_request__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv4 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is higher than
        the maximum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4UnknownMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__unknown__raw__not_bytes(self) -> None:
        """
        Ensure the ICMPv4 message constructor raises an exception
        when the provided 'raw' argument is not bytes.
        """

        self._kwargs["raw"] = value = "not bytes or memoryview"

        with self.assertRaises(AssertionError) as error:
            Icmp4UnknownMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'raw' field must be a bytes or memoryview. "
            f"Got: {type(value)!r}",
        )


class TestIcmp4UnknownParserAsserts(TestCase):
    """
    The ICMPv4 unknown message parser argument constructor assert tests.
    """

    def test__icmp4__unknown__wrong_type(self) -> None:
        """
        Ensure the ICMPv4 unknown message parser raises an exception when
        the provided '_bytes' argument contains incorrect 'type' field.
        """

        for type in range(0, 256):
            if type not in Icmp4Type.get_known_values():
                continue

            _bytes = bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00")
            _bytes[0] = type
            _bytes[2:4] = inet_cksum(data=_bytes).to_bytes(2)

            with self.assertRaises(AssertionError) as error:
                Icmp4UnknownMessage.from_bytes(bytes(_bytes))

            self.assertEqual(
                str(error.exception),
                (
                    "The 'type' field must not be known. "
                    f"Got: {Icmp4Type.from_int(type)!r}"
                ),
            )
