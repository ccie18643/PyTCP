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
Module contains tests for the ICMPv6 unknown message assembler & parser asserts.

tests/unit/protocols/icmp6/test__icmp6__unknown__asserts.py

ver 3.0.2
"""


from testslide import TestCase

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Code, Icmp6Type
from pytcp.protocols.icmp6.message.icmp6_message__unknown import (
    Icmp6UnknownMessage,
)


class TestIcmp6UnknownAssemblerAsserts(TestCase):
    """
    The ICMPv6 unknown message assembler constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 unknown message
        constructor.
        """

        self._message_kwargs = {
            "type": Icmp6Type.from_int(255),
            "code": Icmp6Code.from_int(255),
            "cksum": 0,
            "raw": b"",
        }

    def test__icmp6__unknown__type__not_Icmp6Type(self) -> None:
        """
        Ensure the ICMPv6 message constructor raises an exception when the
        provided 'type' argument is not an Icmp6Type.
        """

        self._message_kwargs["type"] = value = "not an Icmp6Type"

        with self.assertRaises(AssertionError) as error:
            Icmp6UnknownMessage(**self._message_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an Icmp6Type. Got: {type(value)!r}",
        )

    def test__icmp6__unknown__code__not_Icmp6Code(self) -> None:
        """
        Ensure the ICMPv6 message constructor raises an exception when the
        provided 'code' argument is not an Icmp6Code.
        """

        self._message_kwargs["code"] = value = "not an Icmp6Code"

        with self.assertRaises(AssertionError) as error:
            Icmp6UnknownMessage(**self._message_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6Code. Got: {type(value)!r}",
        )

    def test__icmp6__echo_request__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv6 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is lower than the
        minimum supported value.
        """

        self._message_kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6UnknownMessage(**self._message_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp6__echo_request__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv6 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is higher than the
        maximum supported value.
        """

        self._message_kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6UnknownMessage(**self._message_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp6__unknown__raw__not_bytes(self) -> None:
        """
        Ensure the ICMPv6 message constructor raises an exception when the
        provided 'raw' argument is not bytes.
        """

        self._message_kwargs["raw"] = value = "not bytes or memoryview"

        with self.assertRaises(AssertionError) as error:
            Icmp6UnknownMessage(**self._message_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'raw' field must be a bytes or memoryview. "
            f"Got: {type(value)!r}",
        )


class TestIcmp6UnknownParserAsserts(TestCase):
    """
    The ICMPv6 unknown message parser argument constructor assert tests.
    """

    def test__icmp6__unknown__wrong_type(self) -> None:
        """
        Ensure the ICMPv6 unknown message parser raises an exception when
        the provided '_bytes' argument contains incorrect 'type' field.
        """

        for type in range(0, 256):
            if type not in Icmp6Type.get_known_values():
                continue

            _bytes = bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00")
            _bytes[0] = type
            _bytes[2:4] = inet_cksum(_bytes).to_bytes(2)

            with self.assertRaises(AssertionError) as error:
                Icmp6UnknownMessage.from_bytes(bytes(_bytes))

            self.assertEqual(
                str(error.exception),
                (
                    "The 'type' field must not be known. "
                    f"Got: {Icmp6Type.from_int(type)!r}"
                ),
            )
