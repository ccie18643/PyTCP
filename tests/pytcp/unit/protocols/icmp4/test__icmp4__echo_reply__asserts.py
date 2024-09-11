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
Module contains tests for the ICMPv4 Echo Reply message assembler & parser
asserts.

tests/pytcp/unit/protocols/icmp4/test__icmp4__echo_reply__asserts.py

ver 3.0.2
"""


from typing import Any

from testslide import TestCase

from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.protocols.icmp4.message.icmp4_message__echo_reply import (
    ICMP4__ECHO_REPLY__LEN,
    Icmp4EchoReplyCode,
    Icmp4EchoReplyMessage,
)
from pytcp.protocols.ip4.ip4__header import IP4__PAYLOAD__MAX_LEN


class TestIcmp4EchoReplyAssemblerAsserts(TestCase):
    """
    The ICMPv4 Echo Reply message assembler constructor argument assert
    tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv4 Echo Reply message
        constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "code": Icmp4EchoReplyCode.DEFAULT,
            "cksum": 0,
            "id": 0,
            "seq": 0,
            "data": b"",
        }

    def test__icmp4__echo_reply__code__not_Icmp4EchoReplyCode(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Echo Reply message constructor raises an exception
        when the provided 'code' argument is not an Icmp4EchoReplyCode.
        """

        self._kwargs["code"] = value = "not an Icmp4EchoReplyCode"

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoReplyMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4EchoReplyCode. "
            f"Got: {type(value)!r}",
        )

    def test__icmp4__echo_reply__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message assembler constructor raises
        an exception when the provided 'cksum' argument is lower than the
        minimum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoReplyMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__echo_reply__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message assembler constructor raises
        an exception when the provided 'cksum' argument is higher than the
        maximum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoReplyMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__echo_reply__id__under_min(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message assembler constructor raises
        an exception when the provided 'id' argument is lower than the
        minimum supported value.
        """

        self._kwargs["id"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoReplyMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__echo_reply__id__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message assembler constructor raises
        an exception when the provided 'id' argument is higher than the
        maximum supported value.
        """

        self._kwargs["id"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoReplyMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__echo_reply__seq__under_min(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message assembler constructor raises
        an exception when the provided 'seq' argument is lower than the
        minimum supported value.
        """

        self._kwargs["seq"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoReplyMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'seq' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__echo_reply__seq__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message assembler constructor raises
        an exception when the provided 'seq' argument is higher than the
        maximum supported value.
        """

        self._kwargs["seq"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoReplyMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'seq' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__echo_reply__data_len__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message assembler constructor raises
        an exception when the length of the provided 'data' argument is higher
        than the maximum supported value.
        """

        value = IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REPLY__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoReplyMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'data' field length must be a 16-bit unsigned integer less than "
            f"or equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REPLY__LEN}. "
            f"Got: {value!r}",
        )


class TestIcmp4EchoReplyParserAsserts(TestCase):
    """
    The ICMPv4 Echo Reply message parser argument constructor assert tests.
    """

    def test__icmp4__echo_reply__wrong_type(self) -> None:
        """
        Ensure the ICMPv4 Echo Reply message parser raises an exception when
        the provided '_bytes' argument contains incorrect 'type' field.
        """

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoReplyMessage.from_bytes(
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            (
                "The 'type' field must be <Icmp4Type.ECHO_REPLY: 0>. "
                "Got: <Icmp4Type.UNKNOWN_255: 255>"
            ),
        )
