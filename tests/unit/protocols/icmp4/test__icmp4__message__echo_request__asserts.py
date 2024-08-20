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
This module contains tests for the ICMPv4 Echo Request message assembler
asserts.

tests/unit/protocols/icmp4/test__icmp4__message__echo_request__asserts.py

ver 3.0.0
"""

from testslide import TestCase

from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.protocols.icmp4.message.icmp4_message__echo_request import (
    ICMP4__ECHO_REQUEST__LEN,
    Icmp4EchoRequestCode,
    Icmp4EchoRequestMessage,
)
from pytcp.protocols.ip4.ip4__header import IP4__PAYLOAD__MAX_LEN


class TestIcmp4MessageEchoRequestAsserts(TestCase):
    """
    The ICMPv4 Echo Request message assembler & parser constructors
    argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv4 Echo Request message
        constructor.
        """

        self._message_args = {
            "code": Icmp4EchoRequestCode.DEFAULT,
            "cksum": 0,
            "id": 0,
            "seq": 0,
            "data": b"",
        }

    def test__icmp4__message__echo_request__code__not_Icmp4EchoRequestCode(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Echo Request message constructor raises an exception
        when the provided 'code' argument is not an Icmp4EchoRequestCode.
        """

        self._message_args["code"] = value = "not an Icmp4EchoRequestCode"

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoRequestMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4EchoRequestCode. Got: {type(value)!r}",
        )

    def test__icmp4__message__echo_request__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message assembler constructor raises
        an exception when the provided 'cksum' argument is lower than the
        minimum supported value.
        """

        self._message_args["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoRequestMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp4__message__echo_request__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message assembler constructor raises
        an exception when the provided 'cksum' argument is higher than the
        maximum supported value.
        """

        self._message_args["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoRequestMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp4__message__echo_request__id__under_min(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message assembler constructor raises
        an exception when the provided 'id' argument is lower than the
        minimum supported value.
        """

        self._message_args["id"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoRequestMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp4__message__echo_request__id__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message assembler constructor raises
        an exception when the provided 'id' argument is higher than the
        maximum supported value.
        """

        self._message_args["id"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoRequestMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp4__message__echo_request__seq__under_min(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message assembler constructor raises
        an exception when the provided 'seq' argument is lower than the
        minimum supported value.
        """

        self._message_args["seq"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoRequestMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'seq' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp4__message__echo_request__seq__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message assembler constructor raises
        an exception when the provided 'seq' argument is higher than the
        maximum supported value.
        """

        self._message_args["seq"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoRequestMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'seq' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp4__message__echo_request__data_len__over_max(self) -> None:
        """
        Ensure the ICMPv4 Echo Request message assembler constructor raises
        an exception when the length of the provided 'data' argument is higher
        than the maximum supported value.
        """

        value = IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REQUEST__LEN + 1
        self._message_args["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp4EchoRequestMessage(
                **self._message_args,  # type: ignore
            )

        self.assertEqual(
            str(error.exception),
            f"The 'data' field length must be a 16-bit unsigned integer less than or equal "
            f"to {IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REQUEST__LEN}. Got: {value!r}",
        )
