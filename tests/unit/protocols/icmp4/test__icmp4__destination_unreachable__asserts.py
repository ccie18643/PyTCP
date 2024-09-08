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
Module contains tests for the ICMPv4 Destination Unreachable message assembler
& parser asserts.

tests/unit/protocols/icmp4/test__icmp4__destination_unreachable__asserts.py

ver 3.0.2
"""


from typing import Any

from testslide import TestCase

from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.protocols.icmp4.message.icmp4_message__destination_unreachable import (
    ICMP4__DESTINATION_UNREACHABLE__LEN,
    Icmp4DestinationUnreachableCode,
    Icmp4DestinationUnreachableMessage,
)
from pytcp.protocols.ip4.ip4__header import IP4__PAYLOAD__MAX_LEN


class TestIcmp4DestinationUnreachableAssemblerAsserts(TestCase):
    """
    The ICMPv4 Destination Unreachable message assembler constructor
    argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv4 Destination Unreachable
        message constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "code": Icmp4DestinationUnreachableCode.NETWORK,
            "mtu": None,
            "cksum": 0,
            "data": b"",
        }

    def test__icmp4__destination_unreachable__code__not_Icmp4DestinationUnreachableCode(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message constructor
        raises an exception when the provided 'code' argument is not
        an Icmp4DestinationUnreachableCode.
        """

        self._kwargs["code"] = value = "not an Icmp4DestinationUnreachableCode"

        with self.assertRaises(AssertionError) as error:
            Icmp4DestinationUnreachableMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4DestinationUnreachableCode. "
            f"Got: {type(value)!r}",
        )

    def test__icmp4__destination_unreachable__frag_no_mtu(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message assembler
        constructor raises an exception when the given 'code' argument
        equals 'FRAGMENTATION_NEEDED', but the MTU argument is not
        provided.
        """

        self._kwargs["code"] = (
            Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED
        )
        self._kwargs["mtu"] = value = None

        with self.assertRaises(AssertionError) as error:
            Icmp4DestinationUnreachableMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'mtu' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__destination_unreachable__no_frag_mtu(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message assembler
        constructor raises an exception when the given 'code' argument
        doesn't equal 'FRAGMENTATION_NEEDED', but the MTU argument is
        provided.
        """

        self._kwargs["mtu"] = value = 1500

        for code in Icmp4DestinationUnreachableCode:
            if code != Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED:
                with self.assertRaises(AssertionError) as error:
                    Icmp4DestinationUnreachableMessage(
                        *self._args, **self._kwargs
                    )

            self.assertEqual(
                str(error.exception),
                f"The 'mtu' field must not be set. Got: {value!r}",
            )

    def test__icmp4__destination_unreachable__cksum__under_min(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message assembler
        constructor raises an exception when the provided 'cksum' argument
        is lower than the minimum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4DestinationUnreachableMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__destination_unreachable__cksum__over_max(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message assembler
        constructor raises an exception when the provided 'cksum' argument
        is higher than the maximum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4DestinationUnreachableMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__destination_unreachable__mtu__under_min(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message assembler
        constructor raises an exception when the provided 'mtu' argument
        is lower than the minimum supported value.
        """

        self._kwargs["code"] = (
            Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED
        )
        self._kwargs["mtu"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4DestinationUnreachableMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'mtu' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__destination_unreachable__mtu__over_max(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message assembler
        constructor raises an exception when the provided 'mtu' argument
        is higher than the maximum supported value.
        """

        self._kwargs["code"] = (
            Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED
        )
        self._kwargs["mtu"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4DestinationUnreachableMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'mtu' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__icmp4__destination_unreachable__data_len__over_max(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message assembler
        constructor raises an exception when the length of the provided
        'data' argument is higher than the maximum supported value.
        """

        value = IP4__PAYLOAD__MAX_LEN - ICMP4__DESTINATION_UNREACHABLE__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp4DestinationUnreachableMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'data' field length must be a 16-bit unsigned integer less than "
            f"or equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__DESTINATION_UNREACHABLE__LEN}. "
            f"Got: {value!r}",
        )


class TestIcmp4DestinationUnreachableParserAsserts(TestCase):
    """
    The ICMPv4 Destination Unreachable message parser argument constructor
    assert tests.
    """

    def test__icmp4__destination_unreachable__wrong_type(self) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message parser raises
        an exception when the provided '_bytes' argument contains incorrect
        'type' field.
        """

        with self.assertRaises(AssertionError) as error:
            Icmp4DestinationUnreachableMessage.from_bytes(
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            (
                "The 'type' field must be <Icmp4Type.DESTINATION_UNREACHABLE: 3>. "
                "Got: <Icmp4Type.UNKNOWN_255: 255>"
            ),
        )
