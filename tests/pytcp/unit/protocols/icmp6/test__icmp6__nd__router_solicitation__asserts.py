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
Module contains tests for the ICMPv6 ND Router Solicitation message assembler
& parser argument asserts.

tests/pytcp/unit/protocols/icmp6/test__icmp6__nd__router_solicitation__asserts.py

ver 3.0.2
"""

from typing import Any

from testslide import TestCase

from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_solicitation import (
    Icmp6NdRouterSolicitationCode,
    Icmp6NdRouterSolicitationMessage,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
)


class TestIcmp6NdRouterSolicitationAsserts(TestCase):
    """
    The ICMPv6 ND Router Solicitation message assembler & parser argument
    constructors assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 ND Router Solicitation message
        constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "code": Icmp6NdRouterSolicitationCode.DEFAULT,
            "cksum": 0,
            "options": Icmp6NdOptions(),
        }

    def test__icmp6__nd__router_solicitation__code__not_Icmp6NdRouterSolicitationCode(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND message constructor raises an exception when the
        provided 'code' argument is not an Icmp6NdRouterSolicitationCode.
        """

        self._kwargs["code"] = value = "not an Icmp6NdRouterSolicitationCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdRouterSolicitationMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'code' field must be an Icmp6NdRouterSolicitationCode. "
                f"Got: {type(value)!r}"
            ),
        )

    def test__icmp6__nd__router_solicitation__cksum__under_min(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Solicitation message assembler constructor
        raises an exception when the provided 'cksum' argument is lower than
        the minimum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdRouterSolicitationMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'cksum' field must be a 16-bit unsigned integer. "
                f"Got: {value!r}"
            ),
        )

    def test__icmp6__nd__router_solicitation__cksum__over_max(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Solicitation message assembler constructor
        raises an exception when the provided 'cksum' argument is higher than
        the maximum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdRouterSolicitationMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'cksum' field must be a 16-bit unsigned integer. "
                f"Got: {value!r}"
            ),
        )

    def test__icmp6__nd__router_solicitation__options__not_Icmp6NdOptions(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND message constructor raises an exception when the
        provided 'options' argument is not an Icmp6NdOptions.
        """

        self._kwargs["options"] = value = "not an Icmp6NdOptions"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdRouterSolicitationMessage(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'options' field must be an Icmp6NdOptions. "
                f"Got: {type(value)!r}"
            ),
        )


class TestIcmp6NdRouterSolicitationParserAsserts(TestCase):
    """
    The ICMPv6 ND Router Solicitation message parser argument constructor
    assert tests.
    """

    def test__icmp6__nd__router_solicitation__wrong_type(self) -> None:
        """
        Ensure the ICMPv6 ND Router Soliciataion message parser raises
        an exception when the provided '_bytes' argument contains incorrect
        'type' field.
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdRouterSolicitationMessage.from_bytes(
                b"\xff\x00\x00\xff\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            (
                "The 'type' field must be <Icmp6Type.ND__ROUTER_SOLICITATION: "
                "133>. Got: <Icmp6Type.UNKNOWN_255: 255>"
            ),
        )
