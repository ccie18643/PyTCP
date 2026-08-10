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
Module contains tests for the ICMPv6 ND Router Solicitation message
assembler & parser argument asserts.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__router_solicitation__asserts.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import MacAddress
from net_proto import (
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp6NdMessageRouterSolicitation,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6NdRouterSolicitationCode,
)


class TestIcmp6NdMessageRouterSolicitationAsserts(TestCase):
    """
    The ICMPv6 ND Router Solicitation message assembler & parser argument
    constructors assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 ND Router Solicitation
        message constructor.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6NdRouterSolicitationCode.DEFAULT,
            "cksum": 0,
            "options": Icmp6NdOptions(),
        }

    def test__icmp6__nd__message__router_solicitation__code__not_Icmp6NdRouterSolicitationCode(self) -> None:
        """
        Ensure the constructor rejects a 'code' argument that is not an
        Icmp6NdRouterSolicitationCode instance.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        value = "not an Icmp6NdRouterSolicitationCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterSolicitation(**{**self._kwargs, "code": value})

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6NdRouterSolicitationCode. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Icmp6NdRouterSolicitationCode 'code'.",
        )

    def test__icmp6__nd__message__router_solicitation__code__default_accepted(self) -> None:
        """
        Ensure Icmp6NdRouterSolicitationCode.DEFAULT is accepted.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        message = Icmp6NdMessageRouterSolicitation(**self._kwargs)

        self.assertEqual(
            message.code,
            Icmp6NdRouterSolicitationCode.DEFAULT,
            msg="Constructed message.code must equal Icmp6NdRouterSolicitationCode.DEFAULT.",
        )

    def test__icmp6__nd__message__router_solicitation__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument below the
        16-bit unsigned minimum.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterSolicitation(**{**self._kwargs, "cksum": value})

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' below UINT_16__MIN.",
        )

    def test__icmp6__nd__message__router_solicitation__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument above the
        16-bit unsigned maximum.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterSolicitation(**{**self._kwargs, "cksum": value})

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' above UINT_16__MAX.",
        )

    def test__icmp6__nd__message__router_solicitation__cksum__bounds_accepted(self) -> None:
        """
        Ensure both boundary values of the 'cksum' 16-bit range are
        accepted.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        for value in (UINT_16__MIN, UINT_16__MAX):
            with self.subTest(cksum=value):
                message = Icmp6NdMessageRouterSolicitation(**{**self._kwargs, "cksum": value})

                self.assertEqual(
                    message.cksum,
                    value,
                    msg=f"Constructed message.cksum must equal {value}.",
                )

    def test__icmp6__nd__message__router_solicitation__options__not_Icmp6NdOptions(self) -> None:
        """
        Ensure the constructor rejects an 'options' argument that is not
        an Icmp6NdOptions instance.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        value = "not an Icmp6NdOptions"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterSolicitation(**{**self._kwargs, "options": value})

        self.assertEqual(
            str(error.exception),
            f"The 'options' field must be an Icmp6NdOptions. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Icmp6NdOptions 'options'.",
        )

    def test__icmp6__nd__message__router_solicitation__options__empty_accepted(self) -> None:
        """
        Ensure an empty Icmp6NdOptions is accepted.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        options = Icmp6NdOptions()

        message = Icmp6NdMessageRouterSolicitation(**{**self._kwargs, "options": options})

        self.assertEqual(
            message.options,
            options,
            msg="Constructed message.options must equal the provided Icmp6NdOptions().",
        )

    def test__icmp6__nd__message__router_solicitation__options__populated_accepted(self) -> None:
        """
        Ensure a populated Icmp6NdOptions (carrying an SLLA option) is
        accepted.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        options = Icmp6NdOptions(Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")))

        message = Icmp6NdMessageRouterSolicitation(**{**self._kwargs, "options": options})

        self.assertEqual(
            message.options,
            options,
            msg="Constructed message.options must equal the provided populated Icmp6NdOptions.",
        )


class TestIcmp6NdMessageRouterSolicitationParserAsserts(TestCase):
    """
    The ICMPv6 ND Router Solicitation message parser argument constructor
    assert tests.
    """

    def test__icmp6__nd__message__router_solicitation__wrong_type(self) -> None:
        """
        Ensure Icmp6NdMessageRouterSolicitation.from_buffer raises on a
        buffer whose 'type' field is not ND__ROUTER_SOLICITATION.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterSolicitation.from_buffer(b"\xff\x00\x00\xff\x00\x00\x00\x00")

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp6Type.ND__ROUTER_SOLICITATION: 133>. Got: <Icmp6Type.UNKNOWN_255: 255>",
            msg="Unexpected assertion message for wrong ICMPv6 'type' byte.",
        )

    def test__icmp6__nd__message__router_solicitation__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure from_buffer parses a well-formed 8-byte header whose type
        is ND__ROUTER_SOLICITATION (133).

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        message = Icmp6NdMessageRouterSolicitation.from_buffer(b"\x85\x00\x00\x00\x00\x00\x00\x00")

        self.assertEqual(
            message.code,
            Icmp6NdRouterSolicitationCode.DEFAULT,
            msg="Parsed message.code must be Icmp6NdRouterSolicitationCode.DEFAULT.",
        )
        self.assertEqual(
            message.options,
            Icmp6NdOptions(),
            msg="Parsed message.options must be an empty Icmp6NdOptions.",
        )
