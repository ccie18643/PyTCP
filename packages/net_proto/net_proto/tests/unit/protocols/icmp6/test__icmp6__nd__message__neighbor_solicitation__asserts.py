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
Module contains tests for the ICMPv6 ND Neighbor Solicitation message
assembler & parser argument asserts.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__neighbor_solicitation__asserts.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Address, MacAddress
from net_proto import (
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdNeighborSolicitationCode,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
)


class TestIcmp6NdMessageNeighborSolicitationAsserts(TestCase):
    """
    The ICMPv6 ND Neighbor Solicitation message assembler & parser argument
    constructor assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 ND Neighbor Solicitation
        message constructor.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6NdNeighborSolicitationCode.DEFAULT,
            "cksum": 0,
            "target_address": Ip6Address(),
            "options": Icmp6NdOptions(),
        }

    def test__icmp6__nd__message__neighbor_solicitation__code__default_accepted(self) -> None:
        """
        Ensure the constructor accepts the DEFAULT 'code' value.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6NdMessageNeighborSolicitation(**self._kwargs)

    def test__icmp6__nd__message__neighbor_solicitation__code__not_Icmp6NdNeighborSolicitationCode(self) -> None:
        """
        Ensure the constructor raises when 'code' is not an
        Icmp6NdNeighborSolicitationCode.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        self._kwargs["code"] = value = "not an Icmp6NdNeighborSolicitationCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborSolicitation(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6NdNeighborSolicitationCode. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Icmp6NdNeighborSolicitationCode 'code' value.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__cksum__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts the minimum and maximum 16-bit
        unsigned integer values for 'cksum'.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        for cksum in (UINT_16__MIN, UINT_16__MAX):
            with self.subTest(cksum=cksum):
                Icmp6NdMessageNeighborSolicitation(**{**self._kwargs, "cksum": cksum})

    def test__icmp6__nd__message__neighbor_solicitation__cksum__under_min(self) -> None:
        """
        Ensure the constructor raises when 'cksum' is below the minimum
        16-bit unsigned integer value.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborSolicitation(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' below minimum.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__cksum__over_max(self) -> None:
        """
        Ensure the constructor raises when 'cksum' exceeds the maximum
        16-bit unsigned integer value.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborSolicitation(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' above maximum.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__target_address__accepted(self) -> None:
        """
        Ensure the constructor accepts a valid Ip6Address 'target_address'.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6NdMessageNeighborSolicitation(**{**self._kwargs, "target_address": Ip6Address("2001:db8::1")})

    def test__icmp6__nd__message__neighbor_solicitation__target_address__not_Ip6Address(self) -> None:
        """
        Ensure the constructor raises when 'target_address' is not an
        Ip6Address.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        self._kwargs["target_address"] = value = "not an Ip6Address"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborSolicitation(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'target_address' field must be an Ip6Address. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Ip6Address 'target_address' value.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__options__empty_accepted(self) -> None:
        """
        Ensure the constructor accepts an empty Icmp6NdOptions.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6NdMessageNeighborSolicitation(**{**self._kwargs, "options": Icmp6NdOptions()})

    def test__icmp6__nd__message__neighbor_solicitation__options__populated_accepted(self) -> None:
        """
        Ensure the constructor accepts an Icmp6NdOptions carrying options.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6NdMessageNeighborSolicitation(
            **{
                **self._kwargs,
                "options": Icmp6NdOptions(Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))),
            },
        )

    def test__icmp6__nd__message__neighbor_solicitation__options__not_Icmp6NdOptions(self) -> None:
        """
        Ensure the constructor raises when 'options' is not an
        Icmp6NdOptions.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        self._kwargs["options"] = value = "not an Icmp6NdOptions"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborSolicitation(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'options' field must be an Icmp6NdOptions. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Icmp6NdOptions 'options' value.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure from_buffer() accepts a frame whose type byte is
        ICMPv6 ND Neighbor Solicitation (135).

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        # 24-byte NS with zeroed reserved/target, checksum placeholder 0x0000.
        frame = b"\x87\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" b"\x00\x00\x00\x00\x00\x00\x00\x00"

        Icmp6NdMessageNeighborSolicitation.from_buffer(frame)

    def test__icmp6__nd__message__neighbor_solicitation__from_buffer__wrong_type(self) -> None:
        """
        Ensure from_buffer() raises when the 'type' field does not match
        Icmp6Type.ND__NEIGHBOR_SOLICITATION.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborSolicitation.from_buffer(
                b"\xff\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" b"\x00\x00\x00\x00\x00\x00\x00\x00",
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp6Type.ND__NEIGHBOR_SOLICITATION: 135>. Got: <Icmp6Type.UNKNOWN_255: 255>",
            msg="Unexpected assertion message for wrong 'type' byte in from_buffer().",
        )
