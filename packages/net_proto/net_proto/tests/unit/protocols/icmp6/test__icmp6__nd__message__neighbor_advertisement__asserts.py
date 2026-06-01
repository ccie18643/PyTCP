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
Module contains tests for the ICMPv6 ND Neighbor Advertisement message
assembler & parser argument asserts.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__neighbor_advertisement__asserts.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_addr import Ip6Address, MacAddress
from net_proto import (
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdNeighborAdvertisementCode,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
)


class TestIcmp6NdMessageNeighborAdvertisementAsserts(TestCase):
    """
    The ICMPv6 ND Neighbor Advertisement message assembler & parser argument
    constructor assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 ND Neighbor Advertisement
        message constructor.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6NdNeighborAdvertisementCode.DEFAULT,
            "cksum": 0,
            "target_address": Ip6Address(),
            "options": Icmp6NdOptions(),
        }

    def test__icmp6__nd__message__neighbor_advertisement__code__default_accepted(self) -> None:
        """
        Ensure the constructor accepts the DEFAULT 'code' value.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        Icmp6NdMessageNeighborAdvertisement(**self._kwargs)

    def test__icmp6__nd__message__neighbor_advertisement__code__not_Icmp6NdNeighborAdvertisementCode(self) -> None:
        """
        Ensure the constructor raises when 'code' is not an
        Icmp6NdNeighborAdvertisementCode.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self._kwargs["code"] = value = "not an Icmp6NdNeighborAdvertisementCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6NdNeighborAdvertisementCode. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Icmp6NdNeighborAdvertisementCode 'code' value.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__cksum__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts the minimum and maximum 16-bit
        unsigned integer values for 'cksum'.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        for cksum in (UINT_16__MIN, UINT_16__MAX):
            with self.subTest(cksum=cksum):
                Icmp6NdMessageNeighborAdvertisement(**{**self._kwargs, "cksum": cksum})

    def test__icmp6__nd__message__neighbor_advertisement__cksum__under_min(self) -> None:
        """
        Ensure the constructor raises when 'cksum' is below the minimum
        16-bit unsigned integer value.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' below minimum.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__cksum__over_max(self) -> None:
        """
        Ensure the constructor raises when 'cksum' exceeds the maximum
        16-bit unsigned integer value.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' above maximum.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__flag_r__bool_accepted(self) -> None:
        """
        Ensure the constructor accepts 'flag_r' True/False.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        for flag_r in (False, True):
            with self.subTest(flag_r=flag_r):
                Icmp6NdMessageNeighborAdvertisement(**{**self._kwargs, "flag_r": flag_r})

    def test__icmp6__nd__message__neighbor_advertisement__flag_r__not_boolean(self) -> None:
        """
        Ensure the constructor raises when 'flag_r' is not a boolean.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self._kwargs["flag_r"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_r' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_r' value.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__flag_s__bool_accepted(self) -> None:
        """
        Ensure the constructor accepts 'flag_s' True/False.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        for flag_s in (False, True):
            with self.subTest(flag_s=flag_s):
                Icmp6NdMessageNeighborAdvertisement(**{**self._kwargs, "flag_s": flag_s})

    def test__icmp6__nd__message__neighbor_advertisement__flag_s__not_boolean(self) -> None:
        """
        Ensure the constructor raises when 'flag_s' is not a boolean.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self._kwargs["flag_s"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_s' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_s' value.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__flag_o__bool_accepted(self) -> None:
        """
        Ensure the constructor accepts 'flag_o' True/False.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        for flag_o in (False, True):
            with self.subTest(flag_o=flag_o):
                Icmp6NdMessageNeighborAdvertisement(**{**self._kwargs, "flag_o": flag_o})

    def test__icmp6__nd__message__neighbor_advertisement__flag_o__not_boolean(self) -> None:
        """
        Ensure the constructor raises when 'flag_o' is not a boolean.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self._kwargs["flag_o"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_o' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-boolean 'flag_o' value.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__target_address__accepted(self) -> None:
        """
        Ensure the constructor accepts a valid Ip6Address 'target_address'.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        Icmp6NdMessageNeighborAdvertisement(**{**self._kwargs, "target_address": Ip6Address("2001:db8::1")})

    def test__icmp6__nd__message__neighbor_advertisement__target_address__not_Ip6Address(self) -> None:
        """
        Ensure the constructor raises when 'target_address' is not an
        Ip6Address.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self._kwargs["target_address"] = value = "not an Ip6Address"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'target_address' field must be an Ip6Address. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Ip6Address 'target_address' value.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__options__empty_accepted(self) -> None:
        """
        Ensure the constructor accepts an empty Icmp6NdOptions.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        Icmp6NdMessageNeighborAdvertisement(**{**self._kwargs, "options": Icmp6NdOptions()})

    def test__icmp6__nd__message__neighbor_advertisement__options__populated_accepted(self) -> None:
        """
        Ensure the constructor accepts an Icmp6NdOptions carrying options.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        Icmp6NdMessageNeighborAdvertisement(
            **{
                **self._kwargs,
                "options": Icmp6NdOptions(Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))),
            },
        )

    def test__icmp6__nd__message__neighbor_advertisement__options__not_Icmp6NdOptions(self) -> None:
        """
        Ensure the constructor raises when 'options' is not an
        Icmp6NdOptions.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self._kwargs["options"] = value = "not an Icmp6NdOptions"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'options' field must be an Icmp6NdOptions. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Icmp6NdOptions 'options' value.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure from_buffer() accepts a frame whose type byte is
        ICMPv6 ND Neighbor Advertisement (136).

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        # 24-byte NA with zero flags/target, checksum and reserved all zero
        frame = b"\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" b"\x00\x00\x00\x00\x00\x00\x00\x00"

        Icmp6NdMessageNeighborAdvertisement.from_buffer(frame)

    def test__icmp6__nd__message__neighbor_advertisement__from_buffer__wrong_type(self) -> None:
        """
        Ensure from_buffer() raises when the 'type' field does not match
        Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageNeighborAdvertisement.from_buffer(
                b"\xff\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" b"\x00\x00\x00\x00\x00\x00\x00\x00",
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT: 136>. Got: <Icmp6Type.UNKNOWN_255: 255>",
            msg="Unexpected assertion message for wrong 'type' byte in from_buffer().",
        )


class TestIcmp6NdMessageOptionAccessors(TestCase):
    """
    The ICMPv6 ND message bare option-accessor tests.
    """

    def test__icmp6__nd__message__slla_accessor_returns_option_value(self) -> None:
        """
        Ensure the message-level 'slla' accessor returns the Source
        Link-Layer Address carried by the message's SLLA option,
        matching the bare (un-prefixed) option-accessor naming used
        across the other protocol families.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        mac = MacAddress("02:00:00:00:00:91")
        message = Icmp6NdMessageNeighborAdvertisement(
            code=Icmp6NdNeighborAdvertisementCode.DEFAULT,
            cksum=0,
            target_address=Ip6Address(),
            options=Icmp6NdOptions(Icmp6NdOptionSlla(mac)),
        )

        self.assertEqual(
            message.slla,
            mac,
            msg="Icmp6NdMessage.slla must return the SLLA option's MacAddress.",
        )

    def test__icmp6__nd__message__slla_accessor_none_when_absent(self) -> None:
        """
        Ensure the message-level 'slla' accessor returns None when the
        message carries no SLLA option.

        Reference: RFC 4861 §4.6.1 (Source Link-Layer Address option).
        """

        message = Icmp6NdMessageNeighborAdvertisement(
            code=Icmp6NdNeighborAdvertisementCode.DEFAULT,
            cksum=0,
            target_address=Ip6Address(),
            options=Icmp6NdOptions(),
        )

        self.assertIsNone(
            message.slla,
            msg="Icmp6NdMessage.slla must be None when no SLLA option is present.",
        )
