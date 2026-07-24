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
Module contains tests for the ICMPv6 ND Router Advertisement message
assembler & parser argument asserts.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__router_advertisement__asserts.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import MacAddress
from net_proto import (
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6NdRouterAdvertisementCode,
)


class TestIcmp6NdMessageRouterAdvertisementAsserts(TestCase):
    """
    The ICMPv6 ND Router Advertisement message assembler & parser argument
    constructor assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 ND Router Advertisement
        message constructor.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6NdRouterAdvertisementCode.DEFAULT,
            "cksum": 0,
            "hop": 0,
            "flag_m": False,
            "flag_o": False,
            "router_lifetime": 0,
            "reachable_time": 0,
            "retrans_timer": 0,
            "options": Icmp6NdOptions(),
        }

    def test__icmp6__nd__message__router_advertisement__code__default_accepted(self) -> None:
        """
        Ensure the constructor accepts the DEFAULT 'code' value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        Icmp6NdMessageRouterAdvertisement(**self._kwargs)

    def test__icmp6__nd__message__router_advertisement__code__not_Icmp6NdRouterAdvertisementCode(self) -> None:
        """
        Ensure the constructor raises when 'code' is not an
        Icmp6NdRouterAdvertisementCode.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["code"] = value = "not an Icmp6NdRouterAdvertisementCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6NdRouterAdvertisementCode. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Icmp6NdRouterAdvertisementCode 'code' value.",
        )

    def test__icmp6__nd__message__router_advertisement__cksum__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts the minimum and maximum 16-bit
        unsigned integer values for 'cksum'.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        for cksum in (UINT_16__MIN, UINT_16__MAX):
            with self.subTest(cksum=cksum):
                Icmp6NdMessageRouterAdvertisement(**{**self._kwargs, "cksum": cksum})

    def test__icmp6__nd__message__router_advertisement__cksum__under_min(self) -> None:
        """
        Ensure the constructor raises when 'cksum' is below the minimum
        16-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' below minimum.",
        )

    def test__icmp6__nd__message__router_advertisement__cksum__over_max(self) -> None:
        """
        Ensure the constructor raises when 'cksum' exceeds the maximum
        16-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'cksum' above maximum.",
        )

    def test__icmp6__nd__message__router_advertisement__hop__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts the minimum and maximum 8-bit
        unsigned integer values for 'hop'.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        for hop in (UINT_8__MIN, UINT_8__MAX):
            with self.subTest(hop=hop):
                Icmp6NdMessageRouterAdvertisement(**{**self._kwargs, "hop": hop})

    def test__icmp6__nd__message__router_advertisement__hop__under_min(self) -> None:
        """
        Ensure the constructor raises when 'hop' is below the minimum
        8-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["hop"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'hop' field must be an 8-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'hop' below minimum.",
        )

    def test__icmp6__nd__message__router_advertisement__hop__over_max(self) -> None:
        """
        Ensure the constructor raises when 'hop' exceeds the maximum
        8-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["hop"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'hop' field must be an 8-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'hop' above maximum.",
        )

    def test__icmp6__nd__message__router_advertisement__flag_m__bool_accepted(self) -> None:
        """
        Ensure the constructor accepts True and False for 'flag_m'.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        for flag_m in (False, True):
            with self.subTest(flag_m=flag_m):
                Icmp6NdMessageRouterAdvertisement(**{**self._kwargs, "flag_m": flag_m})

    def test__icmp6__nd__message__router_advertisement__flag_m__not_boolean(self) -> None:
        """
        Ensure the constructor raises when 'flag_m' is not a boolean.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["flag_m"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_m' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-bool 'flag_m' value.",
        )

    def test__icmp6__nd__message__router_advertisement__flag_o__bool_accepted(self) -> None:
        """
        Ensure the constructor accepts True and False for 'flag_o'.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        for flag_o in (False, True):
            with self.subTest(flag_o=flag_o):
                Icmp6NdMessageRouterAdvertisement(**{**self._kwargs, "flag_o": flag_o})

    def test__icmp6__nd__message__router_advertisement__flag_o__not_boolean(self) -> None:
        """
        Ensure the constructor raises when 'flag_o' is not a boolean.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["flag_o"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_o' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-bool 'flag_o' value.",
        )

    def test__icmp6__nd__message__router_advertisement__router_lifetime__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts the minimum and maximum 16-bit
        unsigned integer values for 'router_lifetime'.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        for router_lifetime in (UINT_16__MIN, UINT_16__MAX):
            with self.subTest(router_lifetime=router_lifetime):
                Icmp6NdMessageRouterAdvertisement(**{**self._kwargs, "router_lifetime": router_lifetime})

    def test__icmp6__nd__message__router_advertisement__router_lifetime__under_min(self) -> None:
        """
        Ensure the constructor raises when 'router_lifetime' is below the
        minimum 16-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["router_lifetime"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'router_lifetime' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'router_lifetime' below minimum.",
        )

    def test__icmp6__nd__message__router_advertisement__router_lifetime__over_max(self) -> None:
        """
        Ensure the constructor raises when 'router_lifetime' exceeds the
        maximum 16-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["router_lifetime"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'router_lifetime' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'router_lifetime' above maximum.",
        )

    def test__icmp6__nd__message__router_advertisement__reachable_time__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts the minimum and maximum 32-bit
        unsigned integer values for 'reachable_time'.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        for reachable_time in (UINT_32__MIN, UINT_32__MAX):
            with self.subTest(reachable_time=reachable_time):
                Icmp6NdMessageRouterAdvertisement(**{**self._kwargs, "reachable_time": reachable_time})

    def test__icmp6__nd__message__router_advertisement__reachable_time__under_min(self) -> None:
        """
        Ensure the constructor raises when 'reachable_time' is below the
        minimum 32-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["reachable_time"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'reachable_time' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'reachable_time' below minimum.",
        )

    def test__icmp6__nd__message__router_advertisement__reachable_time__over_max(self) -> None:
        """
        Ensure the constructor raises when 'reachable_time' exceeds the
        maximum 32-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["reachable_time"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'reachable_time' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'reachable_time' above maximum.",
        )

    def test__icmp6__nd__message__router_advertisement__retrans_timer__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts the minimum and maximum 32-bit
        unsigned integer values for 'retrans_timer'.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        for retrans_timer in (UINT_32__MIN, UINT_32__MAX):
            with self.subTest(retrans_timer=retrans_timer):
                Icmp6NdMessageRouterAdvertisement(**{**self._kwargs, "retrans_timer": retrans_timer})

    def test__icmp6__nd__message__router_advertisement__retrans_timer__under_min(self) -> None:
        """
        Ensure the constructor raises when 'retrans_timer' is below the
        minimum 32-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["retrans_timer"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'retrans_timer' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'retrans_timer' below minimum.",
        )

    def test__icmp6__nd__message__router_advertisement__retrans_timer__over_max(self) -> None:
        """
        Ensure the constructor raises when 'retrans_timer' exceeds the
        maximum 32-bit unsigned integer value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["retrans_timer"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'retrans_timer' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'retrans_timer' above maximum.",
        )

    def test__icmp6__nd__message__router_advertisement__options__empty_accepted(self) -> None:
        """
        Ensure the constructor accepts an empty Icmp6NdOptions.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        Icmp6NdMessageRouterAdvertisement(**{**self._kwargs, "options": Icmp6NdOptions()})

    def test__icmp6__nd__message__router_advertisement__options__populated_accepted(self) -> None:
        """
        Ensure the constructor accepts an Icmp6NdOptions carrying options.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        Icmp6NdMessageRouterAdvertisement(
            **{
                **self._kwargs,
                "options": Icmp6NdOptions(Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))),
            },
        )

    def test__icmp6__nd__message__router_advertisement__options__not_Icmp6NdOptions(self) -> None:
        """
        Ensure the constructor raises when 'options' is not an
        Icmp6NdOptions.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self._kwargs["options"] = value = "not an Icmp6NdOptions"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'options' field must be an Icmp6NdOptions. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-Icmp6NdOptions 'options' value.",
        )

    def test__icmp6__nd__message__router_advertisement__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure from_buffer() accepts a frame whose type byte is
        ICMPv6 ND Router Advertisement (134).

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        # 16-byte RA with zeroed fields, checksum placeholder 0x0000.
        frame = b"\x86\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        Icmp6NdMessageRouterAdvertisement.from_buffer(frame)

    def test__icmp6__nd__message__router_advertisement__from_buffer__wrong_type(self) -> None:
        """
        Ensure from_buffer() raises when the 'type' field does not match
        Icmp6Type.ND__ROUTER_ADVERTISEMENT.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement.from_buffer(
                b"\xff\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp6Type.ND__ROUTER_ADVERTISEMENT: 134>. Got: <Icmp6Type.UNKNOWN_255: 255>",
            msg="Unexpected assertion message for wrong 'type' byte in from_buffer().",
        )
