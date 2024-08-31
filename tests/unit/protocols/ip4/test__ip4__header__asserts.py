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
This module contains tests for the IPv4 header fields asserts.

tests/unit/protocols/ip4/test__ip4__header__asserts.py

ver 3.0.2
"""


from testslide import TestCase

from pytcp.lib.int_checks import (
    UINT_2__MAX,
    UINT_2__MIN,
    UINT_4__MAX,
    UINT_6__MAX,
    UINT_6__MIN,
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_13__MAX,
    UINT_13__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
)
from pytcp.lib.ip4_address import Ip4Address
from pytcp.protocols.ip4.ip4__enums import Ip4Proto
from pytcp.protocols.ip4.ip4__header import IP4__HEADER__LEN, Ip4Header


class TestIp4HeaderAsserts(TestCase):
    """
    The IPv4 header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the IPv4 header constructor.
        """

        self._header_args = {
            "hlen": IP4__HEADER__LEN,
            "dscp": 0,
            "ecn": 0,
            "plen": IP4__HEADER__LEN,
            "id": 0,
            "flag_mf": False,
            "flag_df": False,
            "offset": 0,
            "ttl": 0,
            "proto": Ip4Proto.RAW,
            "cksum": 0,
            "src": Ip4Address(0),
            "dst": Ip4Address(0),
        }

    def test__ip4__header__hlen__under_min(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'hlen' argument is lower than the minimum supported value.
        """

        self._header_args["hlen"] = value = IP4__HEADER__LEN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'hlen' field must be a 4-bit unsigned integer greater than or equal to 20. Got: {value!r}",
        )

    def test__ip4__header__hlen__over_max(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'hlen' argument is higher than the maximum supported value.
        """

        self._header_args["hlen"] = value = UINT_4__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'hlen' field must be a 4-bit unsigned integer greater than or equal to 20. Got: {value!r}",
        )

    def test__ip4__header__dscp__under_min(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'dscp' argument is lower than the minimum supported value.
        """

        self._header_args["dscp"] = value = UINT_6__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'dscp' field must be a 6-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__dscp__over_max(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'dscp' argument is higher than the maximum supported value.
        """

        self._header_args["dscp"] = value = UINT_6__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'dscp' field must be a 6-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__ecn__under_min(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'ecn' argument is lower than the minimum supported value.
        """

        self._header_args["ecn"] = value = UINT_2__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'ecn' field must be a 2-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__ecn__over_max(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'ecn' argument is higher than the maximum supported value.
        """

        self._header_args["ecn"] = value = UINT_2__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'ecn' field must be a 2-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__plen__under_min(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'plen' argument is lower than the minimum supported value.
        """

        self._header_args["plen"] = value = IP4__HEADER__LEN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'plen' field must be a 16-bit unsigned integer greater than or equal to 20. Got: {value!r}",
        )

    def test__ip4__header__plen__over_max(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'plen' argument is higher than the maximum supported value.
        """

        self._header_args["plen"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'plen' field must be a 16-bit unsigned integer greater than or equal to 20. Got: {value!r}",
        )

    def test__ip4__header__id__under_min(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'id' argument is lower than the minimum supported value.
        """

        self._header_args["id"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__id__over_max(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'id' argument is higher than the maximum supported value.
        """

        self._header_args["id"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__flag_df__not_boolean(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'flag_df' argument is not a boolean.
        """

        self._header_args["flag_df"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flag_df' field must be a boolean. Got: {type(value)!r}",
        )

    def test__ip4__header__flag_mf__not_boolean(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'flag_mf' argument is not a boolean.
        """

        self._header_args["flag_mf"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flag_mf' field must be a boolean. Got: {type(value)!r}",
        )

    def test__ip4__header__offset__under_min(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'offset' argument is lower than the minimum supported value.
        """

        self._header_args["offset"] = value = UINT_13__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__offset__over_max(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'offset' argument is higher than the maximum supported value.
        """

        self._header_args["offset"] = value = UINT_13__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__offset__not_8_byte_alligned(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'offset' argument is not 8-byte aligned.
        """

        self._header_args["offset"] = value = UINT_13__MAX - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be 8-byte aligned. Got: {value!r}",
        )

    def test__ip4__header__ttl__under_min(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'ttl' argument is lower than the minimum supported value.
        """

        self._header_args["ttl"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'ttl' field must be an 8-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__ttl__over_max(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'ttl' argument is higher than the maximum supported value.
        """

        self._header_args["ttl"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'ttl' field must be an 8-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__proto__not_Ip4Proto(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'proto' argument is not an Ip4Proto.
        """

        self._header_args["proto"] = value = "not an Ip4Proto"

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'proto' field must be an Ip4Proto. Got: {type(value)!r}",
        )

    def test__ip4__header__cksum__under_min(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'cksum' argument is lower than the minimum supported value.
        """

        self._header_args["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__cksum__over_max(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'cksum' argument is higher than the maximum supported value.
        """

        self._header_args["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__ip4__header__src__not_ip4_address(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'src' argument is not a Ip4Address.
        """

        self._header_args["src"] = value = 0

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'src' field must be an Ip4Address. Got: {type(value)!r}",
        )

    def test__ip4__header__dst__not_ip4_address(self) -> None:
        """
        Ensure the IPv4 header constructor raises an exception when the provided
        'dst' argument is not a Ip4Address.
        """

        self._header_args["dst"] = value = 0

        with self.assertRaises(AssertionError) as error:
            Ip4Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'dst' field must be an Ip4Address. Got: {type(value)!r}",
        )
