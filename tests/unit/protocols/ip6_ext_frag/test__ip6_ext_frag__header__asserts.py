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
This module contains tests for the IPv6 Ext Frag header fields asserts.

tests/unit/protocols/ip6/test__ip6_ext_frag__header__asserts.py

ver 3.0.0
"""


from testslide import TestCase

from pytcp.lib.int_checks import (
    UINT_13__MAX,
    UINT_13__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
)
from pytcp.protocols.ip6.ip6__enums import Ip6Next
from pytcp.protocols.ip6_ext_frag.ip6_ext_frag__header import Ip6ExtFragHeader


class TestIpExtFrag6HeaderAsserts(TestCase):
    """
    The IPv6 Ext FRag header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the IPv6 Ext Frag header constructor.
        """

        self._header_args = {
            "next": Ip6Next.RAW,
            "offset": 0,
            "flag_mf": False,
            "id": 0,
        }

    def test__ip6_ext_frag__header__next__not_Ip6Next(self) -> None:
        """
        Ensure the IPv6 Ext Frag header constructor raises an exception when
        the provided 'next' argument is not an Ip6Next.
        """

        self._header_args["next"] = value = "not an Ip6Next"

        with self.assertRaises(AssertionError) as error:
            Ip6ExtFragHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'next' field must be an Ip6Next. Got: {type(value)!r}",
        )

    def test__ip6_ext_frag__header__offset__under_min(self) -> None:
        """
        Ensure the IPv6 Ext Frag header constructor raises an exception when
        the provided 'offset' argument is lower than the minimum supported value.
        """

        self._header_args["offset"] = value = UINT_13__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6ExtFragHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6_ext_frag__header__offset__over_max(self) -> None:
        """
        Ensure the IPv6 Ext Frag header constructor raises an exception when
        the provided 'offset' argument is higher than the maximum supported value.
        """

        self._header_args["offset"] = value = UINT_13__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6ExtFragHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be a 13-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6_ext_frag__header__offset__not_8_byte_alligned(self) -> None:
        """
        Ensure the IPv6 Ext Frag header constructor raises an exception when
        the provided 'offset' argument is not 8-byte aligned.
        """

        self._header_args["offset"] = value = UINT_13__MAX - 1

        with self.assertRaises(AssertionError) as error:
            Ip6ExtFragHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'offset' field must be 8-byte aligned. Got: {value!r}",
        )

    def test__ip6_ext_frag__header__flag_mf__not_boolean(self) -> None:
        """
        Ensure the IPv6 Ext Frag header constructor raises an exception when
        the provided 'flag_mf' argument is not a boolean.
        """

        self._header_args["flag_mf"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Ip6ExtFragHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flag_mf' field must be a boolean. Got: {type(value)!r}",
        )

    def test__ip6_ext_frag__header__id__under_min(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'id' argument is lower than the minimum supported value.
        """

        self._header_args["id"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6ExtFragHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 32-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6_ext_frag__header__id__over_max(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'id' argument is higher than the maximum supported value.
        """

        self._header_args["id"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6ExtFragHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'id' field must be a 32-bit unsigned integer. Got: {value!r}",
        )
