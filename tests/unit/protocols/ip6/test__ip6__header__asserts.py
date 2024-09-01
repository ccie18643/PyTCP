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
This module contains tests for the IPv6 header fields asserts.

tests/unit/protocols/ip6/test__ip6__header__asserts.py

ver 3.0.2
"""


from testslide import TestCase

from pytcp.lib.int_checks import (
    UINT_2__MAX,
    UINT_2__MIN,
    UINT_6__MAX,
    UINT_6__MIN,
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_20__MAX,
    UINT_20__MIN,
)
from pytcp.lib.net_addr import Ip6Address
from pytcp.protocols.ip6.ip6__enums import Ip6Next
from pytcp.protocols.ip6.ip6__header import Ip6Header


class TestIp6HeaderAsserts(TestCase):
    """
    The IPv6 header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the IPv6 header constructor.
        """

        self._header_args = {
            "dscp": 0,
            "ecn": 0,
            "flow": 0,
            "dlen": 0,
            "next": Ip6Next.RAW,
            "hop": 0,
            "src": Ip6Address(),
            "dst": Ip6Address(),
        }

    def test__ip6__header__dscp__under_min(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'dscp' argument is lower than the minimum supported value.
        """

        self._header_args["dscp"] = value = UINT_6__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'dscp' field must be a 6-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__dscp__over_max(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'dscp' argument is higher than the maximum supported value.
        """

        self._header_args["dscp"] = value = UINT_6__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'dscp' field must be a 6-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__ecn__under_min(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'ecn' argument is lower than the minimum supported value.
        """

        self._header_args["ecn"] = value = UINT_2__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'ecn' field must be a 2-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__ecn__over_max(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'ecn' argument is higher than the maximum supported value.
        """

        self._header_args["ecn"] = value = UINT_2__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'ecn' field must be a 2-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__flow__under_min(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'flow' argument is lower than the minimum supported value.
        """

        self._header_args["flow"] = value = UINT_20__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flow' field must be a 20-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__flow__over_max(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'flow' argument is higher than the maximum supported value.
        """

        self._header_args["flow"] = value = UINT_20__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'flow' field must be a 20-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__dlen__under_min(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'dlen' argument is lower than the minimum supported value.
        """

        self._header_args["dlen"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'dlen' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__dlen__over_max(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'dlen' argument is higher than the maximum supported value.
        """

        self._header_args["dlen"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'dlen' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__next__not_Ip6Next(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'next' argument is not an Ip6Next.
        """

        self._header_args["next"] = value = "not an Ip6Next"

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'next' field must be an Ip6Next. Got: {type(value)!r}",
        )

    def test__ip6__header__hop__under_min(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'hop' argument is lower than the minimum supported value.
        """

        self._header_args["hop"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'hop' field must be an 8-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__hop__over_max(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'hop' argument is higher than the maximum supported value.
        """

        self._header_args["hop"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'hop' field must be an 8-bit unsigned integer. Got: {value!r}",
        )

    def test__ip6__header__src__not_Ip6Address(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'src' argument is not an Ip6Address.
        """

        self._header_args["src"] = value = "not an Ip6Address"

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'src' field must be an Ip6Address. Got: {type(value)!r}",
        )

    def test__ip6__header__dst__not_Ip6Address(self) -> None:
        """
        Ensure the IPv6 header constructor raises an exception when the provided
        'dst' argument is not an Ip6Address.
        """

        self._header_args["dst"] = value = "not an Ip6Address"

        with self.assertRaises(AssertionError) as error:
            Ip6Header(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'dst' field must be an Ip6Address. Got: {type(value)!r}",
        )
