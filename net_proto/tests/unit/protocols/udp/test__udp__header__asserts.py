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
This module contains tests for the UDP header fields asserts.

net_proto/tests/unit/protocols/udp/test__udp__header__asserts.py

ver 3.0.4
"""


from typing import Any

from net_proto import UINT_16__MAX, UINT_16__MIN, UdpHeader
from testslide import TestCase


class TestUdpHeaderAsserts(TestCase):
    """
    The UDP header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the UDP header constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "sport": 0,
            "dport": 0,
            "plen": 0,
            "cksum": 0,
        }

    def test__udp__header__sport__under_min(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the provided
        'sport' argument is lower than the minimum supported value.
        """

        self._kwargs["sport"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sport' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__udp__header__sport__over_max(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the provided
        'sport' argument is higher than the maximum supported value.
        """

        self._kwargs["sport"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sport' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__udp__assembler__dport__under_min(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the provided
        'dport' argument is lower than the minimum supported value.
        """

        self._kwargs["dport"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dport' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__udp__assembler__dport__over_max(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the provided
        'dport' argument is higher than the maximum supported value.
        """

        self._kwargs["dport"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dport' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__udp__assembler__plen__under_min(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the provided
        'plen' argument is lower than the minimum supported value.
        """

        self._kwargs["plen"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'plen' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__udp__assembler__plen__over_max(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the provided
        'plen' argument is higher than the maximum supported value.
        """

        self._kwargs["plen"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'plen' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__udp__assembler__cksum__under_min(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the provided
        'cksum' argument is lower than the minimum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__udp__assembler__cksum__over_max(self) -> None:
        """
        Ensure the UDP header constructor raises an exception when the provided
        'cksum' argument is higher than the maximum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            UdpHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )
