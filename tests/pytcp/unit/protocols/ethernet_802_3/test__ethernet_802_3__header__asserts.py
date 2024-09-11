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
This module contains tests for the Ethernet 802.3 header fields asserts.

tests/pytcp/unit/protocols/ethernet_802_3/test__ethernet_802_3__header__asserts.py

ver 3.0.2
"""


from typing import Any

from testslide import TestCase

from net_addr import MacAddress
from pytcp.lib.int_checks import UINT_16__MIN
from pytcp.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Header,
)


class TestEthernet8023HeaderAsserts(TestCase):
    """
    The Ethernet 802.3 header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the Ethernet 802.3 header constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "dst": MacAddress(),
            "src": MacAddress(),
            "dlen": 0,
        }

    def test__ethernet_802_3__header__dst__not_MacAddress(self) -> None:
        """
        Ensure the Ethernet 802.3 header constructor raises an exception when the
        provided 'dst' argument is not a MacAddress.
        """

        self._kwargs["dst"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            Ethernet8023Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dst' field must be a MacAddress. Got: {type(value)!r}",
        )

    def test__ethernet_802_3__header__src__not_MacAddress(self) -> None:
        """
        Ensure the Ethernet 802.3 header constructor raises an exception when the
        provided 'src' argument is not a MacAddress.
        """

        self._kwargs["src"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            Ethernet8023Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'src' field must be a MacAddress. Got: {type(value)!r}",
        )

    def test__ethernet_802_3__header__dlen__under_min(self) -> None:
        """
        Ensure the Ethernet 802.3 header constructor raises an exception when the
        provided 'dlen' argument is lower than the minimum supported value.
        """

        self._kwargs["dlen"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ethernet8023Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'dlen' field must be a 16-bit unsigned integer lower than "
            f"or equal to {ETHERNET_802_3__PAYLOAD__MAX_LEN}. Got: {value!r}",
        )

    def test__ethernet_802_3__header__dlen__over_max(self) -> None:
        """
        Ensure the Ethernet 802.3 header constructor raises an exception when the
        provided 'plen' argument is higher than the maximum supported value.
        """

        self._kwargs["dlen"] = value = ETHERNET_802_3__PAYLOAD__MAX_LEN + 1

        with self.assertRaises(AssertionError) as error:
            Ethernet8023Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'dlen' field must be a 16-bit unsigned integer lower than "
            f"or equal to {ETHERNET_802_3__PAYLOAD__MAX_LEN}. Got: {value!r}",
        )
