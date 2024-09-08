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
This module contains tests for the Ethernet II header fields asserts.

tests/unit/protocols/ethernet/test__header__asserts.py

ver 3.0.2
"""


from typing import Any

from testslide import TestCase

from pytcp.lib.net_addr import MacAddress
from pytcp.protocols.ethernet.ethernet__enums import EthernetType
from pytcp.protocols.ethernet.ethernet__header import EthernetHeader


class TestEthernetHeaderAsserts(TestCase):
    """
    The Ethernet header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the Ethernet header constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "dst": MacAddress(),
            "src": MacAddress(),
            "type": EthernetType.RAW,
        }

    def test__ethernet_header__dst__not_MacAddress(self) -> None:
        """
        Ensure the Ethernet header constructor raises an exception when the
        provided 'dst' argument is not a MacAddress.
        """

        self._kwargs["dst"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            EthernetHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dst' field must be a MacAddress. Got: {type(value)!r}",
        )

    def test__ethernet__header__src__not_MacAddress(self) -> None:
        """
        Ensure the Ethernet header constructor raises an exception when the
        provided 'src' argument is not a MacAddress.
        """

        self._kwargs["src"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            EthernetHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'src' field must be a MacAddress. Got: {type(value)!r}",
        )

    def test__ethernet__header__type__not_EthernetType(self) -> None:
        """
        Ensure the Ethernet header constructor raises an exception when the
        provided 'type' argument is not an EthernetType.
        """

        self._kwargs["type"] = value = "not an EthernetType"

        with self.assertRaises(AssertionError) as error:
            EthernetHeader(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an EthernetType. Got: {type(value)!r}",
        )
