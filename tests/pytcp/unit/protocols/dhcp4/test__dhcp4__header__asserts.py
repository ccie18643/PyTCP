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
This module contains tests for the DHCPv4 header fields asserts.

tests/pytcp/unit/protocols/arp/test__dhcp4__header__asserts.py

ver 3.0.2
"""


from typing import Any

from testslide import TestCase

from net_addr import Ip4Address, MacAddress
from pytcp.lib.int_checks import (
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
)
from pytcp.protocols.dhcp4.dhcp4__enums import Dhcp4Operation
from pytcp.protocols.dhcp4.dhcp4__header import (
    DHCP4__HEADER__FILE__MAX_LEN,
    DHCP4__HEADER__SNAME__MAX_LEN,
    Dhcp4Header,
)


class TestDhcp4HeaderAsserts(TestCase):
    """
    The DHCPv4 header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ARP header constructor.
        """

        self._args: list[Any] = []
        self._kwargs: dict[str, Any] = {
            "oper": Dhcp4Operation.REQUEST,
            "hops": 0,
            "xid": 0x12345678,
            "secs": 0,
            "flag_b": False,
            "ciaddr": Ip4Address(),
            "yiaddr": Ip4Address(),
            "siaddr": Ip4Address(),
            "giaddr": Ip4Address(),
            "chaddr": MacAddress(),
            "sname": "",
            "file": "",
        }

    def test__dhcp4__header__oper__not_Dhcp4Operation(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'oper' argument is not a Dhcp4Operation.
        """

        self._kwargs["oper"] = value = "not a Dhcp4Operation"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'oper' field must be a Dhcp4Operation. Got: {type(value)!r}",
        )

    def test__dhcp4__header__hops__under_min(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'hops' argument is lower than the minimum supported value.
        """

        self._kwargs["hops"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'hops' field must be an 8-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__dhcp4__header__hops__over_max(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'hops' argument is higher than the maximum supported value.
        """

        self._kwargs["hops"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'hops' field must be an 8-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__dhcp4__header__xid__under_min(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'xid' argument is lower than the minimum supported value.
        """

        self._kwargs["xid"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'xid' field must be a 32-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__dhcp4__header__xid__over_max(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'xid' argument is higher than the maximum supported value.
        """

        self._kwargs["xid"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'xid' field must be a 32-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__dhcp4__header__secs__under_min(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'secs' argument is lower than the minimum supported value.
        """

        self._kwargs["secs"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'secs' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__dhcp4__header__secs__over_max(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'secs' argument is higher than the maximum supported value.
        """

        self._kwargs["secs"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'secs' field must be a 16-bit unsigned integer. "
            f"Got: {value!r}",
        )

    def test__dhcp4__header__flag_b__not_boolean(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'flag_b' argument is not a boolean.
        """

        self._kwargs["flag_b"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_b' field must be a boolean. Got: {type(value)!r}",
        )

    def test__dhcp4__header__ciaddr__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'ciaddr' argument is not an Ip4Address.
        """

        self._kwargs["ciaddr"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ciaddr' field must be an Ip4Address. Got: {type(value)!r}",
        )

    def test__dhcp4__header__yiaddr__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'yiaddr' argument is not an Ip4Address.
        """

        self._kwargs["yiaddr"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'yiaddr' field must be an Ip4Address. Got: {type(value)!r}",
        )

    def test__dhcp4__header__siaddr__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'siaddr' argument is not an Ip4Address.
        """

        self._kwargs["siaddr"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'siaddr' field must be an Ip4Address. Got: {type(value)!r}",
        )

    def test__dhcp4__header__giaddr__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'giaddr' argument is not an Ip4Address.
        """

        self._kwargs["giaddr"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'giaddr' field must be an Ip4Address. Got: {type(value)!r}",
        )

    def test__dhcp4__header__chaddr__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'chaddr' argument is not an Ip4Address.
        """

        self._kwargs["chaddr"] = value = "not an MacAddress"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'chaddr' field must be a MacAddress. Got: {type(value)!r}",
        )

    def test__dhcp4__header__sname__not_string(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'sname' argument is not a string.
        """

        self._kwargs["sname"] = value = b"not a string"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sname' field must be a string. Got: {type(value)!r}",
        )

    def test__dhcp4__header__sname__over_max_len(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        length of provided 'sname' argument is over maximum allowable
        value.
        """

        self._kwargs["sname"] = value = "X" * (
            DHCP4__HEADER__SNAME__MAX_LEN + 1
        )

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'sname' field length must less or equal to "
            f"{DHCP4__HEADER__SNAME__MAX_LEN!r}. Got: {len(value)!r}",
        )

    def test__dhcp4__header__file__not_string(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'file' argument is not a string.
        """

        self._kwargs["file"] = value = b"not a string"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'file' field must be a string. Got: {type(value)!r}",
        )

    def test__dhcp4__header__file__over_max_len(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        length of provided 'file' argument is over maximum allowable
        value.
        """

        self._kwargs["file"] = value = "X" * (DHCP4__HEADER__FILE__MAX_LEN + 1)

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'file' field length must less or equal to "
            f"{DHCP4__HEADER__FILE__MAX_LEN!r}. Got: {len(value)!r}",
        )
