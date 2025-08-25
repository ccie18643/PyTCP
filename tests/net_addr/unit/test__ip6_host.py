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
This module contains tests for the NetAddr package IPv6 host support class.

tests/net_addr/unit/test__ip6_host.py

ver 3.0.2
"""


import time
from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr import (
    Ip6Address,
    Ip6Host,
    Ip6HostOrigin,
    Ip6HostSanityError,
    Ip6Mask,
    Ip6Network,
    IpVersion,
)

IP6_ADDRESS_EXPIRATION_TIME = int(time.time() + 3600)


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (str)",
            "_args": ["2001:b:c:d:1:2:3:4/64"],
            "_kwargs": {
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.AUTOCONFIG,
                "expiration_time": IP6_ADDRESS_EXPIRATION_TIME,
            },
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6Host('2001:b:c:d:1:2:3:4/64')",
                "__hash__": hash("Ip6Host('2001:b:c:d:1:2:3:4/64')"),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.AUTOCONFIG,
                "expiration_time": IP6_ADDRESS_EXPIRATION_TIME,
            },
        },
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (Ip6Host)",
            "_args": [Ip6Host("2001:b:c:d:1:2:3:4/64")],
            "_kwargs": {},
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6Host('2001:b:c:d:1:2:3:4/64')",
                "__hash__": hash("Ip6Host('2001:b:c:d:1:2:3:4/64')"),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
                "gateway": None,
                "origin": Ip6HostOrigin.UNKNOWN,
                "expiration_time": 0,
            },
        },
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (Ip6Address, Ip6Mask)",
            "_args": [(Ip6Address("2001:b:c:d:1:2:3:4"), Ip6Mask("/64"))],
            "_kwargs": {
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.DHCP,
                "expiration_time": IP6_ADDRESS_EXPIRATION_TIME,
            },
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6Host('2001:b:c:d:1:2:3:4/64')",
                "__hash__": hash("Ip6Host('2001:b:c:d:1:2:3:4/64')"),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.DHCP,
                "expiration_time": IP6_ADDRESS_EXPIRATION_TIME,
            },
        },
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (Ip6Address, Ip6Network)",
            "_args": [
                (
                    Ip6Address("2001:b:c:d:1:2:3:4"),
                    Ip6Network("2001:b:c:d::/64"),
                )
            ],
            "_kwargs": {
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.STATIC,
            },
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6Host('2001:b:c:d:1:2:3:4/64')",
                "__hash__": hash("Ip6Host('2001:b:c:d:1:2:3:4/64')"),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.STATIC,
                "expiration_time": 0,
            },
        },
    ]
)
class TestNetAddrIp6Host(TestCase):
    """
    The NetAddr IPv6 Host tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv6 host object with testcase arguments.
        """

        self._ip6_host = Ip6Host(*self._args, **self._kwargs)

    def test__net_addr__ip6_host__str(self) -> None:
        """
        Ensure the IPv6 host '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip6_host),
            self._results["__str__"],
        )

    def test__net_addr__ip6_host__repr(self) -> None:
        """
        Ensure the IPv6 host '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip6_host),
            self._results["__repr__"],
        )

    def test__net_addr__ip6_host__eq(self) -> None:
        """
        Ensure the IPv6 host '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip6_host == self._ip6_host,
        )

        self.assertFalse(
            self._ip6_host == "not an IPv6 host",
        )

    def test__net_addr__ip6_host__hash(self) -> None:
        """
        Ensure the IPv6 host '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._ip6_host),
            self._results["__hash__"],
        )

    def test__net_addr__ip6_host__version(self) -> None:
        """
        Ensure the IPv6 host 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip6_host.version,
            self._results["version"],
        )

    def test__net_addr__ip6_host__is_ip4(self) -> None:
        """
        Ensure the IPv6 host 'is_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip6_host__is_ip6(self) -> None:
        """
        Ensure the IPv6 host 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip6_host__gateway(self) -> None:
        """
        Ensure the IPv6 host 'gateway' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.gateway,
            self._results["gateway"],
        )

    def test__net_addr__ip6_host__origin(self) -> None:
        """
        Ensure the IPv6 host 'origin' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.origin,
            self._results["origin"],
        )

    def test__net_addr__ip6_host__expiration_time(self) -> None:
        """
        Ensure the IPv6 host 'expiration_time' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.expiration_time,
            self._results["expiration_time"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 host where address is not part of the network.",
            "_args": [
                (Ip6Address("a::1:2:3:4"), Ip6Network("b::/64")),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6HostSanityError,
                "error_message": (
                    "The IPv6 address doesn't belong to the provided network: "
                    "(Ip6Address('a::1:2:3:4'), Ip6Network('b::/64'))"
                ),
            },
        },
    ]
)
class TestNetAddrIp6NetworkErrors(TestCase):
    """
    The NetAddr IPv6 host error tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip6_host__errors(self) -> None:
        """
        Ensure the IPv6 host raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip6Host(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )
