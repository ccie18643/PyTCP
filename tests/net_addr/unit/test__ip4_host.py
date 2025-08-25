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
This module contains tests for the NetAddr package IPv4 host support class.

tests/net_addr/unit/test__ip4_host.py

ver 3.0.2
"""


import time
from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr import (
    Ip4Address,
    Ip4Host,
    Ip4HostOrigin,
    Ip4HostSanityError,
    Ip4Mask,
    Ip4Network,
    IpVersion,
)

IP4_ADDRESS_EXPIRATION_TIME = int(time.time() + 3600)


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (str)",
            "_args": ["192.168.1.100/24"],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.DHCP,
                "expiration_time": IP4_ADDRESS_EXPIRATION_TIME,
            },
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4Host('192.168.1.100/24')",
                "__hash__": hash("Ip4Host('192.168.1.100/24')"),
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.DHCP,
                "expiration_time": IP4_ADDRESS_EXPIRATION_TIME,
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Host)",
            "_args": [Ip4Host("192.168.1.100/24")],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4Host('192.168.1.100/24')",
                "__hash__": hash("Ip4Host('192.168.1.100/24')"),
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": None,
                "origin": Ip4HostOrigin.UNKNOWN,
                "expiration_time": 0,
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Address, Ip4Mask)",
            "_args": [(Ip4Address("192.168.1.100"), Ip4Mask("255.255.255.0"))],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.STATIC,
            },
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4Host('192.168.1.100/24')",
                "__hash__": hash("Ip4Host('192.168.1.100/24')"),
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.STATIC,
                "expiration_time": 0,
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Address, Ip4Network)",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Network("192.168.1.0/24"))
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.STATIC,
            },
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4Host('192.168.1.100/24')",
                "__hash__": hash("Ip4Host('192.168.1.100/24')"),
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.STATIC,
                "expiration_time": 0,
            },
        },
    ]
)
class TestNetAddrIp4Host(TestCase):
    """
    The NetAddr IPv4 Host tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 host object with testcase arguments.
        """

        self._ip4_host = Ip4Host(*self._args, **self._kwargs)

    def test__net_addr__ip4_host__str(self) -> None:
        """
        Ensure the IPv4 host '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip4_host),
            self._results["__str__"],
        )

    def test__net_addr__ip4_host__repr(self) -> None:
        """
        Ensure the IPv4 host '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip4_host),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_host__eq(self) -> None:
        """
        Ensure the IPv4 host '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip4_host == self._ip4_host,
        )

        self.assertFalse(
            self._ip4_host == "not an IPv4 host",
        )

    def test__net_addr__ip4_host__hash(self) -> None:
        """
        Ensure the IPv4 host '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._ip4_host),
            self._results["__hash__"],
        )

    def test__net_addr__ip4_host__version(self) -> None:
        """
        Ensure the IPv4 host 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_host.version,
            self._results["version"],
        )

    def test__net_addr__ip4_host__is_ip4(self) -> None:
        """
        Ensure the IPv4 host 'is_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_host.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_host__is_ip6(self) -> None:
        """
        Ensure the IPv4 host 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_host.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_host__gateway(self) -> None:
        """
        Ensure the IPv4 host 'gateway' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_host.gateway,
            self._results["gateway"],
        )

    def test__net_addr__ip4_host__origin(self) -> None:
        """
        Ensure the IPv4 host 'origin' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_host.origin,
            self._results["origin"],
        )

    def test__net_addr__ip4_host__expiration_time(self) -> None:
        """
        Ensure the IPv4 host 'expiration_time' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_host.expiration_time,
            self._results["expiration_time"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 host where address is not part of the network.",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Network("192.168.2.0/24"))
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4HostSanityError,
                "error_message": (
                    "The IPv4 address doesn't belong to the provided network: "
                    "(Ip4Address('192.168.1.100'), Ip4Network('192.168.2.0/24'))"
                ),
            },
        },
    ]
)
class TestNetAddrIp4NetworkErrors(TestCase):
    """
    The NetAddr IPv4 host error tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_host__errors(self) -> None:
        """
        Ensure the IPv4 host raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Host(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )
