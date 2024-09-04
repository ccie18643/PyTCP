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
This module contains tests for the NetAddr package IPv4 network support class.

tests/unit/lib/net_addr/test__ip4_network.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.net_addr import (
    Ip4Address,
    Ip4Mask,
    Ip4Network,
    Ip4NetworkFormatError,
)


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 network: 0.0.0.0/0 (str)",
            "_args": ["0.0.0.0/0"],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0/0",
                "__repr__": "Ip4Network('0.0.0.0/0')",
                "__hash__": hash("Ip4Network('0.0.0.0/0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address(),
                "mask": Ip4Mask(),
                "last": Ip4Address("255.255.255.255"),
                "broadcast": Ip4Address("255.255.255.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.100/24 (str)",
            "_args": ["192.168.1.100/24"],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "__hash__": hash("Ip4Network('192.168.1.0/24')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.100/24 (str str)",
            "_args": ["192.168.1.100 255.255.255.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "__hash__": hash("Ip4Network('192.168.1.0/24')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.100/24 (Ip4Address, Ip4Mask)",
            "_args": [(Ip4Address("192.168.1.100"), Ip4Mask("255.255.255.0"))],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "__hash__": hash("Ip4Network('192.168.1.0/24')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.100/24 (Ip4Network)",
            "_args": [Ip4Network("192.168.1.100/24")],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "__hash__": hash("Ip4Network('192.168.1.0/24')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 10.20.30.40/8 (str)",
            "_args": ["10.20.30.40/8"],
            "_kwargs": {},
            "_results": {
                "__str__": "10.0.0.0/8",
                "__repr__": "Ip4Network('10.0.0.0/8')",
                "__hash__": hash("Ip4Network('10.0.0.0/8')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("10.0.0.0"),
                "mask": Ip4Mask("255.0.0.0"),
                "last": Ip4Address("10.255.255.255"),
                "broadcast": Ip4Address("10.255.255.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 172.16.21.40/23 (str)",
            "_args": ["172.16.21.40/20"],
            "_kwargs": {},
            "_results": {
                "__str__": "172.16.16.0/20",
                "__repr__": "Ip4Network('172.16.16.0/20')",
                "__hash__": hash("Ip4Network('172.16.16.0/20')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("172.16.16.0"),
                "mask": Ip4Mask("255.255.240.0"),
                "last": Ip4Address("172.16.31.255"),
                "broadcast": Ip4Address("172.16.31.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 172.16.10.70/31 (str)",
            "_args": ["172.16.10.70/31"],
            "_kwargs": {},
            "_results": {
                "__str__": "172.16.10.70/31",
                "__repr__": "Ip4Network('172.16.10.70/31')",
                "__hash__": hash("Ip4Network('172.16.10.70/31')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("172.16.10.70"),
                "mask": Ip4Mask("255.255.255.254"),
                "last": Ip4Address("172.16.10.71"),
                "broadcast": Ip4Address("172.16.10.71"),
            },
        },
        {
            "_description": "Test the IPv4 network: 127.0.0.1/32 (str)",
            "_args": ["127.0.0.1/32"],
            "_kwargs": {},
            "_results": {
                "__str__": "127.0.0.1/32",
                "__repr__": "Ip4Network('127.0.0.1/32')",
                "__hash__": hash("Ip4Network('127.0.0.1/32')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("127.0.0.1"),
                "mask": Ip4Mask("255.255.255.255"),
                "last": Ip4Address("127.0.0.1"),
                "broadcast": Ip4Address("127.0.0.1"),
            },
        },
    ]
)
class TestNetAddrIp4Network(TestCase):
    """
    The NetAddr IPv4 Network tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 network object with testcase arguments.
        """

        self._ip4_network = Ip4Network(*self._args, **self._kwargs)

    def test__net_addr__ip4_network__str(self) -> None:
        """
        Ensure the IPv4 network '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip4_network),
            self._results["__str__"],
        )

    def test__net_addr__ip4_network__repr(self) -> None:
        """
        Ensure the IPv4 network '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip4_network),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_network__eq(self) -> None:
        """
        Ensure the IPv4 network '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip4_network == self._ip4_network,
        )

        if int(self._ip4_network.mask) != 0:
            self.assertFalse(
                self._ip4_network
                == Ip4Network(
                    (
                        Ip4Address(
                            (int(self._ip4_network.address) - 1) & 0xFF_FF_FF_FF
                        ),
                        self._ip4_network.mask,
                    ),
                ),
            )

        self.assertFalse(
            self._ip4_network
            == Ip4Network(
                (
                    self._ip4_network.address,
                    Ip4Mask(f"/{(len(self._ip4_network.mask) + 1) % 33}"),
                ),
            ),
        )

        self.assertFalse(
            self._ip4_network == "not an IPv4 network",
        )

    def test__net_addr__ip4_network__hash(self) -> None:
        """
        Ensure the IPv4 network '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._ip4_network),
            self._results["__hash__"],
        )

    def test__net_addr__ip4_network__version(self) -> None:
        """
        Ensure the IPv4 network 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_network.version,
            self._results["version"],
        )

    def test__net_addr__ip4_network__is_ip4(self) -> None:
        """
        Ensure the IPv4 network 'is_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_network.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_network__is_ip6(self) -> None:
        """
        Ensure the IPv4 network 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_network.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_network__last(self) -> None:
        """
        Ensure the IPv4 network 'last' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_network.last,
            self._results["last"],
        )

    def test__net_addr__ip4_network__broadcast(self) -> None:
        """
        Ensure the IPv4 network 'broadcast' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_network.broadcast,
            self._results["broadcast"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 network format: '192.168.1.0//24'",
            "_args": ["192.168.1.0//24"],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": (
                    "The IPv4 network format is invalid: '192.168.1.0//24'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1./24'",
            "_args": ["192.168.1./24"],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": (
                    "The IPv4 network format is invalid: '192.168.1./24'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1.0/33'",
            "_args": ["192.168.1.0/33"],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": (
                    "The IPv4 network format is invalid: '192.168.1.0/33'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1.0 128.255.255.255'",
            "_args": ["192.168.1.0 128.255.255.255"],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": (
                    "The IPv4 network format is invalid: '192.168.1.0 128.255.255.255'"
                ),
            },
        },
    ]
)
class TestNetAddrIp4NetworkErrors(TestCase):
    """
    The NetAddr IPv4 network error tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_network__errors(self) -> None:
        """
        Ensure the IPv4 network raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Network(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )
