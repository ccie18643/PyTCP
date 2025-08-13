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
This module contains tests for the NetAddr package IPv6 network support class.

tests/net_addr/unit/test__ip6_network.py

ver 3.0.2
"""


from typing import Any

from net_addr.ip_address import IpVersion
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr import Ip6Address, Ip6Mask, Ip6Network, Ip6NetworkFormatError


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 network: ::/0 (str)",
            "_args": ["::/0"],
            "_kwargs": {},
            "_results": {
                "__str__": "::/0",
                "__repr__": "Ip6Network('::/0')",
                "__hash__": hash("Ip6Network('::/0')"),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address(),
                "mask": Ip6Mask(),
                "last": Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: ::/0 (None)",
            "_args": [None],
            "_kwargs": {},
            "_results": {
                "__str__": "::/0",
                "__repr__": "Ip6Network('::/0')",
                "__hash__": hash("Ip6Network('::/0')"),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address(),
                "mask": Ip6Mask(),
                "last": Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: 2001::/96 (Ip6Address, Ip6Mask)",
            "_args": [(Ip6Address("2001::"), Ip6Mask("/96"))],
            "_kwargs": {},
            "_results": {
                "__str__": "2001::/96",
                "__repr__": "Ip6Network('2001::/96')",
                "__hash__": hash("Ip6Network('2001::/96')"),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address(),
                "mask": Ip6Mask(),
                "last": Ip6Address("2001::ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: 2001:0:aaaa:bbbb:cccc:dddd:eeee:ffff/64 (str)",
            "_args": ["2001:0:aaaa:bbbb:cccc:dddd:eeee:ffff/64"],
            "_kwargs": {},
            "_results": {
                "__str__": "2001:0:aaaa:bbbb::/64",
                "__repr__": "Ip6Network('2001:0:aaaa:bbbb::/64')",
                "__hash__": hash("Ip6Network('2001:0:aaaa:bbbb::/64')"),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address(),
                "mask": Ip6Mask(),
                "last": Ip6Address("2001:0:aaaa:bbbb:ffff:ffff:ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: 2002::dddd:cccc:dddd:eeee:ffff/32 (str)",
            "_args": ["2002::dddd:cccc:dddd:eeee:ffff/32"],
            "_kwargs": {},
            "_results": {
                "__str__": "2002::/32",
                "__repr__": "Ip6Network('2002::/32')",
                "__hash__": hash("Ip6Network('2002::/32')"),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address(),
                "mask": Ip6Mask(),
                "last": Ip6Address("2002:0:ffff:ffff:ffff:ffff:ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 (str)",
            "_args": ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"],
            "_kwargs": {},
            "_results": {
                "__str__": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
                "__repr__": "Ip6Network('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128')",
                "__hash__": hash(
                    "Ip6Network('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128')"
                ),
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address(),
                "mask": Ip6Mask(),
                "last": Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            },
        },
    ]
)
class TestNetAddrIp6Network(TestCase):
    """
    The NetAddr IPv6 Network tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv6 network object with testcase arguments.
        """

        self._ip6_network = Ip6Network(*self._args, **self._kwargs)

    def test__net_addr__ip6_network__str(self) -> None:
        """
        Ensure the IPv6 network '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip6_network),
            self._results["__str__"],
        )

    def test__net_addr__ip6_network__repr(self) -> None:
        """
        Ensure the IPv6 network '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip6_network),
            self._results["__repr__"],
        )

    def test__net_addr__ip6_network__eq(self) -> None:
        """
        Ensure the IPv6 network '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip6_network == self._ip6_network,
        )

        if int(self._ip6_network.mask) != 0:
            self.assertFalse(
                self._ip6_network
                == Ip6Network(
                    (
                        Ip6Address(
                            (int(self._ip6_network.address) - 1)
                            & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF
                        ),
                        self._ip6_network.mask,
                    ),
                ),
            )

        self.assertFalse(
            self._ip6_network
            == Ip6Network(
                (
                    self._ip6_network.address,
                    Ip6Mask(f"/{(len(self._ip6_network.mask) + 1) % 129}"),
                ),
            ),
        )

        self.assertFalse(
            self._ip6_network == "not an IPv6 network",
        )

    def test__net_addr__ip6_network__hash(self) -> None:
        """
        Ensure the IPv6 network '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._ip6_network),
            self._results["__hash__"],
        )

    def test__net_addr__ip6_network__version(self) -> None:
        """
        Ensure the IPv6 network 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip6_network.version,
            self._results["version"],
        )

    def test__net_addr__ip6_network__is_ip4(self) -> None:
        """
        Ensure the IPv6 network 'is_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_network.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip6_network__is_ip6(self) -> None:
        """
        Ensure the IPv6 network 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_network.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip6_network__last(self) -> None:
        """
        Ensure the IPv6 network 'last' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_network.last,
            self._results["last"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 network format: '2001:://64'",
            "_args": ["2001:://64"],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": (
                    "The IPv6 network format is invalid: '2001:://64'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 network format: '2001::64'",
            "_args": ["2001::64"],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": (
                    "The IPv6 network format is invalid: '2001::64'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 network format: '1:2:3:4:5:6:7:8:9/64'",
            "_args": ["1:2:3:4:5:6:7:8:9/64"],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": (
                    "The IPv6 network format is invalid: '1:2:3:4:5:6:7:8:9/64'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 network format: '1:2:3:4:5:6:7:8/129'",
            "_args": ["1:2:3:4:5:6:7:8/129"],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": (
                    "The IPv6 network format is invalid: '1:2:3:4:5:6:7:8/129'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 network format: (Ip6Address, Ip6Address)",
            "_args": [(Ip6Address(), Ip6Address())],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": (
                    "The IPv6 network format is invalid: (Ip6Address('::'), Ip6Address('::'))"
                ),
            },
        },
    ]
)
class TestNetAddrIp6NetworkErrors(TestCase):
    """
    The NetAddr IPv6 network error tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip6_network__errors(self) -> None:
        """
        Ensure the IPv6 network raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip6Network(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )
