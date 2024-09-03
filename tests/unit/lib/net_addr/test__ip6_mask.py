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
This module contains tests for the NetAddr package IPv6 mask support class.

tests/unit/lib/net_addr/test__ip6_mask.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.net_addr import Ip4Mask, Ip6Mask, Ip6MaskFormatError


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 mask: '/0' (str)",
            "_args": ["/0"],
            "_results": {
                "__len__": 0,
                "__str__": "/0",
                "__repr__": "Ip6Mask('/0')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash("Ip6Mask('/0')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: None (str)",
            "_args": [None],
            "_results": {
                "__len__": 0,
                "__str__": "/0",
                "__repr__": "Ip6Mask('/0')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash("Ip6Mask('/0')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/8' (str)",
            "_args": ["/8"],
            "_results": {
                "__len__": 8,
                "__str__": "/8",
                "__repr__": "Ip6Mask('/8')",
                "__bytes__": b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 338953138925153547590470800371487866880,
                "__hash__": hash("Ip6Mask('/8')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (str)",
            "_args": ["/16"],
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "__hash__": hash("Ip6Mask('/16')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (Ip6Mask)",
            "_args": [Ip6Mask("/16")],
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "__hash__": hash("Ip6Mask('/16')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (Ip6Mask)",
            "_args": [Ip6Mask("/16")],
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "__hash__": hash("Ip6Mask('/16')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (bytes)",
            "_args": [
                b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ],
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "__hash__": hash("Ip6Mask('/16')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (bytearray)",
            "_args": [
                bytearray(
                    b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                )
            ],
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "__hash__": hash("Ip6Mask('/16')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (memoryview)",
            "_args": [
                memoryview(
                    b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                )
            ],
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "__hash__": hash("Ip6Mask('/16')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (int)",
            "_args": [340277174624079928635746076935438991360],
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "__hash__": hash("Ip6Mask('/16')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/24' (str)",
            "_args": ["/24"],
            "_results": {
                "__len__": 24,
                "__str__": "/24",
                "__repr__": "Ip6Mask('/24')",
                "__bytes__": b"\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282346638528859811704183484516925440,
                "__hash__": hash("Ip6Mask('/24')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/32' (str)",
            "_args": ["/32"],
            "_results": {
                "__len__": 32,
                "__str__": "/32",
                "__repr__": "Ip6Mask('/32')",
                "__bytes__": b"\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366841710300949110269838224261120,
                "__hash__": hash("Ip6Mask('/32')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/40' (str)",
            "_args": ["/40"],
            "_results": {
                "__len__": 40,
                "__str__": "/40",
                "__repr__": "Ip6Mask('/40')",
                "__bytes__": b"\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920628978453553262363043430400,
                "__hash__": hash("Ip6Mask('/40')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/48' (str)",
            "_args": ["/48"],
            "_results": {
                "__len__": 48,
                "__str__": "/48",
                "__repr__": "Ip6Mask('/48')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920937254537554992802593505280,
                "__hash__": hash("Ip6Mask('/48')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/56' (str)",
            "_args": ["/56"],
            "_results": {
                "__len__": 56,
                "__str__": "/56",
                "__repr__": "Ip6Mask('/56')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920938458741008124562122997760,
                "__hash__": hash("Ip6Mask('/56')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/64' (str)",
            "_args": ["/64"],
            "_results": {
                "__len__": 64,
                "__str__": "/64",
                "__repr__": "Ip6Mask('/64')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920938463444927863358058659840,
                "__hash__": hash("Ip6Mask('/64')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/72' (str)",
            "_args": ["/72"],
            "_results": {
                "__len__": 72,
                "__str__": "/72",
                "__repr__": "Ip6Mask('/72')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920938463463302549837730283520,
                "__hash__": hash("Ip6Mask('/72')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/80' (str)",
            "_args": ["/80"],
            "_results": {
                "__len__": 80,
                "__str__": "/80",
                "__repr__": "Ip6Mask('/80')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920938463463374325956791500800,
                "__hash__": hash("Ip6Mask('/80')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/88' (str)",
            "_args": ["/88"],
            "_results": {
                "__len__": 88,
                "__str__": "/88",
                "__repr__": "Ip6Mask('/88')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00",
                "__int__": 340282366920938463463374606332256583680,
                "__hash__": hash("Ip6Mask('/88')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/96' (str)",
            "_args": ["/96"],
            "_results": {
                "__len__": 96,
                "__str__": "/96",
                "__repr__": "Ip6Mask('/96')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00",
                "__int__": 340282366920938463463374607427473244160,
                "__hash__": hash("Ip6Mask('/96')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/104' (str)",
            "_args": ["/104"],
            "_results": {
                "__len__": 104,
                "__str__": "/104",
                "__repr__": "Ip6Mask('/104')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00",
                "__int__": 340282366920938463463374607431751434240,
                "__hash__": hash("Ip6Mask('/104')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/112' (str)",
            "_args": ["/112"],
            "_results": {
                "__len__": 112,
                "__str__": "/112",
                "__repr__": "Ip6Mask('/112')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00",
                "__int__": 340282366920938463463374607431768145920,
                "__hash__": hash("Ip6Mask('/112')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/120' (str)",
            "_args": ["/120"],
            "_results": {
                "__len__": 120,
                "__str__": "/120",
                "__repr__": "Ip6Mask('/120')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00",
                "__int__": 340282366920938463463374607431768211200,
                "__hash__": hash("Ip6Mask('/120')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/128' (str)",
            "_args": ["/128"],
            "_results": {
                "__len__": 128,
                "__str__": "/128",
                "__repr__": "Ip6Mask('/128')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 340282366920938463463374607431768211455,
                "__hash__": hash("Ip6Mask('/128')"),
                "version": 6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
    ]
)
class TestNetAddrIp6Mask(TestCase):
    """
    The NetAddr IPv6 mask tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv6 mask object with testcase arguments.
        """

        self._ip6_mask = Ip6Mask(*self._args)

    def test__net_addr__ip6_mask__len(self) -> None:
        """
        Ensure the IPv6 mask '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._ip6_mask),
            self._results["__len__"],
        )

    def test__net_addr__ip6_mask__str(self) -> None:
        """
        Ensure the IPv6 mask '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip6_mask),
            self._results["__str__"],
        )

    def test__net_addr__ip6_mask__repr(self) -> None:
        """
        Ensure the IPv6 mask '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip6_mask),
            self._results["__repr__"],
        )

    def test__net_addr__ip6_mask__bytes(self) -> None:
        """
        Ensure the IPv6 mask '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._ip6_mask),
            self._results["__bytes__"],
        )

    def test__net_addr__ip6_mask__int(self) -> None:
        """
        Ensure the IPv6 mask '__int__()' method returns a correct value.
        """

        self.assertEqual(
            int(self._ip6_mask),
            self._results["__int__"],
        )

    def test__net_addr__ip6_mask__eq(self) -> None:
        """
        Ensure the IPv6 mask '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip6_mask == self._ip6_mask,
        )

        self.assertFalse(
            self._ip6_mask == Ip6Mask(f"/{(len(self._ip6_mask) + 1) % 129}"),
        )

        self.assertFalse(
            self._ip6_mask == "not an IPv6 mask",
        )

    def test__net_addr__ip6_mask__hash(self) -> None:
        """
        Ensure the IPv6 mask '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._ip6_mask),
            self._results["__hash__"],
        )

    def test__net_addr__ip6_mask__version(self) -> None:
        """
        Ensure the IPv6 mask 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip6_mask.version,
            self._results["version"],
        )

    def test__net_addr__ip6_mask__is_ip4(self) -> None:
        """
        Ensure the IPv6 mask 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_mask.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip6_mask__is_ip6(self) -> None:
        """
        Ensure the IPv6 mask 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_mask.is_ip6,
            self._results["is_ip6"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 mask format: '64'",
            "_args": ["64"],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: '64'",
            },
        },
        {
            "_description": "Test the IPv6 mask format: '/-1'",
            "_args": ["/-1"],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: '/-1'",
            },
        },
        {
            "_description": "Test the IPv6 mask format: '/129'",
            "_args": ["/129"],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: '/129'",
            },
        },
        {
            "_description": "Test the IPv6 mask: b'ffff:ffff:ffff:ffff:ffff:ffff:ffff'",
            "_args": [b"ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": (
                    "The IPv6 mask format is invalid: b'ffff:ffff:ffff:ffff:ffff:ffff:ffff'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 mask: b'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'",
            "_args": [b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": (
                    "The IPv6 mask format is invalid: b'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 mask: -1",
            "_args": [-1],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: -1",
            },
        },
        {
            "_description": "Test the IPv6 mask: 340282366920938463463374607431768211456",
            "_args": [340282366920938463463374607431768211456],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": (
                    "The IPv6 mask format is invalid: 340282366920938463463374607431768211456"
                ),
            },
        },
        {
            "_description": "Test the IPv6 mask format: Ip4Mask()",
            "_args": [Ip4Mask()],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": (
                    "The IPv6 mask format is invalid: Ip4Mask('0.0.0.0')"
                ),
            },
        },
        {
            "_description": "Test the IPv4 mask format: {}",
            "_args": [{}],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: {}",
            },
        },
        {
            "_description": "Test the IPv4 address format: 1.1",
            "_args": [1.1],
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: 1.1",
            },
        },
    ]
)
class TestNetAddrIp4MaskErrors(TestCase):
    """
    The NetAddr IPv6 mask error tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip6_mask__errors(self) -> None:
        """
        Ensure the IPv6 mask raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip6Mask(*self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )
