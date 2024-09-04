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
This module contains tests for the NetAddr package IPv4 mask support class.

tests/unit/lib/net_addr/test__ip4_mask.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.net_addr import Ip4Mask, Ip4MaskFormatError, Ip6Mask


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 mask: 0.0.0.0 (str)",
            "_args": ["0.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__len__": 0,
                "__str__": "/0",
                "__repr__": "Ip4Mask('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash("Ip4Mask('0.0.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 0.0.0.0 (None)",
            "_args": [None],
            "_kwargs": {},
            "_results": {
                "__len__": 0,
                "__str__": "/0",
                "__repr__": "Ip4Mask('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash("Ip4Mask('0.0.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.0.0.0 (str)",
            "_args": ["255.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__len__": 8,
                "__str__": "/8",
                "__repr__": "Ip4Mask('255.0.0.0')",
                "__bytes__": b"\xff\x00\x00\x00",
                "__int__": 4278190080,
                "__hash__": hash("Ip4Mask('255.0.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (str)",
            "_args": ["255.128.0.0"],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('255.128.0.0')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "__hash__": hash("Ip4Mask('255.128.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (Ip4Mask)",
            "_args": [Ip4Mask("255.128.0.0")],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('255.128.0.0')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "__hash__": hash("Ip4Mask('255.128.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (bytes)",
            "_args": [b"\xff\x80\x00\x00"],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('255.128.0.0')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "__hash__": hash("Ip4Mask('255.128.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (bytearray)",
            "_args": [bytearray(b"\xff\x80\x00\x00")],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('255.128.0.0')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "__hash__": hash("Ip4Mask('255.128.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (memoryview)",
            "_args": [memoryview(b"\xff\x80\x00\x00")],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('255.128.0.0')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "__hash__": hash("Ip4Mask('255.128.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (int)",
            "_args": [4286578688],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('255.128.0.0')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "__hash__": hash("Ip4Mask('255.128.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.0.0 (str)",
            "_args": ["255.255.0.0"],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip4Mask('255.255.0.0')",
                "__bytes__": b"\xff\xff\x00\x00",
                "__int__": 4294901760,
                "__hash__": hash("Ip4Mask('255.255.0.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.224.0 (str)",
            "_args": ["255.255.224.0"],
            "_kwargs": {},
            "_results": {
                "__len__": 19,
                "__str__": "/19",
                "__repr__": "Ip4Mask('255.255.224.0')",
                "__bytes__": b"\xff\xff\xe0\x00",
                "__int__": 4294959104,
                "__hash__": hash("Ip4Mask('255.255.224.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.255.0 (str)",
            "_args": ["255.255.255.0"],
            "_kwargs": {},
            "_results": {
                "__len__": 24,
                "__str__": "/24",
                "__repr__": "Ip4Mask('255.255.255.0')",
                "__bytes__": b"\xff\xff\xff\x00",
                "__int__": 4294967040,
                "__hash__": hash("Ip4Mask('255.255.255.0')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.255.252 (str)",
            "_args": ["255.255.255.252"],
            "_kwargs": {},
            "_results": {
                "__len__": 30,
                "__str__": "/30",
                "__repr__": "Ip4Mask('255.255.255.252')",
                "__bytes__": b"\xff\xff\xff\xfc",
                "__int__": 4294967292,
                "__hash__": hash("Ip4Mask('255.255.255.252')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.255.255 (str)",
            "_args": ["255.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__len__": 32,
                "__str__": "/32",
                "__repr__": "Ip4Mask('255.255.255.255')",
                "__bytes__": b"\xff\xff\xff\xff",
                "__int__": 4294967295,
                "__hash__": hash("Ip4Mask('255.255.255.255')"),
                "version": 4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
    ]
)
class TestNetAddrIp4Mask(TestCase):
    """
    The NetAddr IPv4 mask tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 mask object with testcase arguments.
        """

        self._ip4_mask = Ip4Mask(*self._args, **self._kwargs)

    def test__net_addr__ip4_mask__len(self) -> None:
        """
        Ensure the IPv4 mask '__len__()' method returns a correct value.
        """

        self.assertEqual(
            len(self._ip4_mask),
            self._results["__len__"],
        )

    def test__net_addr__ip4_mask__str(self) -> None:
        """
        Ensure the IPv4 mask '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip4_mask),
            self._results["__str__"],
        )

    def test__net_addr__ip4_mask__repr(self) -> None:
        """
        Ensure the IPv4 mask '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip4_mask),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_mask__bytes(self) -> None:
        """
        Ensure the IPv4 mask '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._ip4_mask),
            self._results["__bytes__"],
        )

    def test__net_addr__ip4_mask__int(self) -> None:
        """
        Ensure the IPv4 mask '__int__()' method returns a correct value.
        """

        self.assertEqual(
            int(self._ip4_mask),
            self._results["__int__"],
        )

    def test__net_addr__ip4_mask__eq(self) -> None:
        """
        Ensure the IPv4 mask '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip4_mask == self._ip4_mask,
        )

        self.assertFalse(
            self._ip4_mask == Ip4Mask(f"/{(len(self._ip4_mask) + 1) % 33}"),
        )

        self.assertFalse(
            self._ip4_mask == "not an IPv4 mask",
        )

    def test__net_addr__ip4_mask__hash(self) -> None:
        """
        Ensure the IPv4 mask '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._ip4_mask),
            self._results["__hash__"],
        )

    def test__net_addr__ip4_mask__version(self) -> None:
        """
        Ensure the IPv4 mask 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_mask.version,
            self._results["version"],
        )

    def test__net_addr__ip4_mask__is_ip4(self) -> None:
        """
        Ensure the IPv4 mask 'is_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_mask.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_mask__is_ip6(self) -> None:
        """
        Ensure the IPv4 mask 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_mask.is_ip6,
            self._results["is_ip6"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 mask format: '255.255.255.256'",
            "_args": ["255.255.255.256"],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": (
                    "The IPv4 mask format is invalid: '255.255.255.256'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 mask format: '255.255.255,255'",
            "_args": ["255.255.255,255"],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": (
                    "The IPv4 mask format is invalid: '255.255.255,255'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 mask format: '255.254.255.255'",
            "_args": ["255.254.255.255"],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": (
                    "The IPv4 mask format is invalid: '255.254.255.255'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 mask format: b'\xff\xff\xff'",
            "_args": [b"\xff\xff\xff"],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": (
                    r"The IPv4 mask format is invalid: b'\xff\xff\xff'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 mask format: b'\xff\xff\xff\xff\xff'",
            "_args": [b"\xff\xff\xff\xff\xff"],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": (
                    r"The IPv4 mask format is invalid: b'\xff\xff\xff\xff\xff'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 mask format: -1",
            "_args": [-1],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": ("The IPv4 mask format is invalid: -1"),
            },
        },
        {
            "_description": "Test the IPv4 mask format: 4294967296",
            "_args": [4294967296],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": (
                    "The IPv4 mask format is invalid: 4294967296"
                ),
            },
        },
        {
            "_description": "Test the IPv4 mask format: Ip6Mask()",
            "_args": [Ip6Mask()],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": (
                    "The IPv4 mask format is invalid: Ip6Mask('/0')"
                ),
            },
        },
        {
            "_description": "Test the IPv4 mask format: {}",
            "_args": [{}],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: {}",
            },
        },
        {
            "_description": "Test the IPv4 address format: 1.1",
            "_args": [1.1],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: 1.1",
            },
        },
    ]
)
class TestNetAddrIp4MaskErrors(TestCase):
    """
    The NetAddr IPv4 mask error tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_mask__errors(self) -> None:
        """
        Ensure the IPv4 mask raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Mask(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )
