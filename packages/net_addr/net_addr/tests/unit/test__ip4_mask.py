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

net_addr/tests/unit/test__ip4_mask.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import (
    Ip4Address,
    Ip4Mask,
    Ip4MaskFormatError,
    Ip6Address,
    Ip6Mask,
    IpVersion,
)
from net_addr.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 mask: 0.0.0.0 (str)",
            "_args": [
                "0.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 0,
                "__str__": "/0",
                "__repr__": "Ip4Mask('/0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 0.0.0.0 (None)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 0,
                "__str__": "/0",
                "__repr__": "Ip4Mask('/0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: /0 (slash notation)",
            "_args": [
                "/0",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 0,
                "__str__": "/0",
                "__repr__": "Ip4Mask('/0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.0.0.0 (str)",
            "_args": [
                "255.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 8,
                "__str__": "/8",
                "__repr__": "Ip4Mask('/8')",
                "__bytes__": b"\xff\x00\x00\x00",
                "__int__": 4278190080,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (str)",
            "_args": [
                "255.128.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('/9')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (Ip4Mask)",
            "_args": [
                Ip4Mask("255.128.0.0"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('/9')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (bytes)",
            "_args": [
                b"\xff\x80\x00\x00",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('/9')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (bytearray)",
            "_args": [
                bytearray(b"\xff\x80\x00\x00"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('/9')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (memoryview)",
            "_args": [
                memoryview(b"\xff\x80\x00\x00"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('/9')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.128.0.0 (int)",
            "_args": [
                4286578688,
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "/9",
                "__repr__": "Ip4Mask('/9')",
                "__bytes__": b"\xff\x80\x00\x00",
                "__int__": 4286578688,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.0.0 (str)",
            "_args": [
                "255.255.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip4Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00",
                "__int__": 4294901760,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.224.0 (str)",
            "_args": [
                "255.255.224.0",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 19,
                "__str__": "/19",
                "__repr__": "Ip4Mask('/19')",
                "__bytes__": b"\xff\xff\xe0\x00",
                "__int__": 4294959104,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.255.0 (str)",
            "_args": [
                "255.255.255.0",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 24,
                "__str__": "/24",
                "__repr__": "Ip4Mask('/24')",
                "__bytes__": b"\xff\xff\xff\x00",
                "__int__": 4294967040,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: /24 (slash notation)",
            "_args": [
                "/24",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 24,
                "__str__": "/24",
                "__repr__": "Ip4Mask('/24')",
                "__bytes__": b"\xff\xff\xff\x00",
                "__int__": 4294967040,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.255.252 (str)",
            "_args": [
                "255.255.255.252",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 30,
                "__str__": "/30",
                "__repr__": "Ip4Mask('/30')",
                "__bytes__": b"\xff\xff\xff\xfc",
                "__int__": 4294967292,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: 255.255.255.255 (str)",
            "_args": [
                "255.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 32,
                "__str__": "/32",
                "__repr__": "Ip4Mask('/32')",
                "__bytes__": b"\xff\xff\xff\xff",
                "__int__": 4294967295,
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
            },
        },
        {
            "_description": "Test the IPv4 mask: /32 (slash notation)",
            "_args": [
                "/32",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 32,
                "__str__": "/32",
                "__repr__": "Ip4Mask('/32')",
                "__bytes__": b"\xff\xff\xff\xff",
                "__int__": 4294967295,
                "version": IpVersion.IP4,
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
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the IPv4 mask object with testcase arguments.
        """

        self._ip4_mask = Ip4Mask(*self._args, **self._kwargs)

    def test__net_addr__ip4_mask__len(self) -> None:
        """
        Ensure the IPv4 mask '__len__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._ip4_mask),
            self._results["__len__"],
        )

    def test__net_addr__ip4_mask__str(self) -> None:
        """
        Ensure the IPv4 mask '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip4_mask),
            self._results["__str__"],
        )

    def test__net_addr__ip4_mask__repr(self) -> None:
        """
        Ensure the IPv4 mask '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip4_mask),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_mask__bytes(self) -> None:
        """
        Ensure the IPv4 mask '__bytes__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._ip4_mask),
            self._results["__bytes__"],
        )

    def test__net_addr__ip4_mask__buffer(self) -> None:
        """
        Ensure the IPv4 mask '__buffer__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(memoryview(self._ip4_mask)),
            self._results["__bytes__"],
        )

    def test__net_addr__ip4_mask__int(self) -> None:
        """
        Ensure the IPv4 mask '__int__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(self._ip4_mask),
            self._results["__int__"],
        )

    def test__net_addr__ip4_mask__eq(self) -> None:
        """
        Ensure the IPv4 mask '__eq__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._ip4_mask == self._ip4_mask,
            msg="An Ip4Mask instance must compare equal to itself.",
        )

        self.assertTrue(
            self._ip4_mask == Ip4Mask(int(self._ip4_mask)),
            msg="Ip4Mask must compare equal to one reconstructed from its integer form.",
        )

        self.assertFalse(
            self._ip4_mask == Ip4Mask(f"/{(len(self._ip4_mask) + 1) % 33}"),
            msg="Ip4Mask instances with different bit lengths must not compare equal.",
        )

        self.assertFalse(
            self._ip4_mask == "not an IPv4 mask",
            msg="Ip4Mask must not compare equal to a foreign string value.",
        )

    def test__net_addr__ip4_mask__version(self) -> None:
        """
        Ensure the IPv4 mask 'version' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_mask.version,
            self._results["version"],
        )

    def test__net_addr__ip4_mask__is_ip4(self) -> None:
        """
        Ensure the IPv4 mask 'is_ip4' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_mask.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_mask__is_ip6(self) -> None:
        """
        Ensure the IPv4 mask 'is_ip6' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_mask.is_ip6,
            self._results["is_ip6"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 mask format: '255.255.255.256'",
            "_args": [
                "255.255.255.256",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: '255.255.255.256'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: '/08' (leading-zero prefix length)",
            "_args": [
                "/08",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: '/08'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: '/00' (leading-zero prefix length)",
            "_args": [
                "/00",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: '/00'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: '255.255.255,255'",
            "_args": [
                "255.255.255,255",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: '255.255.255,255'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: '255.254.255.255' (non-contiguous)",
            "_args": [
                "255.254.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: '255.254.255.255'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: '' (empty string)",
            "_args": [
                "",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: ''",
            },
        },
        {
            "_description": "Test the IPv4 mask format: '/33' (out-of-range slash notation)",
            "_args": [
                "/33",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: '/33'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: '/-1' (negative slash notation)",
            "_args": [
                "/-1",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: '/-1'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: '/abc' (non-numeric slash notation)",
            "_args": [
                "/abc",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: '/abc'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: b'\\xff\\x7f\\xff\\xff' (non-contiguous 4 bytes)",
            "_args": [
                b"\xff\x7f\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": r"The IPv4 mask format is invalid: b'\xff\x7f\xff\xff'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: b'\\xff\\xff\\xff' (3 bytes)",
            "_args": [
                b"\xff\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": r"The IPv4 mask format is invalid: b'\xff\xff\xff'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: b'\\xff\\xff\\xff\\xff\\xff' (5 bytes)",
            "_args": [
                b"\xff\xff\xff\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": r"The IPv4 mask format is invalid: b'\xff\xff\xff\xff\xff'",
            },
        },
        {
            "_description": "Test the IPv4 mask format: bytearray(b'\\xff\\xff\\xff') (3 bytes)",
            "_args": [
                bytearray(b"\xff\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: bytearray(b'\\xff\\xff\\xff')",
            },
        },
        {
            "_description": "Test the IPv4 mask format: bytearray(b'\\xff\\xff\\xff\\xff\\xff') (5 bytes)",
            "_args": [
                bytearray(b"\xff\xff\xff\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: bytearray(b'\\xff\\xff\\xff\\xff\\xff')",
            },
        },
        {
            "_description": "Test the IPv4 mask format: memoryview (3 bytes)",
            "_args": [
                memoryview(b"\xff\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: <memory at 0x",
            },
        },
        {
            "_description": "Test the IPv4 mask format: -1",
            "_args": [
                -1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: -1",
            },
        },
        {
            "_description": "Test the IPv4 mask format: 4294967296",
            "_args": [
                4294967296,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: 4294967296",
            },
        },
        {
            "_description": "Test the IPv4 mask format: 0xFF00FF00 (non-contiguous int)",
            "_args": [
                0xFF00FF00,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: 4278255360",
            },
        },
        {
            "_description": "Test the IPv4 mask format: Ip6Mask()",
            "_args": [
                Ip6Mask(),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: Ip6Mask('/0')",
            },
        },
        {
            "_description": "Test the IPv4 mask format: {}",
            "_args": [
                {},
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: {}",
            },
        },
        {
            "_description": "Test the IPv4 mask format: 1.1 (float)",
            "_args": [
                1.1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: 1.1",
            },
        },
        {
            "_description": "Test the IPv4 mask format: '0255.0.0.0' (leading-zero octet)",
            "_args": [
                "0255.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4MaskFormatError,
                "error_message": "The IPv4 mask format is invalid: '0255.0.0.0'",
            },
        },
    ]
)
class TestNetAddrIp4MaskErrors(TestCase):
    """
    The NetAddr IPv4 mask error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_mask__errors(self) -> None:
        """
        Ensure the IPv4 mask raises an error on invalid input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Mask(*self._args, **self._kwargs)

        self.assertTrue(
            str(error.exception).startswith(self._results["error_message"]),
            msg=(
                f"Expected exception message to start with "
                f"{self._results['error_message']!r}, got {str(error.exception)!r}."
            ),
        )


class TestNetAddrIp4MaskEquality(TestCase):
    """
    The NetAddr IPv4 mask equality tests across value and type boundaries.
    """

    def test__net_addr__ip4_mask__eq__identity(self) -> None:
        """
        Ensure the IPv4 mask equals itself.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mask = Ip4Mask("/24")
        self.assertTrue(
            mask == mask,
            msg="An Ip4Mask instance must compare equal to itself.",
        )

    def test__net_addr__ip4_mask__eq__same_value(self) -> None:
        """
        Ensure two IPv4 masks with the same underlying value are equal
        regardless of which constructor form was used.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            Ip4Mask("/24"),
            Ip4Mask("255.255.255.0"),
            msg="Ip4Mask built from slash and dotted-decimal must compare equal.",
        )
        self.assertEqual(
            Ip4Mask("/24"),
            Ip4Mask(b"\xff\xff\xff\x00"),
            msg="Ip4Mask built from slash and bytes must compare equal.",
        )
        self.assertEqual(
            Ip4Mask("/24"),
            Ip4Mask(0xFFFFFF00),
            msg="Ip4Mask built from slash and int must compare equal.",
        )

    def test__net_addr__ip4_mask__eq__different_value(self) -> None:
        """
        Ensure two IPv4 masks with different values are not equal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            Ip4Mask("/24"),
            Ip4Mask("/25"),
            msg="Ip4Mask instances with different bit lengths must not compare equal.",
        )

    def test__net_addr__ip4_mask__eq__foreign_types(self) -> None:
        """
        Ensure the IPv4 mask is never equal to a value of a foreign type,
        even when the underlying integer/bytes would match.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mask = Ip4Mask("/24")

        self.assertFalse(
            mask == "/24",
            msg="Ip4Mask must not compare equal to its string representation.",
        )
        self.assertFalse(
            mask == int(mask),
            msg="Ip4Mask must not compare equal to its integer representation.",
        )
        self.assertFalse(
            mask == bytes(mask),
            msg="Ip4Mask must not compare equal to its bytes representation.",
        )
        self.assertFalse(
            mask == None,  # noqa: E711
            msg="Ip4Mask must not compare equal to None.",
        )
        self.assertFalse(
            mask == Ip6Mask("/24"),
            msg="Ip4Mask must not compare equal to an Ip6Mask of the same bit length.",
        )

    def test__net_addr__ip4_mask__ne(self) -> None:
        """
        Ensure the IPv4 mask '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mask = Ip4Mask("/24")
        self.assertTrue(
            mask != Ip4Mask("/25"),
            msg="Ip4Mask instances with different bit lengths must be unequal.",
        )
        self.assertFalse(
            mask != Ip4Mask("/24"),
            msg="Ip4Mask instances with the same bit length must not be unequal.",
        )
        self.assertTrue(
            mask != "/24",
            msg="Ip4Mask must be unequal to its string representation.",
        )


class TestNetAddrIp4MaskHashConsistency(TestCase):
    """
    The NetAddr IPv4 mask hash and container usability tests.
    """

    def test__net_addr__ip4_mask__hash__equal_masks_hash_equal(self) -> None:
        """
        Ensure equal IPv4 masks built from different input forms produce
        identical hash values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from_slash = Ip4Mask("/24")
        from_dotted = Ip4Mask("255.255.255.0")
        from_bytes = Ip4Mask(b"\xff\xff\xff\x00")
        from_int = Ip4Mask(0xFFFFFF00)
        from_bytearray = Ip4Mask(bytearray(b"\xff\xff\xff\x00"))
        from_memoryview = Ip4Mask(memoryview(b"\xff\xff\xff\x00"))
        from_copy = Ip4Mask(from_slash)

        self.assertEqual(
            hash(from_slash),
            hash(from_dotted),
            msg="Equal Ip4Mask values (slash, dotted) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_slash),
            hash(from_bytes),
            msg="Equal Ip4Mask values (slash, bytes) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_slash),
            hash(from_int),
            msg="Equal Ip4Mask values (slash, int) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_slash),
            hash(from_bytearray),
            msg="Equal Ip4Mask values (slash, bytearray) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_slash),
            hash(from_memoryview),
            msg="Equal Ip4Mask values (slash, memoryview) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_slash),
            hash(from_copy),
            msg="Ip4Mask copied from another Ip4Mask must preserve its hash.",
        )

    def test__net_addr__ip4_mask__usable_in_set(self) -> None:
        """
        Ensure equal IPv4 masks collapse into a single element when used
        in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Mask("/24")
        b = Ip4Mask("255.255.255.0")
        c = Ip4Mask("/25")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip4Mask values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip4Mask values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip4Mask values as the same key.",
        )

    def test__net_addr__ip4_mask__usable_in_dict(self) -> None:
        """
        Ensure equal IPv4 masks refer to the same dict entry regardless
        of which constructor form was used to build the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Mask("/24")
        b = Ip4Mask("255.255.255.0")

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip4Mask must behave consistently as a dict key across input forms.",
        )


class TestNetAddrIp4MaskRoundtrip(TestCase):
    """
    The NetAddr IPv4 mask serialization roundtrip tests.
    """

    def test__net_addr__ip4_mask__roundtrip__str(self) -> None:
        """
        Ensure 'Ip4Mask(str(x))' yields a mask equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("/0", "/1", "/15", "/24", "/31", "/32"):
            with self.subTest(value=value):
                mask = Ip4Mask(value)
                self.assertEqual(
                    Ip4Mask(str(mask)),
                    mask,
                    msg=f"Roundtrip through str() must preserve mask {value!r}.",
                )

    def test__net_addr__ip4_mask__roundtrip__int(self) -> None:
        """
        Ensure 'Ip4Mask(int(x))' yields a mask equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in (0, 0xFF000000, 0xFFFF0000, 0xFFFFFF00, 0xFFFFFFFF):
            with self.subTest(value=value):
                mask = Ip4Mask(value)
                self.assertEqual(
                    Ip4Mask(int(mask)),
                    mask,
                    msg=f"Roundtrip through int() must preserve mask {value:#x}.",
                )

    def test__net_addr__ip4_mask__roundtrip__bytes(self) -> None:
        """
        Ensure 'Ip4Mask(bytes(x))' yields a mask equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in (
            b"\x00\x00\x00\x00",
            b"\xff\x00\x00\x00",
            b"\xff\xff\xff\x00",
            b"\xff\xff\xff\xff",
        ):
            with self.subTest(value=value):
                mask = Ip4Mask(value)
                self.assertEqual(
                    Ip4Mask(bytes(mask)),
                    mask,
                    msg=f"Roundtrip through bytes() must preserve mask {value!r}.",
                )

    def test__net_addr__ip4_mask__roundtrip__copy(self) -> None:
        """
        Ensure 'Ip4Mask(x)' where 'x' is an Ip4Mask yields a mask equal
        to the source.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = Ip4Mask("/24")
        clone = Ip4Mask(source)

        self.assertEqual(
            clone,
            source,
            msg="Ip4Mask copied from another Ip4Mask must compare equal to the source.",
        )
        self.assertEqual(
            int(clone),
            int(source),
            msg="Ip4Mask copied from another Ip4Mask must preserve the integer value.",
        )
        self.assertEqual(
            len(clone),
            len(source),
            msg="Ip4Mask copied from another Ip4Mask must preserve the bit length.",
        )


class TestNetAddrIp4MaskAndAddress(TestCase):
    """
    The NetAddr IPv4 mask & address (network address)
    operator tests.
    """

    def test__net_addr__ip4_mask__and_address(self) -> None:
        """
        Ensure 'address & mask' (and the reflected form) yields
        the network address — every host bit (mask=0) cleared,
        every network bit unchanged.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        for addr, mask, expected in [
            ("10.1.1.42", "/24", "10.1.1.0"),
            ("192.168.5.130", "/26", "192.168.5.128"),
            ("172.16.200.7", "/12", "172.16.0.0"),
            ("10.1.1.42", "/32", "10.1.1.42"),
            ("10.1.1.42", "/0", "0.0.0.0"),
        ]:
            with self.subTest(addr=addr, mask=mask):
                a = Ip4Address(addr)
                m = Ip4Mask(mask)
                self.assertEqual(
                    a & m,
                    Ip4Address(expected),
                    msg=f"{addr} & {mask} must be {expected}.",
                )
                self.assertEqual(
                    m & a,
                    Ip4Address(expected),
                    msg=f"{mask} & {addr} (reflected) must be {expected}.",
                )
                self.assertIsInstance(
                    a & m,
                    Ip4Address,
                    msg="address & mask must return an Ip4Address.",
                )

    def test__net_addr__ip4_mask__and_address_same_subnet_idiom(self) -> None:
        """
        Ensure the same-subnet idiom '(a & m) == (b & m)' admits
        hosts in the same prefix and rejects hosts outside it.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        m = Ip4Mask("/24")
        self.assertEqual(
            Ip4Address("10.1.1.5") & m,
            Ip4Address("10.1.1.200") & m,
            msg="10.1.1.5 and 10.1.1.200 must share a /24.",
        )
        self.assertNotEqual(
            Ip4Address("10.1.1.5") & m,
            Ip4Address("10.1.2.5") & m,
            msg="10.1.1.5 and 10.1.2.5 must not share a /24.",
        )

    def test__net_addr__ip4_mask__and_rejects_foreign_operand(self) -> None:
        """
        Ensure a non-address or cross-version operand yields
        'TypeError' rather than a silent wrong result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        m = Ip4Mask("/24")
        with self.assertRaises(TypeError):
            _ = m & 5
        with self.assertRaises(TypeError):
            _ = Ip6Address("::1") & m


class TestNetAddrIp4MaskWhitespace(TestCase):
    """
    The NetAddr Ip4Mask surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip4_mask__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("/24", "255.255.255.0"):
            expected = Ip4Mask(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip4Mask(wrapped),
                        expected,
                        msg=f"Ip4Mask({wrapped!r}) must equal Ip4Mask({value!r}).",
                    )
