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

net_addr/tests/unit/test__ip6_mask.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import (
    Ip4Address,
    Ip4Mask,
    Ip6Address,
    Ip6Mask,
    Ip6MaskFormatError,
    IpVersion,
)
from net_addr.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 mask: '/0' (str)",
            "_args": [
                "/0",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 0,
                "__str__": "/0",
                "__repr__": "Ip6Mask('/0')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: None (str)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 0,
                "__str__": "/0",
                "__repr__": "Ip6Mask('/0')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/8' (str)",
            "_args": [
                "/8",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 8,
                "__str__": "/8",
                "__repr__": "Ip6Mask('/8')",
                "__bytes__": b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 338953138925153547590470800371487866880,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (str)",
            "_args": [
                "/16",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (Ip6Mask)",
            "_args": [
                Ip6Mask("/16"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (Ip6Mask)",
            "_args": [
                Ip6Mask("/16"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (bytes)",
            "_args": [
                b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (bytearray)",
            "_args": [
                bytearray(b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (memoryview)",
            "_args": [
                memoryview(b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/16' (int)",
            "_args": [
                340277174624079928635746076935438991360,
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "/16",
                "__repr__": "Ip6Mask('/16')",
                "__bytes__": b"\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340277174624079928635746076935438991360,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/24' (str)",
            "_args": [
                "/24",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 24,
                "__str__": "/24",
                "__repr__": "Ip6Mask('/24')",
                "__bytes__": b"\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282346638528859811704183484516925440,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/32' (str)",
            "_args": [
                "/32",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 32,
                "__str__": "/32",
                "__repr__": "Ip6Mask('/32')",
                "__bytes__": b"\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366841710300949110269838224261120,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/40' (str)",
            "_args": [
                "/40",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 40,
                "__str__": "/40",
                "__repr__": "Ip6Mask('/40')",
                "__bytes__": b"\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920628978453553262363043430400,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/48' (str)",
            "_args": [
                "/48",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 48,
                "__str__": "/48",
                "__repr__": "Ip6Mask('/48')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920937254537554992802593505280,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/56' (str)",
            "_args": [
                "/56",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 56,
                "__str__": "/56",
                "__repr__": "Ip6Mask('/56')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920938458741008124562122997760,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/64' (str)",
            "_args": [
                "/64",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 64,
                "__str__": "/64",
                "__repr__": "Ip6Mask('/64')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920938463444927863358058659840,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/72' (str)",
            "_args": [
                "/72",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 72,
                "__str__": "/72",
                "__repr__": "Ip6Mask('/72')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920938463463302549837730283520,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/80' (str)",
            "_args": [
                "/80",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 80,
                "__str__": "/80",
                "__repr__": "Ip6Mask('/80')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00",
                "__int__": 340282366920938463463374325956791500800,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/88' (str)",
            "_args": [
                "/88",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 88,
                "__str__": "/88",
                "__repr__": "Ip6Mask('/88')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00",
                "__int__": 340282366920938463463374606332256583680,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/96' (str)",
            "_args": [
                "/96",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 96,
                "__str__": "/96",
                "__repr__": "Ip6Mask('/96')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00",
                "__int__": 340282366920938463463374607427473244160,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/104' (str)",
            "_args": [
                "/104",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 104,
                "__str__": "/104",
                "__repr__": "Ip6Mask('/104')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00",
                "__int__": 340282366920938463463374607431751434240,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/112' (str)",
            "_args": [
                "/112",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 112,
                "__str__": "/112",
                "__repr__": "Ip6Mask('/112')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00",
                "__int__": 340282366920938463463374607431768145920,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/120' (str)",
            "_args": [
                "/120",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 120,
                "__str__": "/120",
                "__repr__": "Ip6Mask('/120')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00",
                "__int__": 340282366920938463463374607431768211200,
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
            },
        },
        {
            "_description": "Test the IPv6 mask: '/128' (str)",
            "_args": [
                "/128",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 128,
                "__str__": "/128",
                "__repr__": "Ip6Mask('/128')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 340282366920938463463374607431768211455,
                "version": IpVersion.IP6,
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
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the IPv6 mask object with testcase arguments.
        """

        self._ip6_mask = Ip6Mask(*self._args, **self._kwargs)

    def test__net_addr__ip6_mask__len(self) -> None:
        """
        Ensure the IPv6 mask '__len__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._ip6_mask),
            self._results["__len__"],
        )

    def test__net_addr__ip6_mask__str(self) -> None:
        """
        Ensure the IPv6 mask '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip6_mask),
            self._results["__str__"],
        )

    def test__net_addr__ip6_mask__repr(self) -> None:
        """
        Ensure the IPv6 mask '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip6_mask),
            self._results["__repr__"],
        )

    def test__net_addr__ip6_mask__bytes(self) -> None:
        """
        Ensure the IPv6 mask '__bytes__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._ip6_mask),
            self._results["__bytes__"],
        )

    def test__net_addr__ip6_mask__int(self) -> None:
        """
        Ensure the IPv6 mask '__int__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(self._ip6_mask),
            self._results["__int__"],
        )

    def test__net_addr__ip6_mask__eq(self) -> None:
        """
        Ensure the IPv6 mask '__eq__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._ip6_mask == self._ip6_mask,
            msg="An Ip6Mask instance must compare equal to itself.",
        )

        self.assertTrue(
            self._ip6_mask == Ip6Mask(int(self._ip6_mask)),
            msg="Ip6Mask must compare equal to one reconstructed from its integer value.",
        )

        self.assertFalse(
            self._ip6_mask == Ip6Mask(f"/{(len(self._ip6_mask) + 1) % 129}"),
            msg="Ip6Mask instances with different prefix lengths must not compare equal.",
        )

        self.assertFalse(
            self._ip6_mask == "not an IPv6 mask",
            msg="Ip6Mask must not compare equal to a foreign string value.",
        )

        self.assertFalse(
            self._ip6_mask == None,  # noqa: E711
            msg="Ip6Mask must not compare equal to None.",
        )

    def test__net_addr__ip6_mask__version(self) -> None:
        """
        Ensure the IPv6 mask 'version' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_mask.version,
            self._results["version"],
        )

    def test__net_addr__ip6_mask__is_ip4(self) -> None:
        """
        Ensure the IPv6 mask 'is_ip6' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_mask.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip6_mask__is_ip6(self) -> None:
        """
        Ensure the IPv6 mask 'is_ip6' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_mask.is_ip6,
            self._results["is_ip6"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 mask format: '64'",
            "_args": [
                "64",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: '64'",
            },
        },
        {
            "_description": "Test the IPv6 mask format: '/064' (leading-zero prefix length)",
            "_args": [
                "/064",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: '/064'",
            },
        },
        {
            "_description": "Test the IPv6 mask format: '/00' (leading-zero prefix length)",
            "_args": [
                "/00",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: '/00'",
            },
        },
        {
            "_description": "Test the IPv6 mask format: '/-1'",
            "_args": [
                "/-1",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: '/-1'",
            },
        },
        {
            "_description": "Test the IPv6 mask format: '/129'",
            "_args": [
                "/129",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: '/129'",
            },
        },
        {
            "_description": "Test the IPv6 mask: b'ffff:ffff:ffff:ffff:ffff:ffff:ffff'",
            "_args": [
                b"ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": ("The IPv6 mask format is invalid: b'ffff:ffff:ffff:ffff:ffff:ffff:ffff'"),
            },
        },
        {
            "_description": "Test the IPv6 mask: b'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'",
            "_args": [
                b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": ("The IPv6 mask format is invalid: b'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'"),
            },
        },
        {
            "_description": "Test the IPv6 mask: -1",
            "_args": [
                -1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: -1",
            },
        },
        {
            "_description": "Test the IPv6 mask: 340282366920938463463374607431768211456",
            "_args": [
                340282366920938463463374607431768211456,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": ("The IPv6 mask format is invalid: 340282366920938463463374607431768211456"),
            },
        },
        {
            "_description": "Test the IPv6 mask format: Ip4Mask()",
            "_args": [
                Ip4Mask(),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": ("The IPv6 mask format is invalid: Ip4Mask('/0')"),
            },
        },
        {
            "_description": "Test the IPv4 mask format: {}",
            "_args": [
                {},
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: {}",
            },
        },
        {
            "_description": "Test the IPv4 address format: 1.1",
            "_args": [
                1.1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: 1.1",
            },
        },
        {
            "_description": "Test the IPv6 mask format: '/abc' (non-numeric suffix).",
            "_args": ["/abc"],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": "The IPv6 mask format is invalid: '/abc'",
            },
        },
        {
            "_description": "Test the IPv6 mask: non-contiguous 16-byte bytes.",
            "_args": [b"\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00"],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": (
                    "The IPv6 mask format is invalid: "
                    r"b'\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00\xff\x00'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 mask: non-contiguous int (valid 128-bit, invalid mask).",
            "_args": [0xFF00_FF00_FF00_FF00_FF00_FF00_FF00_FF00],
            "_kwargs": {},
            "_results": {
                "error": Ip6MaskFormatError,
                "error_message": (f"The IPv6 mask format is invalid: {0xFF00_FF00_FF00_FF00_FF00_FF00_FF00_FF00}"),
            },
        },
    ]
)
class TestNetAddrIp6MaskErrors(TestCase):
    """
    The NetAddr IPv6 mask error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip6_mask__errors(self) -> None:
        """
        Ensure the IPv6 mask raises an error on invalid input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip6Mask(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


class TestNetAddrIp6MaskEquality(TestCase):
    """
    The NetAddr IPv6 mask equality and inequality tests not tied to a
    parameterized matrix.
    """

    def test__net_addr__ip6_mask__eq__cross_version(self) -> None:
        """
        Ensure an IPv6 mask never compares equal to an IPv4 mask even when
        their integer values overlap in the low bits.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            Ip6Mask("/24"),
            Ip4Mask("/24"),
            msg="Ip6Mask must not compare equal to an Ip4Mask of the same prefix length.",
        )

    def test__net_addr__ip6_mask__eq__foreign_types(self) -> None:
        """
        Ensure the IPv6 mask is never equal to a value of a foreign type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mask = Ip6Mask("/64")

        self.assertFalse(
            mask == "/64",
            msg="Ip6Mask must not compare equal to its string representation.",
        )
        self.assertFalse(
            mask == int(mask),
            msg="Ip6Mask must not compare equal to its integer value.",
        )
        self.assertFalse(
            mask == bytes(mask),
            msg="Ip6Mask must not compare equal to its bytes representation.",
        )
        self.assertFalse(
            mask == len(mask),
            msg="Ip6Mask must not compare equal to its prefix length integer.",
        )

    def test__net_addr__ip6_mask__ne(self) -> None:
        """
        Ensure the IPv6 mask '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mask = Ip6Mask("/64")
        self.assertTrue(
            mask != Ip6Mask("/65"),
            msg="Ip6Mask instances with different prefix lengths must be unequal.",
        )
        self.assertFalse(
            mask != Ip6Mask("/64"),
            msg="Equal Ip6Mask values must not be unequal.",
        )
        self.assertTrue(
            mask != "/64",
            msg="Ip6Mask must be unequal to its string representation.",
        )


class TestNetAddrIp6MaskHashConsistency(TestCase):
    """
    The NetAddr IPv6 mask hash consistency tests.
    """

    def test__net_addr__ip6_mask__hash__distinct_instances(self) -> None:
        """
        Ensure equal masks constructed from different forms hash identically.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Mask("/16")
        b = Ip6Mask(int(a))
        c = Ip6Mask(bytes(a))
        d = Ip6Mask(Ip6Mask("/16"))

        for other in (b, c, d):
            self.assertEqual(
                a,
                other,
                msg="Ip6Mask values built from different inputs but the same prefix must compare equal.",
            )
            self.assertEqual(
                hash(a),
                hash(other),
                msg="Equal Ip6Mask values must hash to the same value across constructor forms.",
            )

    def test__net_addr__ip6_mask__usable_in_set(self) -> None:
        """
        Ensure equal IPv6 masks collapse into a single element when used
        in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Mask("/64")
        b = Ip6Mask(int(a))
        c = Ip6Mask("/65")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip6Mask values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip6Mask values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip6Mask values as the same key.",
        )

    def test__net_addr__ip6_mask__usable_in_dict(self) -> None:
        """
        Ensure equal IPv6 masks refer to the same dict entry regardless
        of which constructor form was used to build the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Mask("/64")
        b = Ip6Mask(bytes(a))

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip6Mask must behave consistently as a dict key across input forms.",
        )


class TestNetAddrIp6MaskRoundtrip(TestCase):
    """
    The NetAddr IPv6 mask roundtrip tests.
    """

    def test__net_addr__ip6_mask__roundtrip__str(self) -> None:
        """
        Ensure 'Ip6Mask(str(x))' yields a mask equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for prefix in (0, 1, 8, 16, 32, 48, 64, 96, 127, 128):
            with self.subTest(prefix=prefix):
                mask = Ip6Mask(f"/{prefix}")
                self.assertEqual(
                    Ip6Mask(str(mask)),
                    mask,
                    msg=f"Roundtrip through str() must preserve mask /{prefix}.",
                )

    def test__net_addr__ip6_mask__roundtrip__int(self) -> None:
        """
        Ensure 'Ip6Mask(int(x))' yields a mask equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for prefix in (0, 1, 64, 127, 128):
            with self.subTest(prefix=prefix):
                mask = Ip6Mask(f"/{prefix}")
                self.assertEqual(
                    Ip6Mask(int(mask)),
                    mask,
                    msg=f"Roundtrip through int() must preserve mask /{prefix}.",
                )

    def test__net_addr__ip6_mask__roundtrip__bytes(self) -> None:
        """
        Ensure 'Ip6Mask(bytes(x))' yields a mask equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for prefix in (0, 1, 64, 127, 128):
            with self.subTest(prefix=prefix):
                mask = Ip6Mask(f"/{prefix}")
                self.assertEqual(
                    Ip6Mask(bytes(mask)),
                    mask,
                    msg=f"Roundtrip through bytes() must preserve mask /{prefix}.",
                )


class TestNetAddrIp6MaskAndAddress(TestCase):
    """
    The NetAddr IPv6 mask & address (network address)
    operator tests.
    """

    def test__net_addr__ip6_mask__and_address(self) -> None:
        """
        Ensure 'address & mask' (and the reflected form) yields
        the network address — every host bit (mask=0) cleared,
        every network bit unchanged.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        for addr, mask, expected in [
            ("2001:db8:abcd:1234:5678::1", "/64", "2001:db8:abcd:1234::"),
            ("2001:db8:abcd:1234::1", "/48", "2001:db8:abcd::"),
            ("2001:db8::1", "/128", "2001:db8::1"),
            ("2001:db8::1", "/0", "::"),
        ]:
            with self.subTest(addr=addr, mask=mask):
                a = Ip6Address(addr)
                m = Ip6Mask(mask)
                self.assertEqual(
                    a & m,
                    Ip6Address(expected),
                    msg=f"{addr} & {mask} must be {expected}.",
                )
                self.assertEqual(
                    m & a,
                    Ip6Address(expected),
                    msg=f"{mask} & {addr} (reflected) must be {expected}.",
                )
                self.assertIsInstance(
                    a & m,
                    Ip6Address,
                    msg="address & mask must return an Ip6Address.",
                )

    def test__net_addr__ip6_mask__and_address_same_subnet_idiom(self) -> None:
        """
        Ensure the same-subnet idiom '(a & m) == (b & m)' admits
        hosts in the same prefix and rejects hosts outside it.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        m = Ip6Mask("/64")
        self.assertEqual(
            Ip6Address("2001:db8:0:1::5") & m,
            Ip6Address("2001:db8:0:1::abcd") & m,
            msg="2001:db8:0:1::5 and ::abcd must share a /64.",
        )
        self.assertNotEqual(
            Ip6Address("2001:db8:0:1::5") & m,
            Ip6Address("2001:db8:0:2::5") & m,
            msg="2001:db8:0:1::5 and 0:2::5 must not share a /64.",
        )

    def test__net_addr__ip6_mask__and_rejects_foreign_operand(self) -> None:
        """
        Ensure a non-address or cross-version operand yields
        'TypeError' rather than a silent wrong result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        m = Ip6Mask("/64")
        with self.assertRaises(TypeError):
            _ = m & 5
        with self.assertRaises(TypeError):
            _ = Ip4Address("10.0.0.1") & m


class TestNetAddrIp6MaskWhitespace(TestCase):
    """
    The NetAddr Ip6Mask surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip6_mask__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("/64",):
            expected = Ip6Mask(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip6Mask(wrapped),
                        expected,
                        msg=f"Ip6Mask({wrapped!r}) must equal Ip6Mask({value!r}).",
                    )
