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
This module contains tests for the NetAddr package MAC address support class.

net_addr/tests/unit/test__mac_address.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import (
    MacAddress,
    MacAddressError,
    MacAddressFormatError,
    MacAddressSanityError,
    NetAddrError,
)
from net_addr.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Test the MAC address: 00:00:00:00:00:00 (str)",
            "_args": [
                "00:00:00:00:00:00",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "00:00:00:00:00:00",
                "__repr__": "MacAddress('00:00:00:00:00:00')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "is_unspecified": True,
                "is_unicast": False,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 00:00:00:00:00:00 (None)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "00:00:00:00:00:00",
                "__repr__": "MacAddress('00:00:00:00:00:00')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "is_unspecified": True,
                "is_unicast": False,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (str)",
            "_args": [
                "02:03:04:aa:bb:cc",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (str uppercase)",
            "_args": [
                "02:03:04:AA:BB:CC",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (str Cisco-style)",
            "_args": [
                "0203.04aa.bbcc",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (str Cisco-style uppercase)",
            "_args": [
                "0203.04AA.BBCC",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (str dash-separated)",
            "_args": [
                "02-03-04-aa-bb-cc",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (bytes)",
            "_args": [
                b"\x02\x03\x04\xaa\xbb\xcc",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (bytearray)",
            "_args": [
                bytearray(b"\x02\x03\x04\xaa\xbb\xcc"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (memoryview)",
            "_args": [
                memoryview(b"\x02\x03\x04\xaa\xbb\xcc"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (MacAddress)",
            "_args": [
                MacAddress("02:03:04:aa:bb:cc"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (int)",
            "_args": [
                2211986455500,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 01:00:5e:01:02:03 (str)",
            "_args": [
                "01:00:5e:01:02:03",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "01:00:5e:01:02:03",
                "__repr__": "MacAddress('01:00:5e:01:02:03')",
                "__bytes__": b"\x01\x00\x5e\x01\x02\x03",
                "__int__": 1101088752131,
                "is_unspecified": False,
                "is_unicast": False,
                "is_multicast": True,
                "is_multicast_ip4": True,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 33:33:00:01:02:03 (str)",
            "_args": [
                "33:33:00:01:02:03",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "33:33:00:01:02:03",
                "__repr__": "MacAddress('33:33:00:01:02:03')",
                "__bytes__": b"\x33\x33\x00\x01\x02\x03",
                "__int__": 56294136414723,
                "is_unspecified": False,
                "is_unicast": False,
                "is_multicast": True,
                "is_multicast_ip4": False,
                "is_multicast_ip6": True,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 33:33:ff:01:02:03 (str)",
            "_args": [
                "33:33:ff:01:02:03",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "33:33:ff:01:02:03",
                "__repr__": "MacAddress('33:33:ff:01:02:03')",
                "__bytes__": b"\x33\x33\xff\x01\x02\x03",
                "__int__": 56298414604803,
                "is_unspecified": False,
                "is_unicast": False,
                "is_multicast": True,
                "is_multicast_ip4": False,
                "is_multicast_ip6": True,
                "is_multicast_ip6_solicited_node": True,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: ff:ff:ff:ff:ff:ff (str)",
            "_args": [
                "ff:ff:ff:ff:ff:ff",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff:ff:ff:ff:ff:ff",
                "__repr__": "MacAddress('ff:ff:ff:ff:ff:ff')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff",
                "__int__": 281474976710655,
                "is_unspecified": False,
                "is_unicast": False,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": True,
            },
        },
    ]
)
class TestNetAddrMacAddress(TestCase):
    """
    The NetAddr MAC address tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the MAC address object with testcase arguments.
        """

        self._mac_address = MacAddress(*self._args, **self._kwargs)

    def test__net_addr__mac_address__str(self) -> None:
        """
        Ensure the MAC address '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._mac_address),
            self._results["__str__"],
        )

    def test__net_addr__mac_address__repr(self) -> None:
        """
        Ensure the MAC address '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._mac_address),
            self._results["__repr__"],
        )

    def test__net_addr__mac_address__bytes(self) -> None:
        """
        Ensure the MAC address '__bytes__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._mac_address),
            self._results["__bytes__"],
        )

    def test__net_addr__mac_address__int(self) -> None:
        """
        Ensure the MAC address '__int__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(self._mac_address),
            self._results["__int__"],
        )

    def test__net_addr__mac_address__eq(self) -> None:
        """
        Ensure the MAC address '__eq__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._mac_address == self._mac_address,
            msg="MacAddress must compare equal to itself.",
        )

        self.assertFalse(
            self._mac_address == MacAddress((int(self._mac_address) + 1) & 0xFFFF_FFFF_FFFF),
            msg="MacAddress values with different integer payloads must compare unequal.",
        )

        self.assertFalse(
            self._mac_address == "not a MAC address",
            msg="MacAddress must not compare equal to an arbitrary string.",
        )

    def test__net_addr__mac_address__is_unspecified(self) -> None:
        """
        Ensure the MAC address 'is_unspecified()' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._mac_address.is_unspecified,
            self._results["is_unspecified"],
        )

    def test__net_addr__mac_address__is_unicast(self) -> None:
        """
        Ensure the MAC address 'is_unicast' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._mac_address.is_unicast,
            self._results["is_unicast"],
        )

    def test__net_addr__mac_address__is_multicast(self) -> None:
        """
        Ensure the MAC address 'is_multicast' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._mac_address.is_multicast,
            self._results["is_multicast"],
        )

    def test__net_addr__mac_address__is_multicast_ip4(self) -> None:
        """
        Ensure the MAC address 'is_multicast_ip4' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._mac_address.is_multicast__ip4,
            self._results["is_multicast_ip4"],
        )

    def test__net_addr__mac_address__is_multicast_ip6(self) -> None:
        """
        Ensure the MAC address 'is_multicast_ip6' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._mac_address.is_multicast__ip6,
            self._results["is_multicast_ip6"],
        )

    def test__net_addr__mac_address__is_multicast_ip6_solicited_node(
        self,
    ) -> None:
        """
        Ensure the MAC address 'is_multicast__ip6__solicited_node' property
        returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._mac_address.is_multicast__ip6__solicited_node,
            self._results["is_multicast_ip6_solicited_node"],
        )

    def test__net_addr__mac_address__is_broadcast(self) -> None:
        """
        Ensure the MAC address 'is_broadcast' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._mac_address.is_broadcast,
            self._results["is_broadcast"],
        )

    def test__net_addr__mac_address__unspecified(self) -> None:
        """
        Ensure the MAC address 'unspecified' property yields the all-zero
        MAC address regardless of the source instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._mac_address.unspecified,
            MacAddress(),
            msg="MacAddress.unspecified must always equal the all-zero MAC address.",
        )
        self.assertTrue(
            self._mac_address.unspecified.is_unspecified,
            msg="MacAddress.unspecified must report 'is_unspecified' as True.",
        )


@parameterized_class(
    [
        {
            "_description": "Test the MAC address format: '01:23:45:ab:cd'",
            "_args": [
                "01:23:45:ab:cd",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '01:23:45:ab:cd'"),
            },
        },
        {
            "_description": "Test the MAC address format: '01:23:45:ab:cd:ef:01'",
            "_args": [
                "01:23:45:ab:cd:ef:01",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '01:23:45:ab:cd:ef:01'"),
            },
        },
        {
            "_description": "Test the MAC address format: '01:23:45:ab:cd:eg'",
            "_args": [
                "01:23:45:ab:cd:eg",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '01:23:45:ab:cd:eg'"),
            },
        },
        {
            "_description": "Test the MAC address format: '0123.45ab' (Cisco-style too short)",
            "_args": [
                "0123.45ab",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '0123.45ab'"),
            },
        },
        {
            "_description": "Test the MAC address format: '01:23:45.ab:cd:ef' (mixed separators)",
            "_args": [
                "01:23:45.ab:cd:ef",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '01:23:45.ab:cd:ef'"),
            },
        },
        {
            "_description": "Test the MAC address format: '02:00-00:00-00:07' (hybrid colon/dash)",
            "_args": [
                "02:00-00:00-00:07",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '02:00-00:00-00:07'"),
            },
        },
        {
            "_description": "Test the MAC address format: '02-00:00:00:00:07' (hybrid dash/colon)",
            "_args": [
                "02-00:00:00:00:07",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '02-00:00:00:00:07'"),
            },
        },
        {
            "_description": "Test the MAC address format: b'\x01\x23\x45\xab\xcd'",
            "_args": [
                b"\x01\x23\x45\xab\xcd",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": (r"The MAC address format is invalid: b'\x01#E\xab\xcd'"),
            },
        },
        {
            "_description": "Test the MAC address format: b'\x01\x23\x45\xab\xcd\xef\x01'",
            "_args": [
                b"\x01\x23\x45\xab\xcd\xef\x01",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": (r"The MAC address format is invalid: b'\x01#E\xab\xcd\xef\x01'"),
            },
        },
        {
            "_description": "Test the MAC address format: -1",
            "_args": [
                -1,
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: -1",
            },
        },
        {
            "_description": "Test the MAC address format: 281474976710656",
            "_args": [
                281474976710656,
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: 281474976710656",
            },
        },
        {
            "_description": "Test the MAC address format: {}",
            "_args": [
                {},
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: {}",
            },
        },
        {
            "_description": "Test the MAC address format: 1.1",
            "_args": [
                1.1,
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: 1.1",
            },
        },
    ]
)
class TestNetAddrMacAddressErrors(TestCase):
    """
    The NetAddr MAC address error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__mac_address__errors(self) -> None:
        """
        Ensure the MAC address raises an error on invalid input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            MacAddress(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


class TestNetAddrMacAddressErrorHierarchy(TestCase):
    """
    The NetAddr MAC address error-class hierarchy tests.
    """

    def test__net_addr__mac_address__error_hierarchy(self) -> None:
        """
        Ensure 'MacAddressFormatError' sits under a per-type
        'MacAddressError' base which sits under 'NetAddrError',
        mirroring every other net_addr value type's error
        hierarchy.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(MacAddressFormatError, MacAddressError),
            msg="MacAddressFormatError must derive from the MacAddressError base.",
        )
        self.assertTrue(
            issubclass(MacAddressError, NetAddrError),
            msg="MacAddressError must derive from the NetAddrError root.",
        )

        with self.assertRaises(MacAddressError, msg="A bad MAC must be catchable as MacAddressError."):
            MacAddress("not-a-mac")
        with self.assertRaises(NetAddrError, msg="A bad MAC must remain catchable as NetAddrError."):
            MacAddress("not-a-mac")


class TestNetAddrMacAddressEquality(TestCase):
    """
    The NetAddr MAC address equality and inequality tests not tied to a
    parameterized matrix.
    """

    def test__net_addr__mac_address__eq__foreign_types(self) -> None:
        """
        Ensure the MAC address is never equal to a value of a foreign type,
        even when the underlying integer or byte payload would match.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mac = MacAddress("02:03:04:aa:bb:cc")

        self.assertFalse(
            mac == "02:03:04:aa:bb:cc",
            msg="MacAddress must not compare equal to its string representation.",
        )
        self.assertFalse(
            mac == int(mac),
            msg="MacAddress must not compare equal to its integer payload.",
        )
        self.assertFalse(
            mac == bytes(mac),
            msg="MacAddress must not compare equal to its bytes payload.",
        )
        self.assertFalse(
            mac == None,  # noqa: E711
            msg="MacAddress must not compare equal to None.",
        )

    def test__net_addr__mac_address__ne(self) -> None:
        """
        Ensure the MAC address '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mac = MacAddress("02:03:04:aa:bb:cc")
        self.assertTrue(
            mac != MacAddress("02:03:04:aa:bb:cd"),
            msg="MacAddress instances with different payloads must be unequal.",
        )
        self.assertFalse(
            mac != MacAddress("02:03:04:aa:bb:cc"),
            msg="MacAddress instances with matching payloads must not be unequal.",
        )
        self.assertTrue(
            mac != "02:03:04:aa:bb:cc",
            msg="MacAddress must be unequal to its string representation.",
        )


class TestNetAddrMacAddressHashConsistency(TestCase):
    """
    The NetAddr MAC address hash consistency tests.
    """

    def test__net_addr__mac_address__hash__distinct_instances(self) -> None:
        """
        Ensure independently constructed equal MAC addresses hash identically
        regardless of the input form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = MacAddress("02:03:04:aa:bb:cc")
        b = MacAddress(b"\x02\x03\x04\xaa\xbb\xcc")
        c = MacAddress(2211986455500)
        d = MacAddress("02-03-04-AA-BB-CC")
        e = MacAddress("0203.04aa.bbcc")

        for other, label in (
            (b, "bytes"),
            (c, "int"),
            (d, "dash-separated string"),
            (e, "Cisco-style string"),
        ):
            with self.subTest(source=label):
                self.assertEqual(
                    a,
                    other,
                    msg=f"MacAddress built from {label} must compare equal to CIDR-style constructor.",
                )
                self.assertEqual(
                    hash(a),
                    hash(other),
                    msg=f"Equal MacAddress values must hash identically across constructor forms ({label}).",
                )

    def test__net_addr__mac_address__usable_in_set(self) -> None:
        """
        Ensure equal MAC addresses collapse into a single element when used
        in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = MacAddress("02:03:04:aa:bb:cc")
        b = MacAddress(2211986455500)
        c = MacAddress("02:03:04:aa:bb:cd")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal MacAddress values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct MacAddress values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal MacAddress values as the same key.",
        )

    def test__net_addr__mac_address__usable_in_dict(self) -> None:
        """
        Ensure equal MAC addresses refer to the same dict entry regardless
        of which constructor form built the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = MacAddress("02:03:04:aa:bb:cc")
        b = MacAddress(b"\x02\x03\x04\xaa\xbb\xcc")

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="MacAddress must behave consistently as a dict key across input forms.",
        )


class TestNetAddrMacAddressRoundtrip(TestCase):
    """
    The NetAddr MAC address roundtrip tests.
    """

    def test__net_addr__mac_address__roundtrip__str(self) -> None:
        """
        Ensure 'MacAddress(str(x))' yields a MAC address equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in (
            "00:00:00:00:00:00",
            "02:03:04:aa:bb:cc",
            "01:00:5e:01:02:03",
            "33:33:ff:01:02:03",
            "ff:ff:ff:ff:ff:ff",
        ):
            with self.subTest(spec=spec):
                mac = MacAddress(spec)
                self.assertEqual(
                    MacAddress(str(mac)),
                    mac,
                    msg=f"Roundtrip through str() must preserve MAC address {spec!r}.",
                )

    def test__net_addr__mac_address__roundtrip__int(self) -> None:
        """
        Ensure 'MacAddress(int(x))' yields a MAC address equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in (
            "00:00:00:00:00:00",
            "02:03:04:aa:bb:cc",
            "ff:ff:ff:ff:ff:ff",
        ):
            with self.subTest(spec=spec):
                mac = MacAddress(spec)
                self.assertEqual(
                    MacAddress(int(mac)),
                    mac,
                    msg=f"Roundtrip through int() must preserve MAC address {spec!r}.",
                )

    def test__net_addr__mac_address__roundtrip__bytes(self) -> None:
        """
        Ensure 'MacAddress(bytes(x))' yields a MAC address equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in (
            "00:00:00:00:00:00",
            "02:03:04:aa:bb:cc",
            "ff:ff:ff:ff:ff:ff",
        ):
            with self.subTest(spec=spec):
                mac = MacAddress(spec)
                self.assertEqual(
                    MacAddress(bytes(mac)),
                    mac,
                    msg=f"Roundtrip through bytes() must preserve MAC address {spec!r}.",
                )

    def test__net_addr__mac_address__roundtrip__copy(self) -> None:
        """
        Ensure constructing a MacAddress from another MacAddress yields an
        equal instance with the same hash.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = MacAddress("02:03:04:aa:bb:cc")
        clone = MacAddress(source)

        self.assertEqual(
            clone,
            source,
            msg="Copy-constructed MacAddress must compare equal to the source.",
        )
        self.assertEqual(
            hash(clone),
            hash(source),
            msg="Copy-constructed MacAddress must share the source's hash.",
        )
        self.assertEqual(
            int(clone),
            int(source),
            msg="Copy-constructed MacAddress must preserve the integer payload.",
        )


class TestNetAddrMacAddressOrdering(TestCase):
    """
    The NetAddr MAC address ordering tests.
    """

    def test__net_addr__mac_address__ordering(self) -> None:
        """
        Ensure MAC addresses are totally ordered by their
        integer value (sortable, min/max, all comparisons).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = MacAddress("00:00:00:00:00:01")
        b = MacAddress("00:00:00:00:00:02")
        c = MacAddress("ff:ff:ff:ff:ff:fe")

        self.assertEqual(
            sorted([c, b, a]),
            [a, b, c],
            msg="MacAddress must sort ascending by integer value.",
        )
        self.assertEqual(min(c, b, a), a, msg="min() must return the lowest MacAddress.")
        self.assertEqual(max(c, b, a), c, msg="max() must return the highest MacAddress.")
        self.assertTrue(a < b, msg="MacAddress < must order by integer value.")
        self.assertTrue(a <= a and a >= a, msg="MacAddress <= / >= must be reflexive.")

    def test__net_addr__mac_address__ordering__foreign_type_raises(self) -> None:
        """
        Ensure ordering a MAC address against an unrelated type
        raises TypeError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError, msg="MacAddress < int must raise TypeError."):
            _ = MacAddress("00:00:00:00:00:01") < 5


class TestNetAddrMacAddressArithmetic(TestCase):
    """
    The NetAddr MAC address arithmetic tests.
    """

    def test__net_addr__mac_address__arithmetic(self) -> None:
        """
        Ensure 'address + int' / 'address - int' yield the
        offset MAC address (stdlib-exact: int operand only).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = MacAddress("00:00:00:00:00:10")
        self.assertEqual(a + 1, MacAddress("00:00:00:00:00:11"), msg="address + 1 must advance by one.")
        self.assertEqual(a - 1, MacAddress("00:00:00:00:00:0f"), msg="address - 1 must retreat by one.")
        self.assertIsInstance(a + 1, MacAddress, msg="Arithmetic must return a MacAddress.")

    def test__net_addr__mac_address__arithmetic__overflow_raises(self) -> None:
        """
        Ensure arithmetic past the MAC address space raises the
        net_addr sanity error (an out-of-range operation result,
        not a malformed literal) with an operation-naming message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(MacAddressSanityError) as over:
            _ = MacAddress("ff:ff:ff:ff:ff:ff") + 1
        self.assertEqual(
            str(over.exception),
            "MacAddress offset out of range: ff:ff:ff:ff:ff:ff + 1",
            msg="Overflow past ff:ff:ff:ff:ff:ff must raise MacAddressSanityError naming the operation.",
        )

        with self.assertRaises(MacAddressSanityError) as under:
            _ = MacAddress("00:00:00:00:00:00") - 1
        self.assertEqual(
            str(under.exception),
            "MacAddress offset out of range: 00:00:00:00:00:00 - 1",
            msg="Underflow below 00:00:00:00:00:00 must raise MacAddressSanityError naming the operation.",
        )

    def test__net_addr__mac_address__arithmetic__non_int_raises(self) -> None:
        """
        Ensure MAC arithmetic with a non-int operand raises
        TypeError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError, msg="address + address must raise TypeError."):
            _ = MacAddress("00:00:00:00:00:01") + MacAddress("00:00:00:00:00:02")


class TestNetAddrMacAddressFormat(TestCase):
    """
    The NetAddr MAC address __format__ tests.
    """

    def test__net_addr__mac_address__format(self) -> None:
        """
        Ensure '__format__' treats the MAC as a 48-bit
        zero-padded integer for x/X/b (with '#' / '_'), and
        also supports the modifier-free 'd' (plain decimal)
        and 'n' (locale-aware decimal) codes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = MacAddress("0a:1b:2c:3d:4e:5f")
        for spec, expected in [
            ("x", "0a1b2c3d4e5f"),
            ("X", "0A1B2C3D4E5F"),
            ("d", "11111822610015"),
            ("b", "000010100001101100101100001111010100111001011111"),
            ("#x", "0x0a1b2c3d4e5f"),
            ("_x", "0a1b_2c3d_4e5f"),
        ]:
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(a, spec),
                    expected,
                    msg=f"format(MacAddress, {spec!r}) must be {expected!r}.",
                )

    def test__net_addr__mac_address__format__decimal_codes_delegate_to_int(self) -> None:
        """
        Ensure the 'd' (plain decimal) and 'n' (locale-aware
        decimal) codes render the MAC exactly as the stdlib
        integer formatter renders its integer value, so 'n'
        honours the caller's LC_NUMERIC and 'd' is always the
        plain value, independent of the ambient locale.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = MacAddress("0a:1b:2c:3d:4e:5f")
        value = int(a)
        for code in ("d", "n"):
            with self.subTest(code=code):
                self.assertEqual(
                    format(a, code),
                    format(value, code),
                    msg=f"format(MacAddress, {code!r}) must equal format(int(addr), {code!r}).",
                )
        self.assertEqual(
            format(a, "d"),
            str(value),
            msg="The 'd' code must be the plain decimal value with no padding or grouping.",
        )

    def test__net_addr__mac_address__format__string_specs_delegate_to_str(self) -> None:
        """
        Ensure a spec carrying no recognised presentation code
        is treated as a string-presentation spec and renders
        the canonical text exactly as str() would (fill /
        align / width / precision), with no trailing 's'
        required.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = MacAddress("0a:1b:2c:3d:4e:5f")
        for spec in (">25", "<25", "^25", "25", ".8", ">25.8", "*>25"):
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(a, spec),
                    format(str(a), spec),
                    msg=f"format(MacAddress, {spec!r}) must match format(str(addr), {spec!r}).",
                )

    def test__net_addr__mac_address__format__unknown_code_raises(self) -> None:
        """
        Ensure an unsupported format code raises
        MacAddressSanityError and preserves the underlying
        stdlib ValueError as '__cause__'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(MacAddressSanityError) as ctx:
            format(MacAddress("0a:1b:2c:3d:4e:5f"), "q")
        self.assertIsInstance(
            ctx.exception.__cause__,
            ValueError,
            msg="The unknown-code SanityError must chain the stdlib ValueError as __cause__.",
        )

    def test__net_addr__mac_address__format_notation(self) -> None:
        """
        Ensure the popular MAC notation codes render correctly:
        'hy' is the hyphen form, 'ci' the Cisco three-group
        dotted form, and the default / 's' spec the canonical
        colon-separated lowercase form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = MacAddress("0a:1b:2c:3d:4e:5f")
        for spec, expected in [
            ("", "0a:1b:2c:3d:4e:5f"),
            ("s", "0a:1b:2c:3d:4e:5f"),
            ("hy", "0a-1b-2c-3d-4e-5f"),
            ("ci", "0a1b.2c3d.4e5f"),
        ]:
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(a, spec),
                    expected,
                    msg=f"format(MacAddress, {spec!r}) must be {expected!r}.",
                )

    def test__net_addr__mac_address__format_unknown_raises(self) -> None:
        """
        Ensure an unrecognised format code raises 'MacAddressSanityError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(MacAddressSanityError):
            format(MacAddress("0a:1b:2c:3d:4e:5f"), "zz")


class TestNetAddrMacAddressWhitespace(TestCase):
    """
    The NetAddr MacAddress surrounding-whitespace tolerance tests.
    """

    def test__net_addr__mac_address__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("02:00:00:00:00:07",):
            expected = MacAddress(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        MacAddress(wrapped),
                        expected,
                        msg=f"MacAddress({wrapped!r}) must equal MacAddress({value!r}).",
                    )


class TestNetAddrMacAddressIgBitEdge(TestCase):
    """
    The NetAddr MAC address I/G-bit (multicast) constant edge test.
    """

    def test__net_addr__mac_address__multicast_even_last_byte(self) -> None:
        """
        Ensure a multicast MAC whose final octet is even (so only
        the group bit, not the address LSB, is set) is still detected
        as multicast and not unicast — pinning the I/G-bit mask to
        exactly the group bit, since a fixture whose multicast MACs
        all end in an odd octet would not.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mac = MacAddress("33:33:00:00:00:02")
        self.assertTrue(
            mac.is_multicast,
            msg="A group-bit-set MAC with an even final octet must be multicast.",
        )
        self.assertFalse(
            mac.is_unicast,
            msg="A group-bit-set MAC with an even final octet must not be unicast.",
        )
