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
This module contains tests for the NetAddr package MAC address support class.

tests/unit/lib/net_addr/test__mac_address.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.net_addr import MacAddress, MacAddressFormatError


@parameterized_class(
    [
        {
            "_description": "Test the MAC address: 00:00:00:00:00:00 (str)",
            "_args": {
                "address": "00:00:00:00:00:00",
            },
            "_results": {
                "__str__": "00:00:00:00:00:00",
                "__repr__": "MacAddress('00:00:00:00:00:00')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": 0,
                "is_unspecified": True,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 00:00:00:00:00:00 (None)",
            "_args": {
                "address": None,
            },
            "_results": {
                "__str__": "00:00:00:00:00:00",
                "__repr__": "MacAddress('00:00:00:00:00:00')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": 0,
                "is_unspecified": True,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (str)",
            "_args": {
                "address": "02:03:04:aa:bb:cc",
            },
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": 2211986455500,
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
            "_args": {
                "address": "02:03:04:AA:BB:CC",
            },
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": 2211986455500,
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
            "_args": {
                "address": b"\x02\x03\x04\xaa\xbb\xcc",
            },
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": 2211986455500,
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
            "_args": {
                "address": bytearray(b"\x02\x03\x04\xaa\xbb\xcc"),
            },
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": 2211986455500,
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
            "_args": {
                "address": memoryview(b"\x02\x03\x04\xaa\xbb\xcc"),
            },
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": 2211986455500,
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
            "_args": {
                "address": MacAddress("02:03:04:aa:bb:cc"),
            },
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": 2211986455500,
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
            "_args": {
                "address": 2211986455500,
            },
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": 2211986455500,
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
            "_args": {
                "address": "01:00:5e:01:02:03",
            },
            "_results": {
                "__str__": "01:00:5e:01:02:03",
                "__repr__": "MacAddress('01:00:5e:01:02:03')",
                "__bytes__": b"\x01\x00\x5e\x01\x02\x03",
                "__int__": 1101088752131,
                "__hash__": 1101088752131,
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
            "_args": {
                "address": "33:33:00:01:02:03",
            },
            "_results": {
                "__str__": "33:33:00:01:02:03",
                "__repr__": "MacAddress('33:33:00:01:02:03')",
                "__bytes__": b"\x33\x33\x00\x01\x02\x03",
                "__int__": 56294136414723,
                "__hash__": 56294136414723,
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
            "_description": "Test the MAC address: 33:33:00:01:02:03 (str)",
            "_args": {
                "address": "33:33:00:01:02:03",
            },
            "_results": {
                "__str__": "33:33:00:01:02:03",
                "__repr__": "MacAddress('33:33:00:01:02:03')",
                "__bytes__": b"\x33\x33\x00\x01\x02\x03",
                "__int__": 56294136414723,
                "__hash__": 56294136414723,
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
            "_args": {
                "address": "33:33:ff:01:02:03",
            },
            "_results": {
                "__str__": "33:33:ff:01:02:03",
                "__repr__": "MacAddress('33:33:ff:01:02:03')",
                "__bytes__": b"\x33\x33\xff\x01\x02\x03",
                "__int__": 56298414604803,
                "__hash__": 56298414604803,
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
            "_args": {
                "address": "ff:ff:ff:ff:ff:ff",
            },
            "_results": {
                "__str__": "ff:ff:ff:ff:ff:ff",
                "__repr__": "MacAddress('ff:ff:ff:ff:ff:ff')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff",
                "__int__": 281474976710655,
                "__hash__": 281474976710655,
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
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the MAC address object with testcase arguments.
        """

        self._mac_address = MacAddress(**self._args)

    def test__net_addr__mac_address__str(self) -> None:
        """
        Ensure the MAC address '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._mac_address),
            self._results["__str__"],
        )

    def test__net_addr__mac_address__repr(self) -> None:
        """
        Ensure the MAC address '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._mac_address),
            self._results["__repr__"],
        )

    def test__net_addr__mac_address__bytes(self) -> None:
        """
        Ensure the MAC address '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._mac_address),
            self._results["__bytes__"],
        )

    def test__net_addr__mac_address__int(self) -> None:
        """
        Ensure the MAC address '__int__()' method returns a correct value.
        """

        self.assertEqual(
            int(self._mac_address),
            self._results["__int__"],
        )

    def test__net_addr__mac_address__eq(self) -> None:
        """
        Ensure the MAC address '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._mac_address == self._mac_address,
        )

        self.assertFalse(
            self._mac_address
            == MacAddress((int(self._mac_address) + 1) & 0xFFFF_FFFF_FFFF),
        )

        self.assertFalse(
            self._mac_address == "not a MAC address",
        )

    def test__net_addr__mac_address__hash(self) -> None:
        """
        Ensure the MAC address '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            int(self._mac_address),
            self._results["__hash__"],
        )

    def test__net_addr__mac_address__is_unspecified(self) -> None:
        """
        Ensure the MAC address 'is_unspecified()' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_unspecified,
            self._results["is_unspecified"],
        )

    def test__net_addr__mac_address__is_unicast(self) -> None:
        """
        Ensure the MAC address 'is_unicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_unicast,
            self._results["is_unicast"],
        )

    def test__net_addr__mac_address__is_multicast(self) -> None:
        """
        Ensure the MAC address 'is_multicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_multicast,
            self._results["is_multicast"],
        )

    def test__net_addr__mac_address__is_multicast_ip4(self) -> None:
        """
        Ensure the MAC address 'is_multicast_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_multicast_ip4,
            self._results["is_multicast_ip4"],
        )

    def test__net_addr__mac_address__is_multicast_ip6(self) -> None:
        """
        Ensure the MAC address 'is_multicast_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_multicast_ip6,
            self._results["is_multicast_ip6"],
        )

    def test__net_addr__mac_address__is_multicast_ip6_solicited_node(
        self,
    ) -> None:
        """
        Ensure the MAC address 'is_multicast_ip6_colicited_node' property
        returns a correct value.
        """

        self.assertEqual(
            self._mac_address.is_multicast_ip6_solicited_node,
            self._results["is_multicast_ip6_solicited_node"],
        )

    def test__net_addr__mac_address__is_broadcast(self) -> None:
        """
        Ensure the MAC address 'is_broadcast' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_broadcast,
            self._results["is_broadcast"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the MAC address format: '01:23:45:ab:cd'",
            "_args": {
                "address": "01:23:45:ab:cd",
            },
            "_results": {
                "error": MacAddressFormatError,
                "error_message": (
                    "The MAC address format is invalid: '01:23:45:ab:cd'"
                ),
            },
        },
        {
            "_description": "Test the MAC address format: '01:23:45:ab:cd:ef:01'",
            "_args": {
                "address": "01:23:45:ab:cd:ef:01",
            },
            "_results": {
                "error": MacAddressFormatError,
                "error_message": (
                    "The MAC address format is invalid: '01:23:45:ab:cd:ef:01'"
                ),
            },
        },
        {
            "_description": "Test the MAC address format: '01:23:45:ab:cd:eg'",
            "_args": {
                "address": "01:23:45:ab:cd:eg",
            },
            "_results": {
                "error": MacAddressFormatError,
                "error_message": (
                    "The MAC address format is invalid: '01:23:45:ab:cd:eg'"
                ),
            },
        },
        {
            "_description": "Test the MAC address format: b'\x01\x23\x45\xab\xcd'",
            "_args": {
                "address": b"\x01\x23\x45\xab\xcd",
            },
            "_results": {
                "error": MacAddressFormatError,
                "error_message": (
                    r"The MAC address format is invalid: b'\x01#E\xab\xcd'"
                ),
            },
        },
        {
            "_description": "Test the MAC address format: b'\x01\x23\x45\xab\xcd\xef\x01'",
            "_args": {
                "address": b"\x01\x23\x45\xab\xcd\xef\x01",
            },
            "_results": {
                "error": MacAddressFormatError,
                "error_message": (
                    r"The MAC address format is invalid: b'\x01#E\xab\xcd\xef\x01'"
                ),
            },
        },
        {
            "_description": "Test the MAC address format: -1",
            "_args": {
                "address": -1,
            },
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: -1",
            },
        },
        {
            "_description": "Test the MAC address format: 281474976710656",
            "_args": {
                "address": 281474976710656,
            },
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: 281474976710656",
            },
        },
        {
            "_description": "Test the MAC address format: {}",
            "_args": {
                "address": {},
            },
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: {}",
            },
        },
        {
            "_description": "Test the MAC address format: 1.1",
            "_args": {
                "address": 1.1,
            },
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
    _args: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__mac_address__errors(self) -> None:
        """
        Ensure the MAC address raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            MacAddress(**self._args)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )
