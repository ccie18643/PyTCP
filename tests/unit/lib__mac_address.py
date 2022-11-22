#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# tests/test_lib_mac_address.py - unit tests for MacAddress library
#
# ver 2.7
#


from dataclasses import dataclass

from testslide import TestCase

from pytcp.lib.mac_address import MacAddress, MacIp4AddressFormatError


class TestMacAddress(TestCase):
    """
    Unit tests for the 'MacAddress' class.
    """

    def setUp(self) -> None:
        """
        Setup tests.
        """

        @dataclass
        class MacSample:
            mac_address: MacAddress
            is_unspecified: bool = False
            is_unicast: bool = False
            is_multicast_ip4: bool = False
            is_multicast_ip6: bool = False
            is_multicast_ip6_solicited_node: bool = False
            is_broadcast: bool = False

        self.mac_samples = [
            MacSample(MacAddress("00:00:00:00:00:00"), is_unspecified=True),
            MacSample(MacAddress("02:03:04:aa:bb:cc"), is_unicast=True),
            MacSample(MacAddress("01:00:5e:01:02:03"), is_multicast_ip4=True),
            MacSample(MacAddress("33:33:00:01:02:03"), is_multicast_ip6=True),
            MacSample(
                MacAddress("33:33:ff:01:02:03"),
                is_multicast_ip6=True,
                is_multicast_ip6_solicited_node=True,
            ),
            MacSample(MacAddress("ff:ff:ff:ff:ff:ff"), is_broadcast=True),
        ]

    def test___init__(self) -> None:
        """
        Test the constructor for 'MacAddress' object.
        """
        self.assertEqual(
            MacAddress("01:23:45:ab:cd:ef")._address,
            1251004370415,
        )
        self.assertEqual(
            MacAddress(MacAddress("01:23:45:ab:cd:ef"))._address,
            1251004370415,
        )
        self.assertEqual(
            MacAddress(b"\x01#E\xab\xcd\xef")._address,
            1251004370415,
        )
        self.assertEqual(
            MacAddress(1251004370415)._address,
            1251004370415,
        )
        self.assertRaises(
            MacIp4AddressFormatError,
            MacAddress,
            "01:23:45:ab:cd",
        )
        self.assertRaises(
            MacIp4AddressFormatError,
            MacAddress,
            "01:23:45:ab:cd:ef:01",
        )
        self.assertRaises(
            MacIp4AddressFormatError,
            MacAddress,
            "01:23:45:ab:cd:eg",
        )
        self.assertRaises(
            MacIp4AddressFormatError,
            MacAddress,
            "01:23:45:ab:cd::eg",
        )
        self.assertRaises(
            MacIp4AddressFormatError,
            MacAddress,
            b"\x01#E\xab\xcd",
        )
        self.assertRaises(
            MacIp4AddressFormatError,
            MacAddress,
            b"\x01#E\xab\xcd\xef\x01",
        )
        self.assertRaises(
            MacIp4AddressFormatError,
            MacAddress,
            -1,
        )
        self.assertRaises(
            MacIp4AddressFormatError,
            MacAddress,
            281474976710656,
        )

    def test___str__(self) -> None:
        """
        Test the '__str__()' dunder.'
        """
        self.assertEqual(
            str(MacAddress("FF:00:AB:C7:D4:33")),
            "ff:00:ab:c7:d4:33",
        )

    def test___repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        self.assertEqual(
            repr(MacAddress("01:23:45:ab:cd:ef")),
            "MacAddress('01:23:45:ab:cd:ef')",
        )

    def test___bytes__(self) -> None:
        """
        Test the '__bytes__()' dunder.
        """
        self.assertEqual(
            bytes(MacAddress("01:23:45:ab:cd:ef")),
            b"\x01#E\xab\xcd\xef",
        )

    def test___int__(self) -> None:
        """
        Test the '__int__()' dunder.
        """
        self.assertEqual(
            int(MacAddress("01:23:45:ab:cd:ef")),
            1251004370415,
        )

    def test___eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        self.assertEqual(
            MacAddress("00:00:00:00:00:00"),
            MacAddress("00:00:00:00:00:00"),
        )
        self.assertNotEqual(
            MacAddress("00:00:00:00:00:00"),
            MacAddress("11:11:11:11:11:11"),
        )

    def test___hash__(self) -> None:
        """
        Test the '__hash__()' dunder.
        """
        self.assertEqual(
            hash(MacAddress("01:23:45:ab:cd:ef")),
            1251004370415,
        )

    def test_is_iunicast(self) -> None:
        """
        Test the 'is_unicast' property.
        """
        for sample in self.mac_samples:
            self.assertEqual(
                sample.mac_address.is_unicast,
                sample.is_unicast,
            )

    def test_is_multicast_ip4(self) -> None:
        """
        Test the 'is_multicast_ip4' property.
        """
        for sample in self.mac_samples:
            self.assertEqual(
                sample.mac_address.is_multicast_ip4,
                sample.is_multicast_ip4,
            )

    def test_is_multicast_ip6(self) -> None:
        """
        Test the 'is_multicast_ip6' property.
        """
        for sample in self.mac_samples:
            self.assertEqual(
                sample.mac_address.is_multicast_ip6,
                sample.is_multicast_ip6,
            )

    def test_is_multicast_ip6_solicited_node(self) -> None:
        """
        Test the 'is_multicast_ip6_solicited_node' property.
        """
        for sample in self.mac_samples:
            self.assertEqual(
                sample.mac_address.is_multicast_ip6_solicited_node,
                sample.is_multicast_ip6_solicited_node,
            )

    def test_is_broadcast(self) -> None:
        """
        Test 'is_broadcast' property.
        """
        for sample in self.mac_samples:
            self.assertEqual(
                sample.mac_address.is_broadcast,
                sample.is_broadcast,
            )
