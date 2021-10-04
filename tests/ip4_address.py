#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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
# tests/test_ip4_address.py - unit tests for Ip4Address library
#


from dataclasses import dataclass

from lib.mac_address import MacAddress
from testslide import TestCase

from pytcp.lib.ip4_address import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip4Host,
    Ip4HostFormatError,
    Ip4Mask,
    Ip4MaskFormatError,
    Ip4Network,
    Ip4NetworkFormatError,
)


class TestIp4Address(TestCase):
    def setUp(self):
        @dataclass
        class Ip4Sample:
            ip4_address: Ip4Address
            is_global: bool = False
            is_link_local: bool = False
            is_loopback: bool = False
            is_multicast: bool = False
            is_private: bool = False
            is_unspecified: bool = False
            is_reserved: bool = False
            is_limited_broadcast: bool = False
            is_unicast: bool = False
            is_invalid: bool = False

        self.ip4_samples = [
            Ip4Sample(Ip4Address("0.0.0.0"), is_unspecified=True),
            Ip4Sample(Ip4Address("0.0.0.1"), is_invalid=True),
            Ip4Sample(Ip4Address("0.255.255.255"), is_invalid=True),
            Ip4Sample(Ip4Address("1.0.0.0"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("8.8.8.8"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("169.253.255.255"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("169.255.0.0"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("126.255.255.255"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("128.0.0.0"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("9.255.255.255"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("11.0.0.0"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("172.15.255.255"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("172.32.0.0"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("192.167.255.255"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("192.169.0.0"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("223.255.255.255"), is_global=True, is_unicast=True),
            Ip4Sample(Ip4Address("169.254.0.0"), is_link_local=True, is_unicast=True),
            Ip4Sample(Ip4Address("169.254.100.10"), is_link_local=True, is_unicast=True),
            Ip4Sample(Ip4Address("169.254.255.255"), is_link_local=True, is_unicast=True),
            Ip4Sample(Ip4Address("127.0.0.0"), is_loopback=True, is_unicast=True),
            Ip4Sample(Ip4Address("127.100.50.25"), is_loopback=True, is_unicast=True),
            Ip4Sample(Ip4Address("127.255.255.255"), is_loopback=True, is_unicast=True),
            Ip4Sample(Ip4Address("224.0.0.0"), is_multicast=True),
            Ip4Sample(Ip4Address("230.0.0.5"), is_multicast=True),
            Ip4Sample(Ip4Address("239.255.255.255"), is_multicast=True),
            Ip4Sample(Ip4Address("192.168.0.0"), is_private=True, is_unicast=True),
            Ip4Sample(Ip4Address("192.168.100.100"), is_private=True, is_unicast=True),
            Ip4Sample(Ip4Address("192.168.255.255"), is_private=True, is_unicast=True),
            Ip4Sample(Ip4Address("172.16.0.0"), is_private=True, is_unicast=True),
            Ip4Sample(Ip4Address("172.16.100.100"), is_private=True, is_unicast=True),
            Ip4Sample(Ip4Address("172.31.255.255"), is_private=True, is_unicast=True),
            Ip4Sample(Ip4Address("10.0.0.0"), is_private=True, is_unicast=True),
            Ip4Sample(Ip4Address("10.100.100.100"), is_private=True, is_unicast=True),
            Ip4Sample(Ip4Address("10.255.255.255"), is_private=True, is_unicast=True),
            Ip4Sample(Ip4Address("240.0.0.0"), is_reserved=True),
            Ip4Sample(Ip4Address("255.255.255.254"), is_reserved=True),
            Ip4Sample(Ip4Address("255.255.255.255"), is_limited_broadcast=True),
        ]

    def test___init__(self):
        self.assertEqual(Ip4Address("192.168.9.1")._address, 3232237825)
        self.assertEqual(Ip4Address(Ip4Address("192.168.9.1"))._address, 3232237825)
        self.assertEqual(Ip4Address(b"\xc0\xa8\t\x01")._address, 3232237825)
        self.assertEqual(Ip4Address(bytearray(b"\xc0\xa8\t\x01"))._address, 3232237825)
        self.assertEqual(Ip4Address(memoryview(b"\xc0\xa8\t\x01"))._address, 3232237825)
        self.assertEqual(Ip4Address(3232237825)._address, 3232237825)
        self.assertRaises(Ip4AddressFormatError, Ip4Address, "10.10.10.256")
        self.assertRaises(Ip4AddressFormatError, Ip4Address, "10.10..10")
        self.assertRaises(Ip4AddressFormatError, Ip4Address, b"\xff\xff\xff")
        self.assertRaises(Ip4AddressFormatError, Ip4Address, b"\xff\xff\xff\xff\xff")
        self.assertRaises(Ip4AddressFormatError, Ip4Address, -1)
        self.assertRaises(Ip4AddressFormatError, Ip4Address, 4294967296)

    def test___str__(self):
        self.assertEqual(str(Ip4Address("192.168.9.1")), "192.168.9.1")

    def test___repr__(self):
        self.assertEqual(repr(Ip4Address("192.168.9.1")), "Ip4Address('192.168.9.1')")

    def test___bytes__(self):
        self.assertEqual(bytes(Ip4Address("192.168.9.1")), b"\xc0\xa8\t\x01")

    def test___eq__(self):
        self.assertEqual(Ip4Address("192.168.9.1"), Ip4Address("192.168.9.1"))

    def test___hash__(self):
        self.assertEqual(hash(Ip4Address("192.168.9.1")), hash(3232237825))

    def test___contains__(self):
        self.assertIn(Ip4Address("192.168.9.7"), Ip4Network("192.168.9.0/24"))
        self.assertNotIn(Ip4Address("192.168.9.7"), Ip4Network("172.16.0.0/12"))
        self.assertNotIn(Ip4Address("192.168.9.7"), Ip4Network("10.0.0.0/8"))

    def test_version(self):
        self.assertEqual(Ip4Address("192.168.9.1").version, 4)

    def test_is_invalid(self):
        for sample in self.ip4_samples:
            self.assertEqual(sample.ip4_address.is_invalid, sample.is_invalid)

    def test_is_global(self):
        for sample in self.ip4_samples:
            self.assertEqual(sample.ip4_address.is_global, sample.is_global)

    def test_is_link_local(self):
        for sample in self.ip4_samples:
            self.assertEqual(sample.ip4_address.is_link_local, sample.is_link_local)

    def test_is_loopback(self):
        for sample in self.ip4_samples:
            self.assertEqual(sample.ip4_address.is_loopback, sample.is_loopback)

    def test_is_multicast(self):
        for sample in self.ip4_samples:
            self.assertEqual(sample.ip4_address.is_multicast, sample.is_multicast)

    def test_is_private(self):
        for sample in self.ip4_samples:
            self.assertEqual(sample.ip4_address.is_private, sample.is_private)

    def test_is_unspecified(self):
        for sample in self.ip4_samples:
            self.assertEqual(sample.ip4_address.is_unspecified, sample.is_unspecified)

    def test_is_limited_broadcast(self):
        for sample in self.ip4_samples:
            self.assertEqual(sample.ip4_address.is_limited_broadcast, sample.is_limited_broadcast)

    def test_is_unicast(self):
        for sample in self.ip4_samples:
            self.assertEqual(sample.ip4_address.is_unicast, sample.is_unicast)

    def test_unspecified(self):
        self.assertEqual(Ip4Address("192.168.9.1").unspecified, Ip4Address("0.0.0.0"))

    def test_multicast_mac(self):
        self.assertEqual(Ip4Address("239.192.0.1").multicast_mac, MacAddress("01:00:5e:40:00:01"))


class TestIp4Mask(TestCase):
    def test___init__(self):
        self.assertEqual(Ip4Mask("255.255.255.255")._mask, 4294967295)
        self.assertEqual(Ip4Mask("255.255.255.0")._mask, 4294967040)
        self.assertEqual(Ip4Mask("/24")._mask, 4294967040)
        self.assertEqual(Ip4Mask(Ip4Mask("255.255.255.0"))._mask, 4294967040)
        self.assertEqual(Ip4Mask(b"\xff\xff\xff\x00")._mask, 4294967040)
        self.assertEqual(Ip4Mask(bytearray(b"\xff\xff\xff\x00"))._mask, 4294967040)
        self.assertEqual(Ip4Mask(memoryview(b"\xff\xff\xff\x00"))._mask, 4294967040)
        self.assertEqual(Ip4Mask(4294967040)._mask, 4294967040)
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, "300.0.0.0")
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, "255.255.0.1")
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, "/33")
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, "10/33")
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, b"\xff\xff\xff")
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, b"\xff\x00\xff\xff")
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, b"\xff\xff\xff\xff\xff")
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, 4294950913)
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, -1)
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, 4294967296)
        self.assertRaises(Ip4MaskFormatError, Ip4Mask, 8)

    def test___str__(self):
        self.assertEqual(str(Ip4Mask("255.255.240.0")), "/20")

    def test___repr__(self):
        self.assertEqual(repr(Ip4Mask("/12")), "Ip4Mask('/12')")

    def test___bytes__(self):
        self.assertEqual(bytes(Ip4Mask("255.255.0.0")), b"\xff\xff\x00\x00")

    def test___int__(self):
        self.assertEqual(int(Ip4Mask("255.255.192.0")), 4294950912)

    def test___eq__(self):
        self.assertEqual(Ip4Mask("255.255.255.240"), Ip4Mask("/28"))
        self.assertNotEqual(Ip4Mask("255.255.255.240"), Ip4Mask("/29"))

    def test___hash__(self):
        self.assertEqual(hash(Ip4Mask("/32")), hash(4294967295))

    def test___len__(self):
        for n in range(33):
            self.assertEqual(len(Ip4Mask(f"/{n}")), n)

    def test_version(self):
        self.assertEqual(Ip4Mask("/0").version, 4)


class TestIp4Network(TestCase):
    def test___init__(self):
        self.assertEqual(Ip4Network("192.168.9.100/24")._address, Ip4Address("192.168.9.0"))
        self.assertEqual(Ip4Network("192.168.9.100/24")._mask, Ip4Mask("255.255.255.0"))
        self.assertEqual(Ip4Network(Ip4Network("192.168.9.100/24"))._address, Ip4Address("192.168.9.0"))
        self.assertEqual(Ip4Network(Ip4Network("192.168.9.100/24"))._mask, Ip4Mask("255.255.255.0"))
        self.assertEqual(Ip4Network((Ip4Address("192.168.9.100"), Ip4Mask("255.255.255.0")))._address, Ip4Address("192.168.9.0"))
        self.assertEqual(Ip4Network((Ip4Address("192.168.9.100"), Ip4Mask("255.255.255.0")))._mask, Ip4Mask("255.255.255.0"))
        self.assertEqual(Ip4Network("192.168.9.100/24")._address, Ip4Address("192.168.9.0"))
        self.assertEqual(Ip4Network("192.168.9.100/24")._mask, Ip4Mask("255.255.255.0"))
        self.assertEqual(Ip4Network("192.168.9.100/0")._address, Ip4Address("0.0.0.0"))
        self.assertEqual(Ip4Network("192.168.9.100/0")._mask, Ip4Mask("0.0.0.0"))
        self.assertRaises(Ip4NetworkFormatError, Ip4Network, "192.168.9.0//32")
        self.assertRaises(Ip4NetworkFormatError, Ip4Network, "192.168.9.0/321")
        self.assertRaises(Ip4NetworkFormatError, Ip4Network, "192.168.9.0")

    def test___str__(self):
        self.assertEqual(str(Ip4Network("192.168.9.0/24")), "192.168.9.0/24")

    def test___repr__(self):
        self.assertEqual(repr(Ip4Network("172.16.0.0/12")), "Ip4Network('172.16.0.0/12')")

    def test___eq__(self):
        self.assertEqual(Ip4Network("0.0.0.0/0"), Ip4Network("0.0.0.0/0"))
        self.assertNotEqual(Ip4Network("0.0.0.0/0"), Ip4Network("0.0.0.0/32"))

    def test___hash__(self):
        self.assertEqual(hash(Ip4Network("10.0.0.0/8")), hash(Ip4Address("10.0.0.0")) ^ hash(Ip4Mask("255.0.0.0")))

    def test_address(self):
        self.assertEqual(Ip4Network("192.168.9.100/24").address, Ip4Address("192.168.9.0"))

    def test_mask(self):
        self.assertEqual(Ip4Network("192.168.9.0/24").mask, Ip4Mask("255.255.255.0"))

    def test_broadcast(self):
        self.assertEqual(Ip4Network("192.168.9.100/24").broadcast, Ip4Address("192.168.9.255"))

    def test_version(self):
        self.assertEqual(Ip4Network("0.0.0.0/0").version, 4)


class TestIp4Host(TestCase):
    def test___init__(self):
        self.assertEqual(Ip4Host("192.168.9.100/24")._address, Ip4Address("192.168.9.100"))
        self.assertEqual(Ip4Host("192.168.9.100/24")._network, Ip4Network("192.168.9.0/24"))
        self.assertEqual(Ip4Host((Ip4Address("192.168.9.100"), Ip4Mask("255.255.255.0")))._address, Ip4Address("192.168.9.100"))
        self.assertEqual(Ip4Host((Ip4Address("192.168.9.100"), Ip4Mask("255.255.255.0")))._network, Ip4Network("192.168.9.0/24"))
        self.assertEqual(Ip4Host((Ip4Address("192.168.9.100"), Ip4Network("192.168.9.0/24")))._address, Ip4Address("192.168.9.100"))
        self.assertEqual(Ip4Host((Ip4Address("192.168.9.100"), Ip4Network("192.168.9.0/24")))._network, Ip4Network("192.168.9.0/24"))
        self.assertEqual(Ip4Host(Ip4Host("192.168.9.100/24"))._address, Ip4Address("192.168.9.100"))
        self.assertEqual(Ip4Host(Ip4Host("192.168.9.100/24"))._network, Ip4Network("192.168.9.0/24"))
        self.assertRaises(Ip4HostFormatError, Ip4Host, "192.168.9.5//32")
        self.assertRaises(Ip4HostFormatError, Ip4Host, "192.168.9.5")

    def test___str__(self):
        self.assertEqual(str(Ip4Host("192.168.9.100/24")), "192.168.9.100/24")

    def test___repr__(self):
        self.assertEqual(repr(Ip4Host("172.16.0.50/12")), "Ip4Host('172.16.0.50/12')")

    def test___eq__(self):
        self.assertEqual(Ip4Host("1.1.1.1/32"), Ip4Host("1.1.1.1/32"))
        self.assertNotEqual(Ip4Host("0.0.0.0/0"), Ip4Host("0.0.0.0/32"))
        self.assertNotEqual(Ip4Host("0.0.0.0/0"), Ip4Host("1.1.1.1/0"))

    def test___hash__(self):
        self.assertEqual(hash(Ip4Host("10.0.0.1/8")), hash(Ip4Address("10.0.0.1")) ^ hash(Ip4Network("10.0.0.0/8")))

    def test_address(self):
        self.assertEqual(Ip4Host("192.168.9.100/24").address, Ip4Address("192.168.9.100"))

    def test_network(self):
        self.assertEqual(Ip4Host("192.168.9.50/24").network, Ip4Network("192.168.9.0/24"))

    def test_version(self):
        self.assertEqual(Ip4Host("0.0.0.0/0").version, 4)
