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
# tests/unit/test_ip6_address.py - unit tests for Ip6Address library
#
# ver 3.0.2
#


from dataclasses import dataclass

from testslide import TestCase

from pytcp.lib.net_addr import (
    Ip6Address,
    Ip6AddressFormatError,
    Ip6Host,
    Ip6HostFormatError,
    Ip6HostGatewayError,
    Ip6Mask,
    Ip6MaskFormatError,
    Ip6Network,
    Ip6NetworkFormatError,
)
from pytcp.lib.net_addr import MacAddress


class TestIp6Address(TestCase):
    """
    Unit tests for 'Ip6Address' class.
    """

    def setUp(self) -> None:
        """
        Setup tests.
        """

        @dataclass
        class Ip6Sample:
            ip6_address: Ip6Address
            is_unspecified: bool = False
            is_loopback: bool = False
            is_global: bool = False
            is_private: bool = False
            is_link_local: bool = False
            is_multicast: bool = False
            is_solicited_node_multicast: bool = False
            is_unicast: bool = False

        self.ip6_samples = [
            Ip6Sample(Ip6Address("::"), is_unspecified=True),
            Ip6Sample(Ip6Address("::1"), is_loopback=True, is_unicast=True),
            Ip6Sample(Ip6Address("::2")),
            Ip6Sample(Ip6Address("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
            Ip6Sample(Ip6Address("2000::"), is_global=True, is_unicast=True),
            Ip6Sample(
                Ip6Address("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                is_global=True,
                is_unicast=True,
            ),
            Ip6Sample(Ip6Address("4000::0")),
            Ip6Sample(Ip6Address("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
            Ip6Sample(Ip6Address("fc00::"), is_private=True, is_unicast=True),
            Ip6Sample(
                Ip6Address("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                is_private=True,
                is_unicast=True,
            ),
            Ip6Sample(Ip6Address("fe00::")),
            Ip6Sample(Ip6Address("fe79:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
            Ip6Sample(
                Ip6Address("fe80::"), is_link_local=True, is_unicast=True
            ),
            Ip6Sample(
                Ip6Address("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                is_link_local=True,
                is_unicast=True,
            ),
            Ip6Sample(Ip6Address("fec0::")),
            Ip6Sample(Ip6Address("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
            Ip6Sample(Ip6Address("ff00::"), is_multicast=True),
            Ip6Sample(
                Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                is_multicast=True,
            ),
            Ip6Sample(
                Ip6Address("ff02::1:ff00:0"),
                is_multicast=True,
                is_solicited_node_multicast=True,
            ),
            Ip6Sample(
                Ip6Address("ff02::1:ffff:ffff"),
                is_multicast=True,
                is_solicited_node_multicast=True,
            ),
        ]

    def test___init__(self) -> None:
        """
        Test the 'Ip6Address' object constructor.
        """
        self.assertEqual(
            Ip6Address("2001::1234:5678:90ab:cdef")._address,
            42540488161975842761862124892595146223,
        )
        self.assertEqual(
            Ip6Address("2001::1234:5678:90AB:CDEF")._address,
            42540488161975842761862124892595146223,
        )
        self.assertEqual(
            Ip6Address("2001:0:0:0:1234:5678:90ab:cdef")._address,
            42540488161975842761862124892595146223,
        )
        self.assertEqual(
            Ip6Address("2001:0000:0000::1234:5678:90ab:cdef")._address,
            42540488161975842761862124892595146223,
        )
        self.assertEqual(
            Ip6Address(Ip6Address("2001::1234:5678:90ab:cdef"))._address,
            42540488161975842761862124892595146223,
        )
        self.assertEqual(
            Ip6Address(
                b" \x01\x00\x00\x00\x00\x00\x00\x124Vx\x90\xab\xcd\xef"
            )._address,
            42540488161975842761862124892595146223,
        )
        self.assertEqual(
            Ip6Address(
                bytearray(
                    b" \x01\x00\x00\x00\x00\x00\x00\x124Vx\x90\xab\xcd\xef"
                )
            )._address,
            42540488161975842761862124892595146223,
        )
        self.assertEqual(
            Ip6Address(
                memoryview(
                    b" \x01\x00\x00\x00\x00\x00\x00\x124Vx\x90\xab\xcd\xef"
                )
            )._address,
            42540488161975842761862124892595146223,
        )
        self.assertEqual(
            Ip6Address(42540488161975842761862124892595146223)._address,
            42540488161975842761862124892595146223,
        )
        self.assertRaises(
            Ip6AddressFormatError, Ip6Address, "2001::1234:5678:90ab:cdeg"
        )
        self.assertRaises(
            Ip6AddressFormatError, Ip6Address, "2001:1234:5678:90ab:cdef"
        )
        self.assertRaises(
            Ip6AddressFormatError, Ip6Address, "2001::1234::5678:90ab:cdef"
        )
        self.assertRaises(
            Ip6AddressFormatError, Ip6Address, "2001:::1234::5678:90ab:cdef"
        )
        self.assertRaises(
            Ip6AddressFormatError,
            Ip6Address,
            b" \x01\x00\x00\x00\x00\x00\x00\x124Vx\x90\xab\xcd",
        )
        self.assertRaises(
            Ip6AddressFormatError,
            Ip6Address,
            b" \x01\x00\x00\x00\x00\x00\x00\x124Vx\x90\xab\xcd\xef\xef",
        )
        self.assertRaises(Ip6AddressFormatError, Ip6Address, -1)
        self.assertRaises(
            Ip6AddressFormatError,
            Ip6Address,
            340282366920938463463374607431768211456,
        )

    def test___str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        self.assertEqual(
            str(Ip6Address("2001::1234:5678:90ab:cdef")),
            "2001::1234:5678:90ab:cdef",
        )

    def test___repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        self.assertEqual(
            repr(Ip6Address("2001::1234:5678:90ab:cdef")),
            "Ip6Address('2001::1234:5678:90ab:cdef')",
        )

    def test___bytes__(self) -> None:
        """
        Test the '__bytes__()' dunder.
        """
        self.assertEqual(
            bytes(Ip6Address("2001::1234:5678:90ab:cdef")),
            b" \x01\x00\x00\x00\x00\x00\x00\x124Vx\x90\xab\xcd\xef",
        )

    def test___eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        self.assertEqual(
            Ip6Address("2001::1234:5678:90ab:cdef"),
            Ip6Address("2001::1234:5678:90ab:cdef"),
        )

    def test___hash__(self) -> None:
        """
        Test the '__hash__()' dunder.
        """
        self.assertEqual(
            hash(Ip6Address("2001::1234:5678:90ab:cdef")),
            hash(42540488161975842761862124892595146223),
        )

    def test_version(self) -> None:
        """
        Test the 'version' property.
        """
        self.assertEqual(Ip6Address("2001::1234:5678:90ab:cdef").version, 6)

    def test_is_unspecified(self) -> None:
        """
        Test the 'is_unspecified' property.
        """
        for sample in self.ip6_samples:
            self.assertEqual(
                sample.ip6_address.is_unspecified, sample.is_unspecified
            )

    def test_is_loopback(self) -> None:
        """
        Test the 'is_loopback' property.
        """
        for sample in self.ip6_samples:
            self.assertEqual(sample.ip6_address.is_loopback, sample.is_loopback)

    def test_is_global(self) -> None:
        """
        Test the 'is_global' property.
        """
        for sample in self.ip6_samples:
            self.assertEqual(sample.ip6_address.is_global, sample.is_global)

    def test_is_private(self) -> None:
        """
        Test the 'is_private' property.
        """
        for sample in self.ip6_samples:
            self.assertEqual(sample.ip6_address.is_private, sample.is_private)

    def test_is_link_local(self) -> None:
        """
        Test the 'is_link_local' property.
        """
        for sample in self.ip6_samples:
            self.assertEqual(
                sample.ip6_address.is_link_local, sample.is_link_local
            )

    def test_is_multicast(self) -> None:
        """
        Test the 'is_multicast' property.
        """
        for sample in self.ip6_samples:
            self.assertEqual(
                sample.ip6_address.is_multicast, sample.is_multicast
            )

    def test_is_solicited_node_multicast(self) -> None:
        """
        Test the 'is_solicited_multicast' property.
        """
        for sample in self.ip6_samples:
            self.assertEqual(
                sample.ip6_address.is_solicited_node_multicast,
                sample.is_solicited_node_multicast,
            )

    def test_is_unicast(self) -> None:
        """
        Test the 'is_unicast' property.
        """
        for sample in self.ip6_samples:
            self.assertEqual(sample.ip6_address.is_unicast, sample.is_unicast)

    def test_solicited_node_multicast(self) -> None:
        """
        Test the 'solicited_node_multicast' property.
        """
        self.assertEqual(
            Ip6Address("2001::1234:5678:90ab:cdef").solicited_node_multicast,
            Ip6Address("ff02::1:ffab:cdef"),
        )

    def test_multicast_mac(self) -> None:
        """
        Test the 'multicast_mac' property.
        """
        self.assertEqual(
            Ip6Address("ff02::1:ffab:cdef").multicast_mac,
            MacAddress("33:33:ff:ab:cd:ef"),
        )

    def test_unspecified(self) -> None:
        """
        Test the 'unspecified' property.
        """
        self.assertEqual(
            Ip6Address("2001::1234:5678:90ab:cdef").unspecified,
            Ip6Address("::"),
        )


class TestIp6Mask(TestCase):
    """
    Unit tests for 'Ip6Mask' class.
    """

    def test___init__(self) -> None:
        """
        Test the constructor for 'Ip6Mask' object.
        """
        self.assertEqual(
            Ip6Mask(
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            )._mask,
            340282366920938463463374607431768211455,
        )
        self.assertEqual(
            Ip6Mask("/64")._mask, 340282366920938463444927863358058659840
        )
        self.assertEqual(
            Ip6Mask(Ip6Mask("/64"))._mask,
            340282366920938463444927863358058659840,
        )
        self.assertEqual(
            Ip6Mask(
                b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
            )._mask,
            340282366920938463444927863358058659840,
        )
        self.assertEqual(
            Ip6Mask(
                bytearray(
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
                )
            )._mask,
            340282366920938463444927863358058659840,
        )
        self.assertEqual(
            Ip6Mask(
                memoryview(
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
                )
            )._mask,
            340282366920938463444927863358058659840,
        )
        self.assertEqual(
            Ip6Mask(340282366920938463444927863358058659840)._mask,
            340282366920938463444927863358058659840,
        )
        self.assertRaises(Ip6MaskFormatError, Ip6Mask, "/129")
        self.assertRaises(Ip6MaskFormatError, Ip6Mask, "2001::/64")
        self.assertRaises(Ip6MaskFormatError, Ip6Mask, b"\xff\xff\xff")
        self.assertRaises(Ip6MaskFormatError, Ip6Mask, b"\xff\x00\xff\xff")
        self.assertRaises(Ip6MaskFormatError, Ip6Mask, b"\xff\xff\xff\xff\xff")
        self.assertRaises(Ip6MaskFormatError, Ip6Mask, -1)
        self.assertRaises(
            Ip6MaskFormatError, Ip6Mask, 340282366920938463463374607431768211456
        )
        self.assertRaises(Ip6MaskFormatError, Ip6Mask, 64)

    def test___str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        self.assertEqual(str(Ip6Mask("/64")), "/64")

    def test___repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        self.assertEqual(repr(Ip6Mask("/80")), "Ip6Mask('/80')")

    def test___bytes__(self) -> None:
        """
        Test the '__bytes__()' dunder.
        """
        self.assertEqual(
            bytes(
                Ip6Mask(
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                    b"\xff\x00\x00\x00\x00"
                )
            ),
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00",
        )

    def test___int__(self) -> None:
        """
        Test the '__int__()' dunder.
        """
        self.assertEqual(
            int(Ip6Mask("/48")), 340282366920937254537554992802593505280
        )

    def test___eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        self.assertEqual(Ip6Mask("/64"), Ip6Mask("/64"))
        self.assertNotEqual(Ip6Mask("/64"), Ip6Mask("/128"))

    def test___hash__(self) -> None:
        """
        Test the '__hash__' dunder.
        """
        self.assertEqual(
            hash(Ip6Mask("/64")), hash(340282366920938463444927863358058659840)
        )

    def test___len__(self) -> None:
        """
        Test the '__len__()' dunder.
        """
        for n in range(129):
            self.assertEqual(len(Ip6Mask(f"/{n}")), n)

    def test_version(self) -> None:
        """
        Test the 'version' property.
        """
        self.assertEqual(Ip6Mask("/0").version, 6)


class TestIp6Network(TestCase):
    """
    Unit tests for 'Ip6Network' class.
    """

    def test___init__(self) -> None:
        """
        Test the constructor for 'Ip6Network' object.
        """
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::/64")._address,
            Ip6Address("1234:5678:90ab:cdef::"),
        )
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::/64")._mask, Ip6Mask("/64")
        )
        self.assertEqual(
            Ip6Network(Ip6Network("1234:5678:90ab:cdef::/64"))._address,
            Ip6Address("1234:5678:90ab:cdef::"),
        )
        self.assertEqual(
            Ip6Network(Ip6Network("1234:5678:90ab:cdef::/64"))._mask,
            Ip6Mask("/64"),
        )
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::1/128")._address,
            Ip6Address("1234:5678:90ab:cdef::1"),
        )
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::1/128")._mask, Ip6Mask("/128")
        )
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::/32")._address,
            Ip6Address("1234:5678::"),
        )
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::/32")._mask, Ip6Mask("/32")
        )
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::/0")._address, Ip6Address("::")
        )
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::/0")._mask, Ip6Mask("/0")
        )
        self.assertRaises(
            Ip6NetworkFormatError, Ip6Network, "1234:5678:90ab:cdef:://64"
        )
        self.assertRaises(
            Ip6NetworkFormatError, Ip6Network, "1234:5678:90ab:cdef::/6432"
        )
        self.assertRaises(
            Ip6NetworkFormatError, Ip6Network, "1234:5678:90ab:cdef::"
        )

    def test___str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        self.assertEqual(
            str(Ip6Network("1234:5678:90ab:cdef::/64")),
            "1234:5678:90ab:cdef::/64",
        )

    def test___repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        self.assertEqual(
            repr(Ip6Network("1234:5678:90ab:cdef::/64")),
            "Ip6Network('1234:5678:90ab:cdef::/64')",
        )

    def test___eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        self.assertEqual(Ip6Network("::/0"), Ip6Network("::/0"))
        self.assertNotEqual(Ip6Network("::/0"), Ip6Network("::/128"))

    def test___hash__(self) -> None:
        """
        Test the '__hash__()' dunder.
        """
        self.assertEqual(
            hash(Ip6Network("1234:5678:90ab:cdef::/64")),
            hash(Ip6Address("1234:5678:90ab:cdef::")) ^ hash(Ip6Mask("/64")),
        )

    def test___contains__(self) -> None:
        """
        Test the '__contains__()' dunder.
        """
        self.assertIn(
            Ip6Address("2001::1234:5678:90ab:cdef"), Ip6Network("2001::/64")
        )
        self.assertNotIn(
            Ip6Address("2000::1234:5678:90ab:cdef"), Ip6Network("2001::/64")
        )
        self.assertNotIn(
            Ip6Address("2002::1234:5678:90ab:cdef"), Ip6Network("2001::/64")
        )

    def test_address(self) -> None:
        """
        Test the 'address' property.
        """
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::/64").address,
            Ip6Address("1234:5678:90ab:cdef::"),
        )

    def test_mask(self) -> None:
        """
        Test the 'mask' property.
        """
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::/64").mask, Ip6Mask("/64")
        )

    def test_last(self) -> None:
        """
        Test the 'last' property.
        """
        self.assertEqual(
            Ip6Network("1234:5678:90ab:cdef::/64").last,
            Ip6Address("1234:5678:90ab:cdef:ffff:ffff:ffff:ffff"),
        )

    def test_version(self) -> None:
        self.assertEqual(Ip6Network("1234:5678:90ab:cdef::/64").version, 6)


class TestIp6Host(TestCase):
    """
    Unit tests for 'Ip6Host' class.
    """

    def test___init__(self) -> None:
        """
        Test the constructor for 'Ip6Host' object.
        """
        self.assertEqual(
            Ip6Host("1234:5678:90ab:cdef::1/64")._address,
            Ip6Address("1234:5678:90ab:cdef::1"),
        )
        self.assertEqual(
            Ip6Host("1234:5678:90ab:cdef::1/64")._network,
            Ip6Network("1234:5678:90ab:cdef::/64"),
        )
        self.assertEqual(
            Ip6Host(Ip6Host("1234:5678:90ab:cdef::1/64"))._address,
            Ip6Address("1234:5678:90ab:cdef::1"),
        )
        self.assertEqual(
            Ip6Host(Ip6Host("1234:5678:90ab:cdef::1/64"))._network,
            Ip6Network("1234:5678:90ab:cdef::/64"),
        )
        self.assertEqual(
            Ip6Host(
                (Ip6Address("1234:5678:90ab:cdef::1"), Ip6Mask("/64"))
            )._address,
            Ip6Address("1234:5678:90ab:cdef::1"),
        )
        self.assertEqual(
            Ip6Host(
                (Ip6Address("1234:5678:90ab:cdef::1"), Ip6Mask("/64"))
            )._network,
            Ip6Network("1234:5678:90ab:cdef::/64"),
        )
        self.assertEqual(
            Ip6Host(
                (
                    Ip6Address("1234:5678:90ab:cdef::1"),
                    Ip6Network("1234:5678:90ab:cdef::0/64"),
                )
            )._address,
            Ip6Address("1234:5678:90ab:cdef::1"),
        )
        self.assertEqual(
            Ip6Host(
                (
                    Ip6Address("1234:5678:90ab:cdef::1"),
                    Ip6Network("1234:5678:90ab:cdef::0/64"),
                )
            )._network,
            Ip6Network("1234:5678:90ab:cdef::/64"),
        )
        self.assertRaises(
            Ip6HostFormatError, Ip6Host, "1234:5678:90ab:cdef::1//64"
        )
        self.assertRaises(Ip6HostFormatError, Ip6Host, "1234:5678:90ab:cdef::1")

    def test___str__(self) -> None:
        """
        Test the '__str__()' dunder.
        """
        self.assertEqual(
            str(Ip6Host("1234:5678:90ab:cdef::1/64")),
            "1234:5678:90ab:cdef::1/64",
        )

    def test___repr__(self) -> None:
        """
        Test the '__repr__()' dunder.
        """
        self.assertEqual(
            repr(Ip6Host("1234:5678:90ab:cdef::1/64")),
            "Ip6Host('1234:5678:90ab:cdef::1/64')",
        )

    def test___eq__(self) -> None:
        """
        Test the '__eq__()' dunder.
        """
        self.assertEqual(
            Ip6Host("1234:5678:90ab:cdef::1/64"),
            Ip6Host("1234:5678:90ab:cdef::1/64"),
        )
        self.assertNotEqual(
            Ip6Host("1234:5678:90ab:cdef::1/64"),
            Ip6Host("1234:5678:90ab:cdef::1/128"),
        )
        self.assertNotEqual(
            Ip6Host("1234:5678:90ab:cdef::1/64"), Ip6Host("::/64")
        )

    def test___hash__(self) -> None:
        """
        Test the '__hash__()' dunder.
        """
        self.assertEqual(
            hash(Ip6Host("1234:5678:90ab:cdef::1/64")),
            hash(Ip6Address("1234:5678:90ab:cdef::1"))
            ^ hash(Ip6Network("1234:5678:90ab:cdef::/64")),
        )

    def test_address(self) -> None:
        """
        Test the 'address' property.
        """
        self.assertEqual(
            Ip6Host("1234:5678:90ab:cdef::1/64").address,
            Ip6Address("1234:5678:90ab:cdef::1"),
        )

    def test_network(self) -> None:
        """
        Test the 'network' property.
        """
        self.assertEqual(
            Ip6Host("1234:5678:90ab:cdef::1/64").network,
            Ip6Network("1234:5678:90ab:cdef::/64"),
        )

    def test_version(self) -> None:
        """
        Test the 'version' property.
        """
        self.assertEqual(Ip6Host("::/128").version, 6)

    def test__gateway_getter__success(self) -> None:
        """
        Ensure that the 'gateway' property getter returns correct value.
        """

        gateway = Ip6Address("fe80::1")
        host = Ip6Host("2001::7/64")
        host._gateway = gateway

        self.assertEqual(host.gateway, gateway)

    def test__gateway_setter__success(self) -> None:
        """
        Ensure that the 'gateway' property setter sets the correct value.
        """

        gateway = Ip6Address("fe80::1")
        host = Ip6Host("2001::7/64")

        host.gateway = gateway

        self.assertIs(host._gateway, gateway)

    def test__gateway_setter__success__none(self) -> None:
        """
        Ensure that the 'gateway' property setter sets the None value.
        """

        host = Ip6Host("2001::7/64")

        host.gateway = None

        self.assertIsNone(host._gateway)

    def test__gateway_setter__error__not_lla(self) -> None:
        """
        Ensure that the 'gateway' property setter raises the 'Ip4HostGatewayError'
        exception when the provided gateway address is not LLA.
        """

        gateway = Ip6Address("2001::1")
        host = Ip6Host("2001::7/64")

        with self.assertRaises(Ip6HostGatewayError) as error:
            host.gateway = gateway

        # self.assertEqual(f"{error.exception}", f"{gateway}")

    def test_eui64(self) -> None:
        """
        Test the 'eui64' property.
        """

        self.assertEqual(
            Ip6Host.from_eui64(
                mac_address=MacAddress("01:02:03:04:05:06"),
                ip6_network=Ip6Network("1234:5678:90ab:cdef::/64"),
            ),
            Ip6Host("1234:5678:90ab:cdef:302:3ff:fe04:506/64"),
        )
