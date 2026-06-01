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
This module contains tests for the NetAddr package IPv6 address support class.

net_addr/tests/unit/test__ip6_address.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import (
    Ip4Address,
    Ip6Address,
    Ip6AddressFormatError,
    Ip6AddressSanityError,
    IpVersion,
    MacAddress,
)


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 address: :: (str)",
            "_args": [
                "::",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "::",
                "__repr__": "Ip6Address('::')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": True,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: :: (None)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "::",
                "__repr__": "Ip6Address('::')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": True,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ::1 (str)",
            "_args": [
                "::1",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "::1",
                "__repr__": "Ip6Address('::1')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                "__int__": 1,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": True,
                "is_multicast": False,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: 2000:: (str)",
            "_args": [
                "2000::",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "2000::",
                "__repr__": "Ip6Address('2000::')",
                "__bytes__": b"\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 42535295865117307932921825928971026432,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: 3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff (str)",
            "_args": [
                "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "__repr__": "Ip6Address('3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')",
                "__bytes__": b"\x3f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 85070591730234615865843651857942052863,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: fe80:: (str)",
            "_args": [
                "fe80::",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "fe80::",
                "__repr__": "Ip6Address('fe80::')",
                "__bytes__": b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 338288524927261089654018896841347694592,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": True,
                "is_loopback": False,
                "is_multicast": False,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff (str)",
            "_args": [
                "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "__repr__": "Ip6Address('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff')",
                "__bytes__": b"\xfe\xbf\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 338620831926207318622244848606417780735,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": True,
                "is_loopback": False,
                "is_multicast": False,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: fc00:: (str)",
            "_args": [
                "fc00::",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "fc00::",
                "__repr__": "Ip6Address('fc00::')",
                "__bytes__": b"\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 334965454937798799971759379190646833152,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": True,
            },
        },
        {
            "_description": "Test the IPv6 address: fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff (str)",
            "_args": [
                "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "__repr__": "Ip6Address('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')",
                "__bytes__": b"\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 337623910929368631717566993311207522303,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": True,
            },
        },
        {
            "_description": "Test the IPv6 address: ff00:: (str)",
            "_args": [
                "ff00::",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff00::",
                "__repr__": "Ip6Address('ff00::')",
                "__bytes__": b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 338953138925153547590470800371487866880,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::1 (str)",
            "_args": [
                "ff02::1",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1",
                "__repr__": "Ip6Address('ff02::1')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                "__int__": 338963523518870617245727861364146307073,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": True,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::2 (str)",
            "_args": [
                "ff02::2",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::2",
                "__repr__": "Ip6Address('ff02::2')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
                "__int__": 338963523518870617245727861364146307074,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": True,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::1:ff00:0 (str)",
            "_args": [
                "ff02::1:ff00:0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": True,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::1:ff00:0 (str uppercase)",
            "_args": [
                "FF02::1:FF00:0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": True,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::1:ff00:0 (Ip6Address)",
            "_args": [
                Ip6Address("ff02::1:ff00:0"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": True,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::1:ff00:0 (int)",
            "_args": [
                338963523518870617245727861372719464448,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": True,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::1:ff00:0 (bytes)",
            "_args": [
                b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": True,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::1:ff00:0 (bytearray)",
            "_args": [
                bytearray(b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": True,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::1:ff00:0 (memoryview)",
            "_args": [
                memoryview(b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": True,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ff02::1:ffff:ffff (str)",
            "_args": [
                "ff02::1:ffff:ffff",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ffff:ffff",
                "__repr__": "Ip6Address('ff02::1:ffff:ffff')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\xff\xff\xff",
                "__int__": 338963523518870617245727861372736241663,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": True,
                "is_private": False,
            },
        },
        {
            "_description": "Test the IPv6 address: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff (str)",
            "_args": [
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "__repr__": "Ip6Address('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 340282366920938463463374607431768211455,
                "version": IpVersion.IP6,
                "unspecified": Ip6Address(),
                "is_ip4": False,
                "is_ip6": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_multicast__all_nodes": False,
                "is_multicast__all_routers": False,
                "is_multicast__solicited_node": False,
                "is_private": False,
            },
        },
    ]
)
class TestNetAddrIp6Address(TestCase):
    """
    The NetAddr IPv6 address tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv6 address object with testcase arguments.
        """

        self._ip6_address = Ip6Address(*self._args, **self._kwargs)

    def test__net_addr__ip6_address__str(self) -> None:
        """
        Ensure the IPv6 address '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip6_address),
            self._results["__str__"],
        )

    def test__net_addr__ip6_address__repr(self) -> None:
        """
        Ensure the IPv6 address '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip6_address),
            self._results["__repr__"],
        )

    def test__net_addr__ip6_address__bytes(self) -> None:
        """
        Ensure the IPv6 address '__bytes__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._ip6_address),
            self._results["__bytes__"],
        )

    def test__net_addr__ip6_address__int(self) -> None:
        """
        Ensure the IPv6 address '__int__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(self._ip6_address),
            self._results["__int__"],
        )

    def test__net_addr__ip6_address__eq(self) -> None:
        """
        Ensure the IPv6 address '__eq__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._ip6_address == self._ip6_address,
            msg="An Ip6Address instance must compare equal to itself.",
        )

        self.assertTrue(
            self._ip6_address == Ip6Address(int(self._ip6_address)),
            msg="Ip6Address must compare equal to one reconstructed from its integer value.",
        )

        self.assertFalse(
            self._ip6_address == Ip6Address((int(self._ip6_address) + 1) & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF),
            msg="Ip6Address instances with different integer values must not compare equal.",
        )

        self.assertFalse(
            self._ip6_address == "not an IPv6 address",
            msg="Ip6Address must not compare equal to a foreign string value.",
        )

        self.assertFalse(
            self._ip6_address == None,  # noqa: E711
            msg="Ip6Address must not compare equal to None.",
        )

    def test__net_addr__ip6_address__version(self) -> None:
        """
        Ensure the IPv6 address 'version' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.version,
            self._results["version"],
        )

    def test__net_addr__ip6_address__unspecified(self) -> None:
        """
        Ensure the IPv6 address 'unspecified' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.unspecified,
            self._results["unspecified"],
        )

    def test__net_addr__ip6_address__is_ip4(self) -> None:
        """
        Ensure the IPv6 address 'is_ip4' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip6_address__is_ip6(self) -> None:
        """
        Ensure the IPv6 address 'is_ip6' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip6_address__is_unspecified(self) -> None:
        """
        Ensure the IPv6 address 'is_unspecified' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_unspecified,
            self._results["is_unspecified"],
        )

    def test__net_addr__ip6_address__is_unicast(self) -> None:
        """
        Ensure the IPv6 address 'is_unicast' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_unicast,
            self._results["is_unicast"],
        )

    def test__net_addr__ip6_address__is_global(self) -> None:
        """
        Ensure the IPv6 address 'is_global' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_global,
            self._results["is_global"],
        )

    def test__net_addr__ip6_address__is_link_local(self) -> None:
        """
        Ensure the IPv6 address 'is_link_local' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_link_local,
            self._results["is_link_local"],
        )

    def test__net_addr__ip6_address__is_loopback(self) -> None:
        """
        Ensure the IPv6 address 'is_loopback' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_loopback,
            self._results["is_loopback"],
        )

    def test__net_addr__ip6_address__is_multicast(self) -> None:
        """
        Ensure the IPv6 address 'is_multicast' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_multicast,
            self._results["is_multicast"],
        )

    def test__net_addr__ip6_address__is_multicast__all_nodes(self) -> None:
        """
        Ensure the IPv6 address 'is_multicast__all_nodes' property returns
        a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_multicast__all_nodes,
            self._results["is_multicast__all_nodes"],
        )

    def test__net_addr__ip6_address__is_multicast__all_routers(self) -> None:
        """
        Ensure the IPv6 address 'is_multicast__all_routers' property returns
        a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_multicast__all_routers,
            self._results["is_multicast__all_routers"],
        )

    def test__net_addr__ip6_address__is_multicast__solicited_node(self) -> None:
        """
        Ensure the IPv6 address 'is_multicast__solicited_node' property returns
        a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_multicast__solicited_node,
            self._results["is_multicast__solicited_node"],
        )

    def test__net_addr__ip6_address__is_private(self) -> None:
        """
        Ensure the IPv6 address 'is_private' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_address.is_private,
            self._results["is_private"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 address format: '2000::10000'",
            "_args": [
                "2000::10000",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": ("The IPv6 address format is invalid: '2000::10000'"),
            },
        },
        {
            "_description": "Test the IPv6 address format: '2000:::'",
            "_args": [
                "2000:::",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": ("The IPv6 address format is invalid: '2000:::'"),
            },
        },
        {
            "_description": "Test the IPv6 address format: '2000;:1'",
            "_args": [
                "2000;:1",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": ("The IPv6 address format is invalid: '2000;:1'"),
            },
        },
        {
            "_description": (
                "Test the IPv6 address format: " "b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"
            ),
            "_args": [
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": (
                    "The IPv6 address format is invalid: "
                    r"b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"
                ),
            },
        },
        {
            "_description": (
                "Test the IPv6 address format: "
                "b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"
            ),
            "_args": [
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": (
                    "The IPv6 address format is invalid: "
                    r"b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 address format: -1",
            "_args": [
                -1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": ("The IPv6 address format is invalid: -1"),
            },
        },
        {
            "_description": ("Test the IPv6 address format: 340282366920938463463374607431768211456"),
            "_args": [
                340282366920938463463374607431768211456,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": ("The IPv6 address format is invalid: 340282366920938463463374607431768211456"),
            },
        },
        {
            "_description": "Test the IPv6 address format: Ip4Address()",
            "_args": [
                Ip4Address(),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": "The IPv6 address format is invalid: Ip4Address('0.0.0.0')",
            },
        },
        {
            "_description": "Test the IPv6 address format: {}",
            "_args": [
                {},
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": "The IPv6 address format is invalid: {}",
            },
        },
        {
            "_description": "Test the IPv6 address format: 1.1",
            "_args": [
                1.1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": "The IPv6 address format is invalid: 1.1",
            },
        },
    ]
)
class TestNetAddrIp6AddressErrors(TestCase):
    """
    The NetAddr IPv6 address error tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip6_address__errors(self) -> None:
        """
        Ensure the IPv6 address raises an error on invalid input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip6Address(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


class TestNetAddrIp6AddressSemantics(TestCase):
    """
    The NetAddr IPv6 address semantic tests not tied to a parameterized matrix.
    """

    def test__net_addr__ip6_address__eq__cross_version(self) -> None:
        """
        Ensure an IPv6 address never compares equal to an IPv4 address
        even when they share the same integer value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            Ip6Address(0xC0A80101),
            Ip4Address(0xC0A80101),
            msg="Ip6Address must not compare equal to an Ip4Address of the same integer value.",
        )

    def test__net_addr__ip6_address__eq__foreign_types(self) -> None:
        """
        Ensure the IPv6 address is never equal to a value of a foreign type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        address = Ip6Address("2001:db8::1")

        self.assertFalse(
            address == "2001:db8::1",
            msg="Ip6Address must not compare equal to its string representation.",
        )
        self.assertFalse(
            address == int(address),
            msg="Ip6Address must not compare equal to its integer value.",
        )
        self.assertFalse(
            address == bytes(address),
            msg="Ip6Address must not compare equal to its bytes representation.",
        )

    def test__net_addr__ip6_address__ne(self) -> None:
        """
        Ensure the IPv6 address '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        address = Ip6Address("2001:db8::1")
        self.assertTrue(
            address != Ip6Address("2001:db8::2"),
            msg="Distinct Ip6Address values must be unequal.",
        )
        self.assertFalse(
            address != Ip6Address("2001:db8::1"),
            msg="Equal Ip6Address values must not be unequal.",
        )
        self.assertTrue(
            address != "2001:db8::1",
            msg="Ip6Address must be unequal to its string representation.",
        )


class TestNetAddrIp6AddressHashConsistency(TestCase):
    """
    The NetAddr IPv6 address hash consistency tests.
    """

    def test__net_addr__ip6_address__hash__distinct_instances(self) -> None:
        """
        Ensure two independently constructed equal addresses hash identically.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Address("ff02::1:ff00:0")
        b = Ip6Address(bytes(a))
        c = Ip6Address(int(a))
        d = Ip6Address("FF02::1:FF00:0")

        self.assertEqual(
            a,
            b,
            msg="Ip6Address built from string and bytes must compare equal.",
        )
        self.assertEqual(
            a,
            c,
            msg="Ip6Address built from string and integer must compare equal.",
        )
        self.assertEqual(
            a,
            d,
            msg="Ip6Address case must not affect equality.",
        )
        for other in (b, c, d):
            self.assertEqual(
                hash(a),
                hash(other),
                msg="Equal Ip6Address values must hash to the same value across constructor forms.",
            )

    def test__net_addr__ip6_address__usable_in_set(self) -> None:
        """
        Ensure equal IPv6 addresses collapse into a single element when used
        in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Address("2001:db8::1")
        b = Ip6Address(int(a))
        c = Ip6Address("2001:db8::2")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip6Address values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip6Address values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip6Address values as the same key.",
        )

    def test__net_addr__ip6_address__usable_in_dict(self) -> None:
        """
        Ensure equal IPv6 addresses refer to the same dict entry regardless
        of which constructor form was used to build the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Address("2001:db8::1")
        b = Ip6Address(bytes(a))

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip6Address must behave consistently as a dict key across input forms.",
        )


class TestNetAddrIp6AddressRoundtrip(TestCase):
    """
    The NetAddr IPv6 address roundtrip tests.
    """

    def test__net_addr__ip6_address__roundtrip__str(self) -> None:
        """
        Ensure 'Ip6Address(str(x))' yields an address equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in (
            "::",
            "::1",
            "2001:db8::1",
            "fe80::1",
            "ff02::1",
            "ff02::1:ff00:0",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ):
            with self.subTest(spec=spec):
                address = Ip6Address(spec)
                self.assertEqual(
                    Ip6Address(str(address)),
                    address,
                    msg=f"Roundtrip through str() must preserve address {spec!r}.",
                )

    def test__net_addr__ip6_address__roundtrip__bytes(self) -> None:
        """
        Ensure 'Ip6Address(bytes(x))' yields an address equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in (
            "::",
            "2001:db8::1",
            "ff02::1:ff00:0",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ):
            with self.subTest(spec=spec):
                address = Ip6Address(spec)
                self.assertEqual(
                    Ip6Address(bytes(address)),
                    address,
                    msg=f"Roundtrip through bytes() must preserve address {spec!r}.",
                )

    def test__net_addr__ip6_address__roundtrip__int(self) -> None:
        """
        Ensure 'Ip6Address(int(x))' yields an address equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in (
            "::",
            "2001:db8::1",
            "ff02::1:ff00:0",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ):
            with self.subTest(spec=spec):
                address = Ip6Address(spec)
                self.assertEqual(
                    Ip6Address(int(address)),
                    address,
                    msg=f"Roundtrip through int() must preserve address {spec!r}.",
                )


class TestNetAddrIp6AddressMulticastMac(TestCase):
    """
    The NetAddr IPv6 address 'multicast_mac' property tests.
    """

    def test__net_addr__ip6_address__multicast_mac__all_nodes(self) -> None:
        """
        Ensure multicast_mac maps ff02::1 to 33:33:00:00:00:01.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            Ip6Address("ff02::1").multicast_mac,
            MacAddress("33:33:00:00:00:01"),
            msg="ff02::1 must map to MAC 33:33:00:00:00:01.",
        )

    def test__net_addr__ip6_address__multicast_mac__solicited_node(self) -> None:
        """
        Ensure multicast_mac uses the low 32 bits of the IPv6 address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            Ip6Address("ff02::1:ff12:3456").multicast_mac,
            MacAddress("33:33:ff:12:34:56"),
            msg="Solicited-node multicast address must map to 33:33:ff:xx:xx:xx.",
        )

    def test__net_addr__ip6_address__multicast_mac__non_multicast_raises(self) -> None:
        """
        Ensure 'multicast_mac' raises Ip6AddressSanityError for a non-multicast address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(
            Ip6AddressSanityError,
            msg="multicast_mac must reject a non-multicast address.",
        ):
            _ = Ip6Address("2001:db8::1").multicast_mac


class TestNetAddrIp6AddressSolicitedNodeMulticast(TestCase):
    """
    The NetAddr IPv6 address 'solicited_node_multicast' property tests.
    """

    def test__net_addr__ip6_address__solicited_node_multicast__unicast(self) -> None:
        """
        Ensure the solicited-node multicast of a unicast address is
        ff02::1:ff<low-24-bits>.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            Ip6Address("2001:db8::1:2345:6789").solicited_node_multicast,
            Ip6Address("ff02::1:ff45:6789"),
            msg="Solicited-node multicast must combine ff02::1:ff00:0 with the low 24 bits.",
        )

    def test__net_addr__ip6_address__solicited_node_multicast__unspecified(self) -> None:
        """
        Ensure the unspecified address maps to ff02::1:ff00:0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            Ip6Address().solicited_node_multicast,
            Ip6Address("ff02::1:ff00:0"),
            msg="The unspecified address must map to ff02::1:ff00:0.",
        )

    def test__net_addr__ip6_address__solicited_node_multicast__multicast_raises(self) -> None:
        """
        Ensure 'solicited_node_multicast' rejects a multicast address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(
            Ip6AddressSanityError,
            msg="solicited_node_multicast must reject a multicast address.",
        ):
            _ = Ip6Address("ff02::1").solicited_node_multicast


class TestIp6AddressIsDocumentation(TestCase):
    """
    'Ip6Address.is_documentation' recognises the 2001:db8::/32
    (RFC 3849) and 3fff::/20 (RFC 9637) documentation prefixes.
    """

    def test__net_addr__ip6_address__is_documentation__match(self) -> None:
        """
        Ensure an address in 2001:db8::/32 reports
        is_documentation = True.

        Reference: RFC 3849 (IPv6 Address Prefix Reserved for Documentation).
        """

        self.assertTrue(
            Ip6Address("2001:db8::1").is_documentation,
            msg="2001:db8::1 must be recognised as documentation.",
        )

    def test__net_addr__ip6_address__is_documentation__boundary(self) -> None:
        """
        Ensure the upper boundary of 2001:db8::/32 reports
        is_documentation = True.

        Reference: RFC 3849 (IPv6 Address Prefix Reserved for Documentation).
        """

        self.assertTrue(
            Ip6Address("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff").is_documentation,
            msg="Last address in 2001:db8::/32 must be documentation.",
        )

    def test__net_addr__ip6_address__is_documentation__below(self) -> None:
        """
        Ensure addresses below the 2001:db8::/32 prefix report
        is_documentation = False.

        Reference: RFC 3849 (IPv6 Address Prefix Reserved for Documentation).
        """

        self.assertFalse(
            Ip6Address("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff").is_documentation,
            msg="2001:db7::/32 is not the documentation prefix.",
        )

    def test__net_addr__ip6_address__is_documentation__above(self) -> None:
        """
        Ensure addresses above the 2001:db8::/32 prefix report
        is_documentation = False.

        Reference: RFC 3849 (IPv6 Address Prefix Reserved for Documentation).
        """

        self.assertFalse(
            Ip6Address("2001:db9::1").is_documentation,
            msg="2001:db9::/32 is not the documentation prefix.",
        )

    def test__net_addr__ip6_address__is_documentation__global_unrelated(self) -> None:
        """
        Ensure a regular global IPv6 address reports
        is_documentation = False.

        Reference: RFC 3849 (IPv6 Address Prefix Reserved for Documentation).
        """

        self.assertFalse(
            Ip6Address("2606:4700:4700::1111").is_documentation,
            msg="Cloudflare public DNS is not documentation.",
        )

    def test__net_addr__ip6_address__is_documentation__rfc9637_match(self) -> None:
        """
        Ensure an address in 3fff::/20 reports
        is_documentation = True.

        Reference: RFC 9637 (Expanding the IPv6 Documentation Prefix).
        """

        self.assertTrue(
            Ip6Address("3fff::1").is_documentation,
            msg="3fff::1 must be recognised as documentation.",
        )

    def test__net_addr__ip6_address__is_documentation__rfc9637_boundary(self) -> None:
        """
        Ensure the upper boundary of 3fff::/20 reports
        is_documentation = True.

        Reference: RFC 9637 (Expanding the IPv6 Documentation Prefix).
        """

        self.assertTrue(
            Ip6Address("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff").is_documentation,
            msg="Last address in 3fff::/20 must be documentation.",
        )

    def test__net_addr__ip6_address__is_documentation__rfc9637_above(self) -> None:
        """
        Ensure addresses just above 3fff::/20 report
        is_documentation = False.

        Reference: RFC 9637 (Expanding the IPv6 Documentation Prefix).
        """

        self.assertFalse(
            Ip6Address("3fff:1000::1").is_documentation,
            msg="3fff:1000::/20 is outside the documentation prefix.",
        )


class TestIp6AddressIsReserved(TestCase):
    """
    'Ip6Address.is_reserved' aggregates the IPv6 special-purpose
    prefixes from the IANA registry (RFC 8190 / RFC 6890) that
    are not already covered by is_loopback / is_link_local /
    is_multicast / is_private / is_unspecified.
    """

    def test__net_addr__ip6_address__is_reserved__discard(self) -> None:
        """
        Ensure 100::/64 (Discard-Only Address Block) reports
        is_reserved = True.

        Reference: RFC 6666 (A Discard Prefix for IPv6).
        """

        self.assertTrue(
            Ip6Address("100::1").is_reserved,
            msg="100::/64 discard prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__documentation(self) -> None:
        """
        Ensure 2001:db8::/32 (documentation) reports
        is_reserved = True.

        Reference: RFC 3849 (IPv6 Address Prefix Reserved for Documentation).
        """

        self.assertTrue(
            Ip6Address("2001:db8::1").is_reserved,
            msg="2001:db8::/32 documentation prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__benchmark(self) -> None:
        """
        Ensure 2001:2::/48 (benchmarking) reports
        is_reserved = True.

        Reference: RFC 5180 (IPv6 Benchmarking Methodology).
        """

        self.assertTrue(
            Ip6Address("2001:2::1").is_reserved,
            msg="2001:2::/48 benchmarking prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__ipv4_mapped(self) -> None:
        """
        Ensure ::ffff:0:0/96 (IPv4-mapped) reports
        is_reserved = True.

        Reference: RFC 4291 §2.5.5.2 (IPv4-mapped IPv6 address).
        """

        self.assertTrue(
            Ip6Address("::ffff:192.0.2.1").is_reserved,
            msg="::ffff:0:0/96 IPv4-mapped prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__nat64_well_known(self) -> None:
        """
        Ensure 64:ff9b::/96 (IPv4-IPv6 translation well-known
        prefix) reports is_reserved = True.

        Reference: RFC 6052 §2.1 (Well-Known Prefix).
        """

        self.assertTrue(
            Ip6Address("64:ff9b::192.0.2.1").is_reserved,
            msg="64:ff9b::/96 NAT64 well-known prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__nat64_local(self) -> None:
        """
        Ensure 64:ff9b:1::/48 (local-use IPv4-IPv6 translation
        prefix) reports is_reserved = True.

        Reference: RFC 8215 (Local-Use IPv4/IPv6 Translation Prefix).
        """

        self.assertTrue(
            Ip6Address("64:ff9b:1::1").is_reserved,
            msg="64:ff9b:1::/48 NAT64 local-use prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__dummy(self) -> None:
        """
        Ensure 100:0:0:1::/64 (Dummy IPv6 Prefix) reports
        is_reserved = True.

        Reference: RFC 9780 (A Dummy IPv6 Prefix).
        """

        self.assertTrue(
            Ip6Address("100:0:0:1::1").is_reserved,
            msg="100:0:0:1::/64 dummy prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__ietf_protocol(self) -> None:
        """
        Ensure the 2001::/23 IETF Protocol Assignments umbrella
        reports is_reserved = True (it subsumes TEREDO, AMT,
        AS112-v6, ORCHIDv2, the DET prefix and the anycast
        single-address assignments).

        Reference: RFC 2928 (Initial IPv6 Sub-TLA ID Assignments).
        """

        self.assertTrue(
            Ip6Address("2001::1").is_reserved,
            msg="2001::/23 IETF Protocol Assignments must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__sixtofour(self) -> None:
        """
        Ensure 2002::/16 (6to4) reports is_reserved = True.

        Reference: RFC 3056 §2 (6to4 prefix).
        """

        self.assertTrue(
            Ip6Address("2002::1").is_reserved,
            msg="2002::/16 6to4 prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__as112(self) -> None:
        """
        Ensure 2620:4f:8000::/48 (Direct Delegation AS112
        Service) reports is_reserved = True.

        Reference: RFC 7534 (AS112 Nameserver Operations).
        """

        self.assertTrue(
            Ip6Address("2620:4f:8000::1").is_reserved,
            msg="2620:4f:8000::/48 AS112 prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__documentation_rfc9637(self) -> None:
        """
        Ensure 3fff::/20 (second documentation prefix) reports
        is_reserved = True.

        Reference: RFC 9637 (Expanding the IPv6 Documentation Prefix).
        """

        self.assertTrue(
            Ip6Address("3fff::1").is_reserved,
            msg="3fff::/20 documentation prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__srv6(self) -> None:
        """
        Ensure 5f00::/16 (Segment Routing SRv6 SIDs) reports
        is_reserved = True.

        Reference: RFC 9602 (Segment Routing over IPv6 SIDs block).
        """

        self.assertTrue(
            Ip6Address("5f00::1").is_reserved,
            msg="5f00::/16 SRv6 SID prefix must be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__global_not_reserved(self) -> None:
        """
        Ensure a regular global unicast address reports
        is_reserved = False.

        Reference: RFC 8190 (Updates to Special-Purpose IP Address Registries).
        """

        self.assertFalse(
            Ip6Address("2606:4700:4700::1111").is_reserved,
            msg="Regular global unicast must not be reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__link_local_not_reserved(self) -> None:
        """
        Ensure a link-local address reports is_reserved = False
        (link-local has its own predicate).

        Reference: RFC 8190 (the registry includes fe80::/10 but
        PyTCP's is_link_local owns it).
        """

        self.assertFalse(
            Ip6Address("fe80::1").is_reserved,
            msg="Link-local addresses are covered by is_link_local, not is_reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__ula_not_reserved(self) -> None:
        """
        Ensure a ULA address reports is_reserved = False (ULA
        has its own predicate via is_private).

        Reference: RFC 4193 (the registry includes fc00::/7 but
        PyTCP's is_private owns it).
        """

        self.assertFalse(
            Ip6Address("fd00::1").is_reserved,
            msg="ULA addresses are covered by is_private, not is_reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__loopback_not_reserved(self) -> None:
        """
        Ensure ::1 reports is_reserved = False (loopback has
        its own predicate).

        Reference: RFC 8190 (the registry includes ::1/128 but
        PyTCP's is_loopback owns it).
        """

        self.assertFalse(
            Ip6Address("::1").is_reserved,
            msg="Loopback is covered by is_loopback, not is_reserved.",
        )

    def test__net_addr__ip6_address__is_reserved__unspecified_not_reserved(self) -> None:
        """
        Ensure :: reports is_reserved = False (unspecified has
        its own predicate).

        Reference: RFC 8190 (the registry includes ::/128 but
        PyTCP's is_unspecified owns it).
        """

        self.assertFalse(
            Ip6Address("::").is_reserved,
            msg="Unspecified is covered by is_unspecified, not is_reserved.",
        )


class TestNetAddrIp6AddressOrdering(TestCase):
    """
    The NetAddr IPv6 address ordering tests.
    """

    def test__net_addr__ip6_address__ordering(self) -> None:
        """
        Ensure IPv6 addresses are totally ordered by their
        integer value (sortable, min/max, all comparisons).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Address("2001:db8::1")
        b = Ip6Address("2001:db8::2")
        c = Ip6Address("2001:db8:1::")

        self.assertEqual(
            sorted([c, b, a]),
            [a, b, c],
            msg="Ip6Address must sort ascending by integer value.",
        )
        self.assertEqual(min(c, b, a), a, msg="min() must return the lowest Ip6Address.")
        self.assertEqual(max(c, b, a), c, msg="max() must return the highest Ip6Address.")
        self.assertTrue(a < b <= b < c, msg="Chained Ip6Address comparisons must hold.")
        self.assertFalse(a < a, msg="An Ip6Address must not be strictly less than itself.")
        self.assertTrue(a >= a, msg="An Ip6Address must be >= itself.")

    def test__net_addr__ip6_address__ordering__scope_aware(self) -> None:
        """
        Ensure ordering folds the RFC 4007 scope identifier into
        the sort key consistently with equality, so same-address
        different-scope values stay totally ordered (exactly one
        of <, ==, > holds) and an unscoped value sorts before a
        scoped one.

        Reference: RFC 4007 (scoped-address zone identifier).
        """

        plain = Ip6Address("fe80::1")
        eth0 = Ip6Address("fe80::1%eth0")
        eth1 = Ip6Address("fe80::1%eth1")

        for lo, hi in ((plain, eth0), (eth0, eth1)):
            self.assertNotEqual(lo, hi, msg="Different-scope values must be unequal.")
            self.assertTrue(
                (lo < hi) and not (hi < lo) and (lo <= hi) and (hi >= lo),
                msg=f"Scope-differing values must be totally ordered: {lo!r} < {hi!r}.",
            )

        self.assertEqual(
            sorted([eth1, plain, eth0]),
            [plain, eth0, eth1],
            msg="Ip6Address must sort by (address, scope_id), unscoped first.",
        )

    def test__net_addr__ip6_address__ordering__cross_version_raises(self) -> None:
        """
        Ensure every ordering operator (<, <=, >, >=) against an
        IPv4 address raises TypeError (mixed-version ordering is
        undefined); each comparison returns NotImplemented so
        Python falls back to the TypeError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip6 = Ip6Address("2001:db8::1")
        ip4 = Ip4Address("10.0.0.1")
        with self.assertRaises(TypeError, msg="Ip6Address < Ip4Address must raise TypeError."):
            _ = ip6 < ip4
        with self.assertRaises(TypeError, msg="Ip6Address <= Ip4Address must raise TypeError."):
            _ = ip6 <= ip4
        with self.assertRaises(TypeError, msg="Ip6Address > Ip4Address must raise TypeError."):
            _ = ip6 > ip4
        with self.assertRaises(TypeError, msg="Ip6Address >= Ip4Address must raise TypeError."):
            _ = ip6 >= ip4


class TestNetAddrIp6AddressArithmetic(TestCase):
    """
    The NetAddr IPv6 address arithmetic tests.
    """

    def test__net_addr__ip6_address__arithmetic(self) -> None:
        """
        Ensure 'address + int' / 'address - int' yield the
        offset IPv6 address (stdlib-exact: int operand only).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Address("2001:db8::10")
        self.assertEqual(a + 1, Ip6Address("2001:db8::11"), msg="address + 1 must advance by one.")
        self.assertEqual(a - 1, Ip6Address("2001:db8::f"), msg="address - 1 must retreat by one.")
        self.assertEqual(a + 0, a, msg="address + 0 must be unchanged.")
        self.assertIsInstance(a + 1, Ip6Address, msg="Arithmetic must return an Ip6Address.")

    def test__net_addr__ip6_address__arithmetic__non_int_operand_raises(self) -> None:
        """
        Ensure 'address + x' / 'address - x' with a non-integer
        operand raises TypeError (both operators return
        NotImplemented so Python falls back to the TypeError).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Address("2001:db8::10")
        with self.assertRaises(TypeError, msg="Ip6Address + non-int must raise TypeError."):
            _ = a + "1"
        with self.assertRaises(TypeError, msg="Ip6Address - non-int must raise TypeError."):
            _ = a - "1"

    def test__net_addr__ip6_address__arithmetic__preserves_scope(self) -> None:
        """
        Ensure 'address + int' / 'address - int' carry the RFC
        4007 zone identifier onto the result, consistently with
        equality / hashing / ordering; an unscoped operand stays
        unscoped.

        Reference: RFC 4007 (scoped-address zone identifier).
        """

        scoped = Ip6Address("fe80::10%eth0")
        self.assertEqual((scoped + 1).scope_id, "eth0", msg="address + int must keep the zone.")
        self.assertEqual((scoped - 1).scope_id, "eth0", msg="address - int must keep the zone.")
        self.assertEqual(
            scoped + 1,
            Ip6Address("fe80::11%eth0"),
            msg="The offset scoped address must equal the literal scoped form.",
        )
        self.assertIsNone(
            (Ip6Address("fe80::10") + 1).scope_id,
            msg="An unscoped operand must yield an unscoped result.",
        )

    def test__net_addr__ip6_address__arithmetic__drops_scope_when_result_not_zoneable(self) -> None:
        """
        Ensure 'address + int' / 'address - int' drop the RFC
        4007 zone when the offset carries the address out of a
        zoneable scope, so a scoped Ip6Address is always one the
        constructor would accept and equality / hashing stay
        consistent with the plainly-constructed form.

        Reference: RFC 4007 §6 (zone meaningful only for non-global scopes).
        """

        # fe80::1%eth0 (link-local, zoneable) + 2**120 -> ff80::1
        # (multicast, scop nibble 0 -> not zoneable).
        crossed_up = Ip6Address("fe80::1%eth0") + (1 << 120)
        self.assertIsNone(
            crossed_up.scope_id,
            msg="A result outside any zoneable scope must not carry a zone.",
        )
        self.assertEqual(
            crossed_up,
            Ip6Address("ff80::1"),
            msg="The zone-dropped result must equal the plainly-constructed address.",
        )
        self.assertEqual(
            hash(crossed_up),
            hash(Ip6Address("ff80::1")),
            msg="The zone-dropped result must hash as the plainly-constructed address.",
        )

        # fe80:: (link-local, zoneable) - 1 -> fe7f:ffff:...:ffff
        # (no longer link-local/loopback/multicast -> not zoneable).
        crossed_down = Ip6Address("fe80::%eth0") - 1
        self.assertIsNone(
            crossed_down.scope_id,
            msg="Retreating out of the zoneable range must drop the zone.",
        )
        self.assertEqual(
            int(crossed_down),
            int(Ip6Address("fe80::")) - 1,
            msg="Dropping the zone must not perturb the 128 address bits.",
        )

    def test__net_addr__ip6_address__arithmetic__overflow_raises(self) -> None:
        """
        Ensure arithmetic past the IPv6 address space raises the
        net_addr sanity error (an out-of-range operation result,
        not a malformed literal) with an operation-naming message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip6AddressSanityError) as over:
            _ = Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") + 1
        self.assertEqual(
            str(over.exception),
            "Ip6Address offset out of range: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff + 1",
            msg="Overflow past the max IPv6 address must raise Ip6AddressSanityError naming the operation.",
        )

        with self.assertRaises(Ip6AddressSanityError) as under:
            _ = Ip6Address("::") - 1
        self.assertEqual(
            str(under.exception),
            "Ip6Address offset out of range: :: - 1",
            msg="Underflow below :: must raise Ip6AddressSanityError naming the operation.",
        )

    def test__net_addr__ip6_address__arithmetic__non_int_raises(self) -> None:
        """
        Ensure address arithmetic with a non-int operand raises
        TypeError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError, msg="address + address must raise TypeError."):
            _ = Ip6Address("2001:db8::1") + Ip6Address("2001:db8::2")


class TestNetAddrIp6AddressReversePointer(TestCase):
    """
    The NetAddr IPv6 address reverse-pointer tests.
    """

    def test__net_addr__ip6_address__reverse_pointer(self) -> None:
        """
        Ensure 'reverse_pointer' yields the reversed-nibble
        ip6.arpa PTR name (all 32 nibbles).

        Reference: RFC 3596 (DNS Extensions for IPv6 — ip6.arpa).
        """

        for address, expected in [
            (
                "2001:db8::1",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            ),
            (
                "::1",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            ),
            (
                "::",
                "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
            ),
            (
                "fe80::1",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
            ),
        ]:
            with self.subTest(address=address):
                self.assertEqual(
                    Ip6Address(address).reverse_pointer,
                    expected,
                    msg=f"Unexpected reverse_pointer for {address}.",
                )


class TestNetAddrIp6AddressFormatExploded(TestCase):
    """
    The NetAddr IPv6 address 'ex' / default text-format tests.
    """

    def test__net_addr__ip6_address__format_exploded(self) -> None:
        """
        Ensure the 'ex' format code yields the fully expanded
        eight-group four-hex-digit form with no zero
        compression.

        Reference: RFC 4291 §2.2 (IPv6 text representation, form 1).
        """

        for address, expected in [
            ("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"),
            ("::1", "0000:0000:0000:0000:0000:0000:0000:0001"),
            ("::", "0000:0000:0000:0000:0000:0000:0000:0000"),
            ("fe80::1", "fe80:0000:0000:0000:0000:0000:0000:0001"),
            ("2001:db8:1:2:3:4:5:6", "2001:0db8:0001:0002:0003:0004:0005:0006"),
        ]:
            with self.subTest(address=address):
                self.assertEqual(
                    format(Ip6Address(address), "ex"),
                    expected,
                    msg=f"Unexpected 'ex' form for {address}.",
                )

    def test__net_addr__ip6_address__format_default_compressed(self) -> None:
        """
        Ensure the default text form yields the canonical
        zero-compressed representation (identical to str()).

        Reference: RFC 5952 §4 (canonical IPv6 text representation).
        """

        for address, expected in [
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("::1", "::1"),
            ("::", "::"),
            ("fe80::1", "fe80::1"),
            ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2:3:4:5:6"),
        ]:
            with self.subTest(address=address):
                obj = Ip6Address(address)
                self.assertEqual(
                    f"{obj}",
                    expected,
                    msg=f"Unexpected default form for {address}.",
                )
                self.assertEqual(
                    f"{obj}",
                    str(obj),
                    msg="default form must equal str() for an IPv6 address.",
                )


class TestNetAddrIp6AddressMaxPrefixlen(TestCase):
    """
    The NetAddr IPv6 address max_prefixlen tests.
    """

    def test__net_addr__ip6_address__max_prefixlen(self) -> None:
        """
        Ensure 'max_prefixlen' is 128 for any IPv6 address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ["::", "2001:db8::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]:
            with self.subTest(address=value):
                self.assertEqual(
                    Ip6Address(value).max_prefixlen,
                    128,
                    msg=f"max_prefixlen must be 128 for {value}.",
                )


class TestNetAddrIp6AddressFormat(TestCase):
    """
    The NetAddr IPv6 address __format__ tests.
    """

    def test__net_addr__ip6_address__format(self) -> None:
        """
        Ensure '__format__' treats the address as a 128-bit
        zero-padded integer for s/b/x/X (with '#' / '_'), and
        also supports the modifier-free 'd' (plain decimal) and
        'n' (locale-aware decimal) codes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Address("::1")
        for spec, expected in [
            ("", "::1"),
            ("s", "::1"),
            ("x", "00000000000000000000000000000001"),
            ("d", "1"),
            ("b", "0" * 127 + "1"),
            ("#x", "0x00000000000000000000000000000001"),
        ]:
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(a, spec),
                    expected,
                    msg=f"format(Ip6Address, {spec!r}) must be {expected!r}.",
                )

    def test__net_addr__ip6_address__format__decimal_codes_delegate_to_int(self) -> None:
        """
        Ensure the 'd' (plain decimal) and 'n' (locale-aware
        decimal) codes render the address exactly as the stdlib
        integer formatter renders its integer value, so 'n'
        honours the caller's LC_NUMERIC and 'd' is always the
        plain value, independent of the ambient locale.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Address("2001:db8::1")
        value = int(a)
        for code in ("d", "n"):
            with self.subTest(code=code):
                self.assertEqual(
                    format(a, code),
                    format(value, code),
                    msg=f"format(Ip6Address, {code!r}) must equal format(int(addr), {code!r}).",
                )
        self.assertEqual(
            format(a, "d"),
            str(value),
            msg="The 'd' code must be the plain decimal value with no padding or grouping.",
        )

    def test__net_addr__ip6_address__format__string_specs_delegate_to_str(self) -> None:
        """
        Ensure a spec carrying no recognised presentation code
        is treated as a string-presentation spec and renders
        the canonical text exactly as str() would (fill /
        align / width / precision), with no trailing 's'
        required.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Address("2001:db8::1")
        for spec in (">30", "<30", "^30", "30", ".11", ">30.11", "*>30"):
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(a, spec),
                    format(str(a), spec),
                    msg=f"format(Ip6Address, {spec!r}) must match format(str(addr), {spec!r}).",
                )

    def test__net_addr__ip6_address__format__unknown_code_raises(self) -> None:
        """
        Ensure an unsupported format code raises
        Ip6AddressSanityError and preserves the underlying
        stdlib ValueError as '__cause__'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip6AddressSanityError) as ctx:
            format(Ip6Address("2001:db8::1"), "q")
        self.assertIsInstance(
            ctx.exception.__cause__,
            ValueError,
            msg="The unknown-code SanityError must chain the stdlib ValueError as __cause__.",
        )


class TestNetAddrIp6AddressTransitional(TestCase):
    """
    The NetAddr IPv6 transitional-address extractor tests.
    """

    def test__net_addr__ip6_address__ipv4_mapped(self) -> None:
        """
        Ensure 'ipv4_mapped' extracts the embedded IPv4 address
        from an ::ffff:0:0/96 address and is None otherwise.

        Reference: RFC 4291 (IPv4-mapped IPv6 address, §2.5.5.2).
        """

        self.assertEqual(
            Ip6Address("::ffff:192.0.2.1").ipv4_mapped,
            Ip4Address("192.0.2.1"),
            msg="ipv4_mapped must extract the embedded IPv4 address.",
        )
        self.assertIsNone(
            Ip6Address("2001:db8::1").ipv4_mapped,
            msg="ipv4_mapped must be None for a non-mapped address.",
        )

    def test__net_addr__ip6_address__is_ipv4_mapped_true_for_prefix(self) -> None:
        """
        Ensure 'is_ipv4_mapped' returns True for any address
        inside the ::ffff:0:0/96 prefix — the predicate the
        dual-stack code paths key off.

        Reference: RFC 4291 §2.5.5.2 (IPv4-mapped IPv6 prefix).
        """

        self.assertTrue(
            Ip6Address("::ffff:192.0.2.1").is_ipv4_mapped,
            msg="is_ipv4_mapped must be True for an ::ffff:0:0/96 address.",
        )
        self.assertTrue(
            Ip6Address("::ffff:0.0.0.0").is_ipv4_mapped,
            msg="is_ipv4_mapped must be True for the prefix's all-zeros embedded IPv4.",
        )
        self.assertTrue(
            Ip6Address("::ffff:255.255.255.255").is_ipv4_mapped,
            msg="is_ipv4_mapped must be True for the prefix's all-ones embedded IPv4.",
        )

    def test__net_addr__ip6_address__is_ipv4_mapped_false_for_non_mapped(self) -> None:
        """
        Ensure 'is_ipv4_mapped' returns False for canonical
        non-mapped IPv6 addresses (loopback, ULA, link-local,
        global), the ::0 unspecified address, and ::1.

        Reference: RFC 4291 §2.5.5.2 (predicate scope).
        """

        for address in (
            Ip6Address("::"),
            Ip6Address("::1"),
            Ip6Address("2001:db8::1"),
            Ip6Address("fe80::1"),
            Ip6Address("fc00::1"),
            Ip6Address("ff02::1"),
        ):
            with self.subTest(address=str(address)):
                self.assertFalse(
                    address.is_ipv4_mapped,
                    msg=f"is_ipv4_mapped must be False for {address}.",
                )

    def test__net_addr__ip6_address__from_ipv4_mapped_constructs_mapped(self) -> None:
        """
        Ensure 'Ip6Address.from_ipv4_mapped(ip4)' produces the
        canonical ::ffff:0:0/96 mapped form embedding 'ip4' as
        the low 32 bits — the explicit IPv4 → IPv6 conversion
        the dual-stack listener-fork uses on accept().

        Reference: RFC 4291 §2.5.5.2 (IPv4-mapped construction).
        """

        mapped = Ip6Address.from_ipv4_mapped(Ip4Address("192.0.2.1"))
        self.assertEqual(
            mapped,
            Ip6Address("::ffff:192.0.2.1"),
            msg="from_ipv4_mapped must produce the ::ffff:0:0/96 form.",
        )
        self.assertTrue(
            mapped.is_ipv4_mapped,
            msg="The constructed address must satisfy is_ipv4_mapped.",
        )

    def test__net_addr__ip6_address__from_ipv4_mapped_round_trip(self) -> None:
        """
        Ensure 'from_ipv4_mapped' and 'ipv4_mapped' round-trip:
        the embedded IPv4 of a freshly-mapped address equals
        the original — invariant that pins the conversion's
        bit-layout exactness.

        Reference: RFC 4291 §2.5.5.2 (IPv4-mapped bit layout).
        """

        original = Ip4Address("10.20.30.40")
        round_tripped = Ip6Address.from_ipv4_mapped(original).ipv4_mapped
        self.assertEqual(
            round_tripped,
            original,
            msg="from_ipv4_mapped → ipv4_mapped must round-trip the original IPv4.",
        )

    def test__net_addr__ip6_address__sixtofour(self) -> None:
        """
        Ensure 'sixtofour' extracts the embedded IPv4 address
        from a 2002::/16 address and is None otherwise.

        Reference: RFC 3056 (6to4, §2).
        """

        self.assertEqual(
            Ip6Address("2002:c000:0201::").sixtofour,
            Ip4Address("192.0.2.1"),
            msg="sixtofour must extract the embedded IPv4 address.",
        )
        self.assertIsNone(
            Ip6Address("2001:db8::1").sixtofour,
            msg="sixtofour must be None for a non-6to4 address.",
        )

    def test__net_addr__ip6_address__teredo(self) -> None:
        """
        Ensure 'teredo' returns the (server, client) IPv4 pair
        for a 2001:0000::/32 address and is None otherwise.

        Reference: RFC 4380 (Teredo, §4).
        """

        self.assertEqual(
            Ip6Address("2001:0000:4136:e378:8000:63bf:3fff:fdd2").teredo,
            (Ip4Address("65.54.227.120"), Ip4Address("192.0.2.45")),
            msg="teredo must return the (server, client) IPv4 pair.",
        )
        self.assertIsNone(
            Ip6Address("2001:db8::1").teredo,
            msg="teredo must be None for a non-Teredo address.",
        )


class TestNetAddrIp6AddressScopeId(TestCase):
    """
    The NetAddr IPv6 address RFC 4007 scope-identifier tests.
    """

    def test__net_addr__ip6_address__scope_id__parse_and_roundtrip(self) -> None:
        """
        Ensure a '%zone' suffix is parsed into 'scope_id' and
        round-trips through str(); the address bits are
        unaffected.

        Reference: RFC 4007 (IPv6 Scoped Address Architecture).
        """

        a = Ip6Address("fe80::1%eth0")
        self.assertEqual(a.scope_id, "eth0", msg="scope_id must be the text after '%'.")
        self.assertEqual(str(a), "fe80::1%eth0", msg="str() must round-trip the zone.")
        self.assertEqual(int(a), int(Ip6Address("fe80::1")), msg="The zone is not part of the 128 bits.")
        self.assertEqual(bytes(a), bytes(Ip6Address("fe80::1")), msg="packed bytes ignore the zone.")
        self.assertEqual(Ip6Address("fe80::1%1").scope_id, "1", msg="A numeric zone is kept as a string.")

    def test__net_addr__ip6_address__scope_id__identity(self) -> None:
        """
        Ensure the scope identifier participates in equality
        and hashing.

        Reference: RFC 4007 (IPv6 Scoped Address Architecture).
        """

        self.assertEqual(Ip6Address("fe80::1%eth0"), Ip6Address("fe80::1%eth0"), msg="Same zone must be equal.")
        self.assertNotEqual(Ip6Address("fe80::1%eth0"), Ip6Address("fe80::1"), msg="Zoned != unzoned.")
        self.assertNotEqual(Ip6Address("fe80::1%eth0"), Ip6Address("fe80::1%eth1"), msg="Different zones must differ.")
        self.assertEqual(
            hash(Ip6Address("fe80::1%eth0")),
            hash(Ip6Address("fe80::1%eth0")),
            msg="Equal zoned addresses must hash equal.",
        )
        self.assertEqual(
            Ip6Address(Ip6Address("fe80::1%eth0")).scope_id,
            "eth0",
            msg="Copy-construction must preserve the zone.",
        )

    def test__net_addr__ip6_address__scope_id__unzoned_unchanged(self) -> None:
        """
        Ensure an address with no zone has scope_id None and
        compares / hashes exactly as before (single-interface
        behaviour is provably unchanged).

        Reference: RFC 4007 (IPv6 Scoped Address Architecture).
        """

        self.assertIsNone(Ip6Address("fe80::1").scope_id, msg="An unzoned address must have scope_id None.")
        self.assertIsNone(Ip6Address(1).scope_id, msg="An int-built address has no zone.")
        self.assertEqual(Ip6Address("fe80::1"), Ip6Address("fe80::1"), msg="Unzoned equality unchanged.")
        self.assertEqual(
            hash(Ip6Address("fe80::1")),
            hash(Ip6Address("fe80::1")),
            msg="Unzoned hashing is stable.",
        )

    def test__net_addr__ip6_address__scope_id__global_scope_rejected(self) -> None:
        """
        Ensure a '%zone' suffix is rejected on an address whose
        scope is global (a zone index is meaningless there), and
        accepted on the non-global scopes where it is meaningful
        — link-local unicast, loopback, and non-global multicast.

        Reference: RFC 4007 §6 (zone indices meaningful only for
        non-global scopes).
        """

        for bad in ["2001:db8::1%eth0", "ff0e::1%eth0", "::%eth0"]:
            with self.subTest(value=bad):
                with self.assertRaises(
                    Ip6AddressFormatError,
                    msg=f"A zone on the global-scope address {bad!r} must raise.",
                ):
                    Ip6Address(bad)

        for good in ["fe80::1%eth0", "::1%lo", "ff02::1%eth0", "ff05::1%eth0"]:
            with self.subTest(value=good):
                self.assertEqual(
                    Ip6Address(good).scope_id,
                    good.split("%", 1)[1],
                    msg=f"A zone on the non-global-scope address {good!r} must be accepted.",
                )

    def test__net_addr__ip6_address__scope_id__invalid_raises(self) -> None:
        """
        Ensure an empty or multi-'%' zone raises
        'Ip6AddressFormatError'.

        Reference: RFC 4007 (IPv6 Scoped Address Architecture).
        """

        for bad in ["fe80::1%", "fe80::1%a%b", "%eth0"]:
            with self.subTest(value=bad):
                with self.assertRaises(Ip6AddressFormatError, msg=f"{bad!r} must raise."):
                    Ip6Address(bad)


class TestNetAddrIp6AddressWhitespace(TestCase):
    """
    The NetAddr Ip6Address surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip6_address__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("2001:db8::7",):
            expected = Ip6Address(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip6Address(wrapped),
                        expected,
                        msg=f"Ip6Address({wrapped!r}) must equal Ip6Address({value!r}).",
                    )
