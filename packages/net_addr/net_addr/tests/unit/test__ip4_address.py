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
This module contains tests for the NetAddr package IPv4 address support class.

net_addr/tests/unit/test__ip4_address.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip4AddressSanityError,
    Ip6Address,
    IpVersion,
    MacAddress,
)
from net_addr.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 address: 0.0.0.0 (str)",
            "_args": [
                "0.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Address('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": True,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 0.0.0.0 (None)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Address('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": True,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 0.0.0.1 (str)",
            "_args": [
                "0.0.0.1",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.1",
                "__repr__": "Ip4Address('0.0.0.1')",
                "__bytes__": b"\x00\x00\x00\x01",
                "__int__": 1,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": True,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 0.255.255.255 (str)",
            "_args": [
                "0.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.255.255.255",
                "__repr__": "Ip4Address('0.255.255.255')",
                "__bytes__": b"\x00\xff\xff\xff",
                "__int__": 16777215,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": True,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 1.0.0.0 (str)",
            "_args": [
                "1.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "1.0.0.0",
                "__repr__": "Ip4Address('1.0.0.0')",
                "__bytes__": b"\x01\x00\x00\x00",
                "__int__": 16777216,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 9.255.255.255 (str)",
            "_args": [
                "9.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "9.255.255.255",
                "__repr__": "Ip4Address('9.255.255.255')",
                "__bytes__": b"\x09\xff\xff\xff",
                "__int__": 167772159,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 10.0.0.0 (str)",
            "_args": [
                "10.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "10.0.0.0",
                "__repr__": "Ip4Address('10.0.0.0')",
                "__bytes__": b"\x0a\x00\x00\x00",
                "__int__": 167772160,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 10.255.255.255 (str)",
            "_args": [
                "10.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "10.255.255.255",
                "__repr__": "Ip4Address('10.255.255.255')",
                "__bytes__": b"\x0a\xff\xff\xff",
                "__int__": 184549375,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 11.0.0.0 (str)",
            "_args": [
                "11.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "11.0.0.0",
                "__repr__": "Ip4Address('11.0.0.0')",
                "__bytes__": b"\x0b\x00\x00\x00",
                "__int__": 184549376,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 126.255.255.255 (str)",
            "_args": [
                "126.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "126.255.255.255",
                "__repr__": "Ip4Address('126.255.255.255')",
                "__bytes__": b"\x7e\xff\xff\xff",
                "__int__": 2130706431,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 127.0.0.0 (str)",
            "_args": [
                "127.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "127.0.0.0",
                "__repr__": "Ip4Address('127.0.0.0')",
                "__bytes__": b"\x7f\x00\x00\x00",
                "__int__": 2130706432,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": True,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 127.255.255.255 (str)",
            "_args": [
                "127.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "127.255.255.255",
                "__repr__": "Ip4Address('127.255.255.255')",
                "__bytes__": b"\x7f\xff\xff\xff",
                "__int__": 2147483647,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": True,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 128.0.0.0 (str)",
            "_args": [
                "128.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "128.0.0.0",
                "__repr__": "Ip4Address('128.0.0.0')",
                "__bytes__": b"\x80\x00\x00\x00",
                "__int__": 2147483648,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 169.253.255.255 (str)",
            "_args": [
                "169.253.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "169.253.255.255",
                "__repr__": "Ip4Address('169.253.255.255')",
                "__bytes__": b"\xa9\xfd\xff\xff",
                "__int__": 2851995647,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 169.254.0.0 (str)",
            "_args": [
                "169.254.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "169.254.0.0",
                "__repr__": "Ip4Address('169.254.0.0')",
                "__bytes__": b"\xa9\xfe\x00\x00",
                "__int__": 2851995648,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": True,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 169.254.255.255 (str)",
            "_args": [
                "169.254.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "169.254.255.255",
                "__repr__": "Ip4Address('169.254.255.255')",
                "__bytes__": b"\xa9\xfe\xff\xff",
                "__int__": 2852061183,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": True,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 169.255.0.0 (str)",
            "_args": [
                "169.255.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "169.255.0.0",
                "__repr__": "Ip4Address('169.255.0.0')",
                "__bytes__": b"\xa9\xff\x00\x00",
                "__int__": 2852061184,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 170.0.0.0 (str)",
            "_args": [
                "170.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "170.0.0.0",
                "__repr__": "Ip4Address('170.0.0.0')",
                "__bytes__": b"\xaa\x00\x00\x00",
                "__int__": 2852126720,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 172.15.255.255 (str)",
            "_args": [
                "172.15.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.15.255.255",
                "__repr__": "Ip4Address('172.15.255.255')",
                "__bytes__": b"\xac\x0f\xff\xff",
                "__int__": 2886729727,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 172.16.0.0 (str)",
            "_args": [
                "172.16.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.16.0.0",
                "__repr__": "Ip4Address('172.16.0.0')",
                "__bytes__": b"\xac\x10\x00\x00",
                "__int__": 2886729728,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 172.31.255.255 (str)",
            "_args": [
                "172.31.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.31.255.255",
                "__repr__": "Ip4Address('172.31.255.255')",
                "__bytes__": b"\xac\x1f\xff\xff",
                "__int__": 2887778303,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 172.32.0.0 (str)",
            "_args": [
                "172.32.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.32.0.0",
                "__repr__": "Ip4Address('172.32.0.0')",
                "__bytes__": b"\xac\x20\x00\x00",
                "__int__": 2887778304,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 191.255.255.255 (str)",
            "_args": [
                "191.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "191.255.255.255",
                "__repr__": "Ip4Address('191.255.255.255')",
                "__bytes__": b"\xbf\xff\xff\xff",
                "__int__": 3221225471,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.0.0.0 (str)",
            "_args": [
                "192.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.0.0.0",
                "__repr__": "Ip4Address('192.0.0.0')",
                "__bytes__": b"\xc0\x00\x00\x00",
                "__int__": 3221225472,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 0 (int, unspecified boundary)",
            "_args": [
                0,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Address('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": True,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 4294967295 (int, limited broadcast boundary)",
            "_args": [
                4294967295,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "255.255.255.255",
                "__repr__": "Ip4Address('255.255.255.255')",
                "__bytes__": b"\xff\xff\xff\xff",
                "__int__": 4294967295,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": True,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.167.255.255 (str)",
            "_args": [
                "192.167.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.167.255.255",
                "__repr__": "Ip4Address('192.167.255.255')",
                "__bytes__": b"\xc0\xa7\xff\xff",
                "__int__": 3232235519,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.0.0 (str)",
            "_args": [
                "192.168.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.0.0",
                "__repr__": "Ip4Address('192.168.0.0')",
                "__bytes__": b"\xc0\xa8\x00\x00",
                "__int__": 3232235520,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (str)",
            "_args": [
                "192.168.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (Ip4Address)",
            "_args": [
                Ip4Address("192.168.255.255"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (int)",
            "_args": [
                3232301055,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (bytes)",
            "_args": [
                b"\xc0\xa8\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (bytearray)",
            "_args": [
                bytearray(b"\xc0\xa8\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (memoryview)",
            "_args": [
                memoryview(b"\xc0\xa8\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.169.0.0 (str)",
            "_args": [
                "192.169.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.169.0.0",
                "__repr__": "Ip4Address('192.169.0.0')",
                "__bytes__": b"\xc0\xa9\x00\x00",
                "__int__": 3232301056,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 223.255.255.255 (str)",
            "_args": [
                "223.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "223.255.255.255",
                "__repr__": "Ip4Address('223.255.255.255')",
                "__bytes__": b"\xdf\xff\xff\xff",
                "__int__": 3758096383,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 224.0.0.0 (str)",
            "_args": [
                "224.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "224.0.0.0",
                "__repr__": "Ip4Address('224.0.0.0')",
                "__bytes__": b"\xe0\x00\x00\x00",
                "__int__": 3758096384,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 239.255.255.255 (str)",
            "_args": ["239.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "239.255.255.255",
                "__repr__": "Ip4Address('239.255.255.255')",
                "__bytes__": b"\xef\xff\xff\xff",
                "__int__": 4026531839,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 240.0.0.0 (str)",
            "_args": [
                "240.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "240.0.0.0",
                "__repr__": "Ip4Address('240.0.0.0')",
                "__bytes__": b"\xf0\x00\x00\x00",
                "__int__": 4026531840,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": True,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 255.255.255.254 (str)",
            "_args": [
                "255.255.255.254",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "255.255.255.254",
                "__repr__": "Ip4Address('255.255.255.254')",
                "__bytes__": b"\xff\xff\xff\xfe",
                "__int__": 4294967294,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": True,
                "is_invalid": False,
                "is_limited_broadcast": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 255.255.255.255 (str)",
            "_args": [
                "255.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "255.255.255.255",
                "__repr__": "Ip4Address('255.255.255.255')",
                "__bytes__": b"\xff\xff\xff\xff",
                "__int__": 4294967295,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": True,
            },
        },
    ]
)
class TestNetAddrIp4Address(TestCase):
    """
    The NetAddr IPv4 address tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the IPv4 address object with testcase arguments.
        """

        self._ip4_address = Ip4Address(*self._args, **self._kwargs)

    def test__net_addr__ip4_address__str(self) -> None:
        """
        Ensure the IPv4 address '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip4_address),
            self._results["__str__"],
        )

    def test__net_addr__ip4_address__repr(self) -> None:
        """
        Ensure the IPv4 address '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip4_address),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_address__bytes(self) -> None:
        """
        Ensure the IPv4 address '__bytes__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._ip4_address),
            self._results["__bytes__"],
        )

    def test__net_addr__ip4_address__buffer(self) -> None:
        """
        Ensure the IPv4 address '__buffer__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(memoryview(self._ip4_address)),
            self._results["__bytes__"],
        )

    def test__net_addr__ip4_address__int(self) -> None:
        """
        Ensure the IPv4 address '__int__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            int(self._ip4_address),
            self._results["__int__"],
        )

    def test__net_addr__ip4_address__version(self) -> None:
        """
        Ensure the IPv4 address 'version' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.version,
            self._results["version"],
        )

    def test__net_addr__ip4_address__unspecified(self) -> None:
        """
        Ensure the IPv4 address 'unspecified' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.unspecified,
            self._results["unspecified"],
        )

    def test__net_addr__ip4_address__is_ip4(self) -> None:
        """
        Ensure the IPv4 address 'is_ip4' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_address__is_ip6(self) -> None:
        """
        Ensure the IPv4 address 'is_ip6' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_address__is_unspecified(self) -> None:
        """
        Ensure the IPv4 address 'is_unspecified' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_unspecified,
            self._results["is_unspecified"],
        )

    def test__net_addr__ip4_address__is_unicast(self) -> None:
        """
        Ensure the IPv4 address 'is_unicast' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_unicast,
            self._results["is_unicast"],
        )

    def test__net_addr__ip4_address__is_global(self) -> None:
        """
        Ensure the IPv4 address 'is_global' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_global,
            self._results["is_global"],
        )

    def test__net_addr__ip4_address__is_link_local(self) -> None:
        """
        Ensure the IPv4 address 'is_link_local' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_link_local,
            self._results["is_link_local"],
        )

    def test__net_addr__ip4_address__is_loopback(self) -> None:
        """
        Ensure the IPv4 address 'is_loopback' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_loopback,
            self._results["is_loopback"],
        )

    def test__net_addr__ip4_address__is_multicast(self) -> None:
        """
        Ensure the IPv4 address 'is_multicast' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_multicast,
            self._results["is_multicast"],
        )

    def test__net_addr__ip4_address__is_private(self) -> None:
        """
        Ensure the IPv4 address 'is_private' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_private,
            self._results["is_private"],
        )

    def test__net_addr__ip4_address__is_reserved(self) -> None:
        """
        Ensure the IPv4 address 'is_reserved' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_reserved,
            self._results["is_reserved"],
        )

    def test__net_addr__ip4_address__is_invalid(self) -> None:
        """
        Ensure the IPv4 address 'is_invalid' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_invalid,
            self._results["is_invalid"],
        )

    def test__net_addr__ip4_address__is_limited_broadcast(self) -> None:
        """
        Ensure the IPv4 address 'is_limited_broadcast' property returns
        a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.is_limited_broadcast,
            self._results["is_limited_broadcast"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 address format: '10.10.10.256'",
            "_args": [
                "10.10.10.256",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: '10.10.10.256'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: '1.2.3' (too few octets)",
            "_args": [
                "1.2.3",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '1.2.3'",
            },
        },
        {
            "_description": "Test the IPv4 address format: '1.2.3.4.5' (too many octets)",
            "_args": [
                "1.2.3.4.5",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '1.2.3.4.5'",
            },
        },
        {
            "_description": "Test the IPv4 address format: '300.300.300.300'",
            "_args": [
                "300.300.300.300",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '300.300.300.300'",
            },
        },
        {
            "_description": "Test the IPv4 address format: '10.10..10'",
            "_args": [
                "10.10..10",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: '10.10..10'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: '10.10.10,10'",
            "_args": [
                "10.10.10,10",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: '10.10.10,10'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: ''",
            "_args": [
                "",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: ''",
            },
        },
        {
            "_description": "Test the IPv4 address format: b'\\xff\\xff\\xff'",
            "_args": [
                b"\xff\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (r"The IPv4 address format is invalid: b'\xff\xff\xff'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: b'\\xff\\xff\\xff\\xff\\xff'",
            "_args": [
                b"\xff\xff\xff\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (r"The IPv4 address format is invalid: b'\xff\xff\xff\xff\xff'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: bytearray(b'\\xff\\xff\\xff')",
            "_args": [
                bytearray(b"\xff\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: bytearray(b'\\xff\\xff\\xff')",
            },
        },
        {
            "_description": "Test the IPv4 address format: bytearray(b'\\xff\\xff\\xff\\xff\\xff')",
            "_args": [
                bytearray(b"\xff\xff\xff\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: bytearray(b'\\xff\\xff\\xff\\xff\\xff')",
            },
        },
        {
            "_description": "Test the IPv4 address format: memoryview(b'\\xff\\xff\\xff')",
            "_args": [
                memoryview(b"\xff\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: <memory at 0x",
            },
        },
        {
            "_description": "Test the IPv4 address format: -1",
            "_args": [
                -1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: -1"),
            },
        },
        {
            "_description": "Test the IPv4 address format: 4294967296",
            "_args": [
                4294967296,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: 4294967296"),
            },
        },
        {
            "_description": "Test the IPv4 address format: Ip6Address()",
            "_args": [
                Ip6Address(),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: Ip6Address('::')",
            },
        },
        {
            "_description": "Test the IPv4 address format: {}",
            "_args": [
                {},
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: {}",
            },
        },
        {
            "_description": "Test the IPv4 address format: 1.1",
            "_args": [
                1.1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: 1.1",
            },
        },
        {
            "_description": "Test the IPv4 address format: '1.2.3.010' (octal octet)",
            "_args": [
                "1.2.3.010",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '1.2.3.010'",
            },
        },
        {
            "_description": "Test the IPv4 address format: '01.02.03.04' (leading zeros)",
            "_args": [
                "01.02.03.04",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '01.02.03.04'",
            },
        },
        {
            "_description": "Test the IPv4 address format: '1.2.3.04' (leading-zero octet)",
            "_args": [
                "1.2.3.04",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '1.2.3.04'",
            },
        },
        {
            "_description": "Test the IPv4 address format: '1.2.3.0x4' (hex octet)",
            "_args": [
                "1.2.3.0x4",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '1.2.3.0x4'",
            },
        },
    ]
)
class TestNetAddrIp4AddressErrors(TestCase):
    """
    The NetAddr IPv4 address error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_address__errors(self) -> None:
        """
        Ensure the IPv4 address raises an error on invalid input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Address(*self._args, **self._kwargs)

        self.assertTrue(
            str(error.exception).startswith(self._results["error_message"]),
            msg=(
                f"Expected exception message to start with "
                f"{self._results['error_message']!r}, got {str(error.exception)!r}."
            ),
        )


@parameterized_class(
    [
        {
            "_description": "Test multicast_mac for 224.0.0.0",
            "_args": ["224.0.0.0"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:00:00:00"),
            },
        },
        {
            "_description": "Test multicast_mac for 224.0.0.1",
            "_args": ["224.0.0.1"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:00:00:01"),
            },
        },
        {
            "_description": "Test multicast_mac for 239.255.255.255",
            "_args": ["239.255.255.255"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:7f:ff:ff"),
            },
        },
        {
            "_description": "Test multicast_mac masking collision: 224.128.0.1 shares MAC with 224.0.0.1",
            "_args": ["224.128.0.1"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:00:00:01"),
            },
        },
        {
            "_description": "Test multicast_mac masking collision: 239.128.0.1 shares MAC with 224.0.0.1",
            "_args": ["239.128.0.1"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:00:00:01"),
            },
        },
    ]
)
class TestNetAddrIp4AddressMulticastMac(TestCase):
    """
    The NetAddr IPv4 address multicast MAC tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the IPv4 address object with testcase arguments.
        """

        self._ip4_address = Ip4Address(*self._args, **self._kwargs)

    def test__net_addr__ip4_address__multicast_mac(self) -> None:
        """
        Ensure the IPv4 address 'multicast_mac' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_address.multicast_mac,
            self._results["multicast_mac"],
        )


class TestNetAddrIp4AddressMulticastMacError(TestCase):
    """
    The NetAddr IPv4 address multicast MAC assertion error test.
    """

    def test__net_addr__ip4_address__multicast_mac__error(self) -> None:
        """
        Ensure 'multicast_mac' raises Ip4AddressSanityError with the
        expected message when called on a non-multicast address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip4AddressSanityError) as error:
            _ = Ip4Address("192.168.1.1").multicast_mac

        self.assertEqual(
            str(error.exception),
            "The IPv4 address must be a multicast address to get a multicast " "MAC address. Got: 192.168.1.1",
        )


class TestNetAddrIp4AddressEquality(TestCase):
    """
    The NetAddr IPv4 address equality tests across value and type boundaries.
    """

    def test__net_addr__ip4_address__eq__identity(self) -> None:
        """
        Ensure the IPv4 address equals itself.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        address = Ip4Address("192.168.1.1")
        self.assertTrue(
            address == address,
            msg="An Ip4Address instance must compare equal to itself.",
        )

    def test__net_addr__ip4_address__eq__same_value(self) -> None:
        """
        Ensure two IPv4 addresses with the same underlying value are equal
        regardless of which constructor form was used.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            Ip4Address("192.168.1.1"),
            Ip4Address(b"\xc0\xa8\x01\x01"),
            msg="Ip4Address built from string and from bytes must compare equal.",
        )
        self.assertEqual(
            Ip4Address("192.168.1.1"),
            Ip4Address(3232235777),
            msg="Ip4Address built from string and from int must compare equal.",
        )

    def test__net_addr__ip4_address__eq__different_value(self) -> None:
        """
        Ensure two IPv4 addresses with different values are not equal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            Ip4Address("192.168.1.1"),
            Ip4Address("192.168.1.2"),
            msg="Ip4Address instances with different values must not compare equal.",
        )

    def test__net_addr__ip4_address__eq__foreign_types(self) -> None:
        """
        Ensure the IPv4 address is never equal to a value of a foreign type,
        even when the underlying integer/bytes would match.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        address = Ip4Address("192.168.1.1")

        self.assertFalse(
            address == "192.168.1.1",
            msg="Ip4Address must not compare equal to its string representation.",
        )
        self.assertFalse(
            address == int(address),
            msg="Ip4Address must not compare equal to its integer representation.",
        )
        self.assertFalse(
            address == bytes(address),
            msg="Ip4Address must not compare equal to its bytes representation.",
        )
        self.assertFalse(
            address == None,  # noqa: E711
            msg="Ip4Address must not compare equal to None.",
        )
        self.assertFalse(
            address == Ip6Address(),
            msg="Ip4Address must not compare equal to an Ip6Address.",
        )
        self.assertFalse(
            address == MacAddress(),
            msg="Ip4Address must not compare equal to a MacAddress.",
        )

    def test__net_addr__ip4_address__ne(self) -> None:
        """
        Ensure the IPv4 address '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        address = Ip4Address("192.168.1.1")
        self.assertTrue(
            address != Ip4Address("192.168.1.2"),
            msg="Ip4Address instances with different values must be unequal.",
        )
        self.assertFalse(
            address != Ip4Address("192.168.1.1"),
            msg="Ip4Address instances with the same value must not be unequal.",
        )
        self.assertTrue(
            address != "192.168.1.1",
            msg="Ip4Address must be unequal to its string representation.",
        )


class TestNetAddrIp4AddressHashConsistency(TestCase):
    """
    The NetAddr IPv4 address hash and container usability tests.
    """

    def test__net_addr__ip4_address__hash__equal_addresses_hash_equal(self) -> None:
        """
        Ensure equal IPv4 addresses built from different input forms produce
        identical hash values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from_str = Ip4Address("192.168.1.1")
        from_bytes = Ip4Address(b"\xc0\xa8\x01\x01")
        from_int = Ip4Address(3232235777)
        from_bytearray = Ip4Address(bytearray(b"\xc0\xa8\x01\x01"))
        from_memoryview = Ip4Address(memoryview(b"\xc0\xa8\x01\x01"))
        from_copy = Ip4Address(from_str)

        self.assertEqual(
            hash(from_str),
            hash(from_bytes),
            msg="Equal Ip4Address values (str, bytes) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_str),
            hash(from_int),
            msg="Equal Ip4Address values (str, int) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_str),
            hash(from_bytearray),
            msg="Equal Ip4Address values (str, bytearray) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_str),
            hash(from_memoryview),
            msg="Equal Ip4Address values (str, memoryview) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_str),
            hash(from_copy),
            msg="Ip4Address copied from another Ip4Address must preserve its hash.",
        )

    def test__net_addr__ip4_address__usable_in_set(self) -> None:
        """
        Ensure equal IPv4 addresses collapse into a single element when used
        in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Address("192.168.1.1")
        b = Ip4Address(b"\xc0\xa8\x01\x01")
        c = Ip4Address("192.168.1.2")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip4Address values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip4Address values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip4Address values as the same key.",
        )

    def test__net_addr__ip4_address__usable_in_dict(self) -> None:
        """
        Ensure equal IPv4 addresses refer to the same dict entry regardless
        of which constructor form was used to build the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Address("192.168.1.1")
        b = Ip4Address(b"\xc0\xa8\x01\x01")

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip4Address must behave consistently as a dict key across input forms.",
        )


class TestNetAddrIp4AddressRoundtrip(TestCase):
    """
    The NetAddr IPv4 address serialization roundtrip tests.
    """

    def test__net_addr__ip4_address__roundtrip__str(self) -> None:
        """
        Ensure 'Ip4Address(str(x))' yields an address equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("0.0.0.0", "127.0.0.1", "192.168.1.1", "255.255.255.255"):
            with self.subTest(value=value):
                address = Ip4Address(value)
                self.assertEqual(
                    Ip4Address(str(address)),
                    address,
                    msg=f"Roundtrip through str() must preserve address {value!r}.",
                )

    def test__net_addr__ip4_address__roundtrip__int(self) -> None:
        """
        Ensure 'Ip4Address(int(x))' yields an address equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in (0, 1, 2130706433, 3232235777, 4294967295):
            with self.subTest(value=value):
                address = Ip4Address(value)
                self.assertEqual(
                    Ip4Address(int(address)),
                    address,
                    msg=f"Roundtrip through int() must preserve address {value}.",
                )

    def test__net_addr__ip4_address__roundtrip__bytes(self) -> None:
        """
        Ensure 'Ip4Address(bytes(x))' yields an address equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in (
            b"\x00\x00\x00\x00",
            b"\x7f\x00\x00\x01",
            b"\xc0\xa8\x01\x01",
            b"\xff\xff\xff\xff",
        ):
            with self.subTest(value=value):
                address = Ip4Address(value)
                self.assertEqual(
                    Ip4Address(bytes(address)),
                    address,
                    msg=f"Roundtrip through bytes() must preserve address {value!r}.",
                )

    def test__net_addr__ip4_address__roundtrip__copy(self) -> None:
        """
        Ensure 'Ip4Address(x)' where 'x' is an Ip4Address yields an address
        equal to the source.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = Ip4Address("192.168.1.1")
        clone = Ip4Address(source)

        self.assertEqual(
            clone,
            source,
            msg="Ip4Address copied from another Ip4Address must compare equal to the source.",
        )
        self.assertEqual(
            int(clone),
            int(source),
            msg="Ip4Address copied from another Ip4Address must preserve the integer value.",
        )


class TestNetAddrIp4AddressOrdering(TestCase):
    """
    The NetAddr IPv4 address ordering tests.
    """

    def test__net_addr__ip4_address__ordering(self) -> None:
        """
        Ensure IPv4 addresses are totally ordered by their
        integer value (sortable, min/max, all comparisons).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Address("10.0.0.1")
        b = Ip4Address("10.0.0.2")
        c = Ip4Address("192.168.1.1")

        self.assertEqual(
            sorted([c, a, b]),
            [a, b, c],
            msg="Ip4Address must sort ascending by integer value.",
        )
        self.assertEqual(min(c, a, b), a, msg="min() must return the lowest Ip4Address.")
        self.assertEqual(max(c, a, b), c, msg="max() must return the highest Ip4Address.")
        for left, op, right, expected in [
            (a, "<", b, True),
            (b, "<", a, False),
            (a, "<=", a, True),
            (a, "<", a, False),
            (c, ">", a, True),
            (a, ">=", a, True),
        ]:
            with self.subTest(case=f"{left} {op} {right}"):
                got = {
                    "<": left < right,
                    "<=": left <= right,
                    ">": left > right,
                    ">=": left >= right,
                }[op]
                self.assertEqual(got, expected, msg=f"{left} {op} {right} must be {expected}.")

    def test__net_addr__ip4_address__ordering__cross_version_raises(self) -> None:
        """
        Ensure ordering an IPv4 address against an IPv6 address
        raises TypeError (mixed-version ordering is undefined).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError, msg="Ip4Address < Ip6Address must raise TypeError."):
            _ = Ip4Address("10.0.0.1") < Ip6Address("2001:db8::1")


class TestNetAddrIp4AddressArithmetic(TestCase):
    """
    The NetAddr IPv4 address arithmetic tests.
    """

    def test__net_addr__ip4_address__arithmetic(self) -> None:
        """
        Ensure 'address + int' / 'address - int' yield the
        offset IPv4 address (stdlib-exact: int operand only).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Address("10.0.0.10")
        self.assertEqual(a + 1, Ip4Address("10.0.0.11"), msg="address + 1 must advance by one.")
        self.assertEqual(a - 1, Ip4Address("10.0.0.9"), msg="address - 1 must retreat by one.")
        self.assertEqual(a + 0, a, msg="address + 0 must be unchanged.")
        self.assertEqual(a + 256, Ip4Address("10.0.1.10"), msg="address + 256 must carry across octets.")
        self.assertIsInstance(a + 1, Ip4Address, msg="Arithmetic must return an Ip4Address.")

    def test__net_addr__ip4_address__arithmetic__overflow_raises(self) -> None:
        """
        Ensure arithmetic past the IPv4 address space raises the
        net_addr sanity error (an out-of-range operation result,
        not a malformed literal) with an operation-naming message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip4AddressSanityError) as over:
            _ = Ip4Address("255.255.255.255") + 1
        self.assertEqual(
            str(over.exception),
            "Ip4Address offset out of range: 255.255.255.255 + 1",
            msg="Overflow past 255.255.255.255 must raise Ip4AddressSanityError naming the operation.",
        )

        with self.assertRaises(Ip4AddressSanityError) as under:
            _ = Ip4Address("0.0.0.0") - 1
        self.assertEqual(
            str(under.exception),
            "Ip4Address offset out of range: 0.0.0.0 - 1",
            msg="Underflow below 0.0.0.0 must raise Ip4AddressSanityError naming the operation.",
        )

    def test__net_addr__ip4_address__arithmetic__non_int_raises(self) -> None:
        """
        Ensure address arithmetic with a non-int operand raises
        TypeError (no address+address, no string operand).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError, msg="address + address must raise TypeError."):
            _ = Ip4Address("10.0.0.1") + Ip4Address("10.0.0.2")
        with self.assertRaises(TypeError, msg="address + str must raise TypeError."):
            _ = Ip4Address("10.0.0.1") + "1"


class TestNetAddrIp4AddressReversePointer(TestCase):
    """
    The NetAddr IPv4 address reverse-pointer tests.
    """

    def test__net_addr__ip4_address__reverse_pointer(self) -> None:
        """
        Ensure 'reverse_pointer' yields the reversed-octet
        in-addr.arpa PTR name.

        Reference: RFC 1035 (Domain Names — in-addr.arpa).
        """

        for address, expected in [
            ("192.0.2.1", "1.2.0.192.in-addr.arpa"),
            ("8.8.8.8", "8.8.8.8.in-addr.arpa"),
            ("0.0.0.0", "0.0.0.0.in-addr.arpa"),
            ("255.255.255.255", "255.255.255.255.in-addr.arpa"),
        ]:
            with self.subTest(address=address):
                self.assertEqual(
                    Ip4Address(address).reverse_pointer,
                    expected,
                    msg=f"Unexpected reverse_pointer for {address}.",
                )


class TestNetAddrIp4AddressFormatExploded(TestCase):
    """
    The NetAddr IPv4 address 'ex' / default text-format tests.
    """

    def test__net_addr__ip4_address__format_exploded(self) -> None:
        """
        Ensure the 'ex' format code and the default text form
        both yield the dotted-decimal string for IPv4 (no zero
        compression exists for IPv4).

        Reference: RFC 791 §2.3 (IPv4 dotted-decimal notation).
        """

        for address in ["192.0.2.1", "0.0.0.0", "255.255.255.255", "10.20.30.40"]:
            with self.subTest(address=address):
                obj = Ip4Address(address)
                self.assertEqual(format(obj, "ex"), address, msg=f"'ex' must be {address}.")
                self.assertEqual(f"{obj}", address, msg=f"default form must be {address}.")
                self.assertEqual(format(obj, "ex"), str(obj), msg="'ex' must equal str() for IPv4.")


class TestNetAddrIp4AddressMaxPrefixlen(TestCase):
    """
    The NetAddr IPv4 address max_prefixlen tests.
    """

    def test__net_addr__ip4_address__max_prefixlen(self) -> None:
        """
        Ensure 'max_prefixlen' is 32 for any IPv4 address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ["0.0.0.0", "192.0.2.1", "255.255.255.255"]:
            with self.subTest(address=value):
                self.assertEqual(
                    Ip4Address(value).max_prefixlen,
                    32,
                    msg=f"max_prefixlen must be 32 for {value}.",
                )


class TestNetAddrIp4AddressFormat(TestCase):
    """
    The NetAddr IPv4 address __format__ tests.
    """

    def test__net_addr__ip4_address__format(self) -> None:
        """
        Ensure '__format__' supports the documented spec set:
        s/b/x/X with the '#' and '_' modifiers (the address as
        a 32-bit zero-padded integer), plus the modifier-free
        'd' (plain decimal) and 'n' (locale-aware decimal)
        codes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Address("1.2.3.4")
        for spec, expected in [
            ("", "1.2.3.4"),
            ("s", "1.2.3.4"),
            (">10s", "   1.2.3.4"),
            ("b", "00000001000000100000001100000100"),
            ("x", "01020304"),
            ("X", "01020304"),
            ("d", "16909060"),
            ("#x", "0x01020304"),
            ("_b", "0000_0001_0000_0010_0000_0011_0000_0100"),
            ("#_x", "0x0102_0304"),
        ]:
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(a, spec),
                    expected,
                    msg=f"format(Ip4Address, {spec!r}) must be {expected!r}.",
                )

    def test__net_addr__ip4_address__format__invalid_spec_raises(self) -> None:
        """
        Ensure an unsupported format code raises
        Ip4AddressSanityError and preserves the underlying
        stdlib ValueError as '__cause__'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip4AddressSanityError) as ctx:
            format(Ip4Address("1.2.3.4"), "q")
        self.assertIsInstance(
            ctx.exception.__cause__,
            ValueError,
            msg="The unknown-code SanityError must chain the stdlib ValueError as __cause__.",
        )

    def test__net_addr__ip4_address__format__string_specs_delegate_to_str(self) -> None:
        """
        Ensure a spec carrying no recognised presentation code
        is treated as a string-presentation spec and renders
        the canonical text exactly as str() would (fill /
        align / width / precision), with no trailing 's'
        required.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Address("1.2.3.4")
        for spec in (">20", "<20", "^20", "20", ".7", ">20.7", "*>20"):
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(a, spec),
                    format(str(a), spec),
                    msg=f"format(Ip4Address, {spec!r}) must match format(str(addr), {spec!r}).",
                )

    def test__net_addr__ip4_address__format__decimal_codes_delegate_to_int(self) -> None:
        """
        Ensure the 'd' (plain decimal) and 'n' (locale-aware
        decimal) codes render the address exactly as the stdlib
        integer formatter renders its integer value, so 'n'
        honours the caller's LC_NUMERIC and 'd' is always the
        plain value, independent of the ambient locale.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Address("1.2.3.4")
        value = int(a)
        for code in ("d", "n"):
            with self.subTest(code=code):
                self.assertEqual(
                    format(a, code),
                    format(value, code),
                    msg=f"format(Ip4Address, {code!r}) must equal format(int(addr), {code!r}).",
                )
        self.assertEqual(
            format(a, "d"),
            str(value),
            msg="The 'd' code must be the plain decimal value with no padding or grouping.",
        )


class TestNetAddrIp4AddressWhitespace(TestCase):
    """
    The NetAddr Ip4Address surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip4_address__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("10.0.0.7",):
            expected = Ip4Address(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip4Address(wrapped),
                        expected,
                        msg=f"Ip4Address({wrapped!r}) must equal Ip4Address({value!r}).",
                    )
