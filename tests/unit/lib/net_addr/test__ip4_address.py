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
This module contains tests for the NetAddr package IPv4 address support class.

tests/unit/lib/net_addr/test__ip4_address.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.net_addr import Ip4Address, Ip4AddressFormatError, Ip6Address


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 address: 0.0.0.0 (str)",
            "_args": ["0.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Address('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash("Ip4Address('0.0.0.0')"),
                "version": 4,
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
            "_args": [None],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Address('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash("Ip4Address('0.0.0.0')"),
                "version": 4,
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
            "_args": ["0.0.0.1"],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.1",
                "__repr__": "Ip4Address('0.0.0.1')",
                "__bytes__": b"\x00\x00\x00\x01",
                "__int__": 1,
                "__hash__": hash("Ip4Address('0.0.0.1')"),
                "version": 4,
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
            "_args": ["0.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "0.255.255.255",
                "__repr__": "Ip4Address('0.255.255.255')",
                "__bytes__": b"\x00\xff\xff\xff",
                "__int__": 16777215,
                "__hash__": hash("Ip4Address('0.255.255.255')"),
                "version": 4,
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
            "_args": ["1.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "1.0.0.0",
                "__repr__": "Ip4Address('1.0.0.0')",
                "__bytes__": b"\x01\x00\x00\x00",
                "__int__": 16777216,
                "__hash__": hash("Ip4Address('1.0.0.0')"),
                "version": 4,
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
            "_args": ["9.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "9.255.255.255",
                "__repr__": "Ip4Address('9.255.255.255')",
                "__bytes__": b"\x09\xff\xff\xff",
                "__int__": 167772159,
                "__hash__": hash("Ip4Address('9.255.255.255')"),
                "version": 4,
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
            "_args": ["10.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "10.0.0.0",
                "__repr__": "Ip4Address('10.0.0.0')",
                "__bytes__": b"\x0a\x00\x00\x00",
                "__int__": 167772160,
                "__hash__": hash("Ip4Address('10.0.0.0')"),
                "version": 4,
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
            "_args": ["10.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "10.255.255.255",
                "__repr__": "Ip4Address('10.255.255.255')",
                "__bytes__": b"\x0a\xff\xff\xff",
                "__int__": 184549375,
                "__hash__": hash("Ip4Address('10.255.255.255')"),
                "version": 4,
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
            "_args": ["11.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "11.0.0.0",
                "__repr__": "Ip4Address('11.0.0.0')",
                "__bytes__": b"\x0b\x00\x00\x00",
                "__int__": 184549376,
                "__hash__": hash("Ip4Address('11.0.0.0')"),
                "version": 4,
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
            "_args": ["126.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "126.255.255.255",
                "__repr__": "Ip4Address('126.255.255.255')",
                "__bytes__": b"\x7e\xff\xff\xff",
                "__int__": 2130706431,
                "__hash__": hash("Ip4Address('126.255.255.255')"),
                "version": 4,
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
            "_args": ["127.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "127.0.0.0",
                "__repr__": "Ip4Address('127.0.0.0')",
                "__bytes__": b"\x7f\x00\x00\x00",
                "__int__": 2130706432,
                "__hash__": hash("Ip4Address('127.0.0.0')"),
                "version": 4,
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
            "_args": ["127.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "127.255.255.255",
                "__repr__": "Ip4Address('127.255.255.255')",
                "__bytes__": b"\x7f\xff\xff\xff",
                "__int__": 2147483647,
                "__hash__": hash("Ip4Address('127.255.255.255')"),
                "version": 4,
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
            "_args": ["128.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "128.0.0.0",
                "__repr__": "Ip4Address('128.0.0.0')",
                "__bytes__": b"\x80\x00\x00\x00",
                "__int__": 2147483648,
                "__hash__": hash("Ip4Address('128.0.0.0')"),
                "version": 4,
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
            "_args": ["169.253.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "169.253.255.255",
                "__repr__": "Ip4Address('169.253.255.255')",
                "__bytes__": b"\xa9\xfd\xff\xff",
                "__int__": 2851995647,
                "__hash__": hash("Ip4Address('169.253.255.255')"),
                "version": 4,
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
            "_description": "Test the IPv4 address: 169.255.0.0 (str)",
            "_args": ["169.255.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "169.255.0.0",
                "__repr__": "Ip4Address('169.255.0.0')",
                "__bytes__": b"\xa9\xff\x00\x00",
                "__int__": 2852061184,
                "__hash__": hash("Ip4Address('169.255.0.0')"),
                "version": 4,
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
            "_args": ["170.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "170.0.0.0",
                "__repr__": "Ip4Address('170.0.0.0')",
                "__bytes__": b"\xaa\x00\x00\x00",
                "__int__": 2852126720,
                "__hash__": hash("Ip4Address('170.0.0.0')"),
                "version": 4,
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
            "_args": ["172.15.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "172.15.255.255",
                "__repr__": "Ip4Address('172.15.255.255')",
                "__bytes__": b"\xac\x0f\xff\xff",
                "__int__": 2886729727,
                "__hash__": hash("Ip4Address('172.15.255.255')"),
                "version": 4,
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
            "_args": ["172.16.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "172.16.0.0",
                "__repr__": "Ip4Address('172.16.0.0')",
                "__bytes__": b"\xac\x10\x00\x00",
                "__int__": 2886729728,
                "__hash__": hash("Ip4Address('172.16.0.0')"),
                "version": 4,
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
            "_args": ["172.31.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "172.31.255.255",
                "__repr__": "Ip4Address('172.31.255.255')",
                "__bytes__": b"\xac\x1f\xff\xff",
                "__int__": 2887778303,
                "__hash__": hash("Ip4Address('172.31.255.255')"),
                "version": 4,
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
            "_args": ["172.32.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "172.32.0.0",
                "__repr__": "Ip4Address('172.32.0.0')",
                "__bytes__": b"\xac\x20\x00\x00",
                "__int__": 2887778304,
                "__hash__": hash("Ip4Address('172.32.0.0')"),
                "version": 4,
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
            "_description": "Test the IPv4 address: 192.167.255.255 (str)",
            "_args": ["192.167.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "192.167.255.255",
                "__repr__": "Ip4Address('192.167.255.255')",
                "__bytes__": b"\xc0\xa7\xff\xff",
                "__int__": 3232235519,
                "__hash__": hash("Ip4Address('192.167.255.255')"),
                "version": 4,
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
            "_args": ["192.168.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.0.0",
                "__repr__": "Ip4Address('192.168.0.0')",
                "__bytes__": b"\xc0\xa8\x00\x00",
                "__int__": 3232235520,
                "__hash__": hash("Ip4Address('192.168.0.0')"),
                "version": 4,
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
            "_args": ["192.168.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "__hash__": hash("Ip4Address('192.168.255.255')"),
                "version": 4,
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
            "_args": [Ip4Address("192.168.255.255")],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "__hash__": hash("Ip4Address('192.168.255.255')"),
                "version": 4,
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
            "_args": [3232301055],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "__hash__": hash("Ip4Address('192.168.255.255')"),
                "version": 4,
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
            "_args": [b"\xc0\xa8\xff\xff"],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "__hash__": hash("Ip4Address('192.168.255.255')"),
                "version": 4,
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
            "_args": [bytearray(b"\xc0\xa8\xff\xff")],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "__hash__": hash("Ip4Address('192.168.255.255')"),
                "version": 4,
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
            "_args": [memoryview(b"\xc0\xa8\xff\xff")],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "__hash__": hash("Ip4Address('192.168.255.255')"),
                "version": 4,
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
            "_args": ["192.169.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "192.169.0.0",
                "__repr__": "Ip4Address('192.169.0.0')",
                "__bytes__": b"\xc0\xa9\x00\x00",
                "__int__": 3232301056,
                "__hash__": hash("Ip4Address('192.169.0.0')"),
                "version": 4,
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
            "_args": ["223.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "223.255.255.255",
                "__repr__": "Ip4Address('223.255.255.255')",
                "__bytes__": b"\xdf\xff\xff\xff",
                "__int__": 3758096383,
                "__hash__": hash("Ip4Address('223.255.255.255')"),
                "version": 4,
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
            "_args": ["224.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "224.0.0.0",
                "__repr__": "Ip4Address('224.0.0.0')",
                "__bytes__": b"\xe0\x00\x00\x00",
                "__int__": 3758096384,
                "__hash__": hash("Ip4Address('224.0.0.0')"),
                "version": 4,
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
                "__hash__": hash("Ip4Address('239.255.255.255')"),
                "version": 4,
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
            "_args": ["240.0.0.0"],
            "_kwargs": {},
            "_results": {
                "__str__": "240.0.0.0",
                "__repr__": "Ip4Address('240.0.0.0')",
                "__bytes__": b"\xf0\x00\x00\x00",
                "__int__": 4026531840,
                "__hash__": hash("Ip4Address('240.0.0.0')"),
                "version": 4,
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
            "_args": ["255.255.255.254"],
            "_kwargs": {},
            "_results": {
                "__str__": "255.255.255.254",
                "__repr__": "Ip4Address('255.255.255.254')",
                "__bytes__": b"\xff\xff\xff\xfe",
                "__int__": 4294967294,
                "__hash__": hash("Ip4Address('255.255.255.254')"),
                "version": 4,
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
            "_args": ["255.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "255.255.255.255",
                "__repr__": "Ip4Address('255.255.255.255')",
                "__bytes__": b"\xff\xff\xff\xff",
                "__int__": 4294967295,
                "__hash__": hash("Ip4Address('255.255.255.255')"),
                "version": 4,
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
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 address object with testcase arguments.
        """

        self._ip4_address = Ip4Address(*self._args, **self._kwargs)

    def test__net_addr__ip4_address__str(self) -> None:
        """
        Ensure the IPv4 address '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip4_address),
            self._results["__str__"],
        )

    def test__net_addr__ip4_address__repr(self) -> None:
        """
        Ensure the IPv4 address '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip4_address),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_address__bytes(self) -> None:
        """
        Ensure the IPv4 address '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._ip4_address),
            self._results["__bytes__"],
        )

    def test__net_addr__ip4_address__int(self) -> None:
        """
        Ensure the IPv4 address '__int__()' method returns a correct value.
        """

        self.assertEqual(
            int(self._ip4_address),
            self._results["__int__"],
        )

    def test__net_addr__ip4_address__eq(self) -> None:
        """
        Ensure the IPv4 address '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip4_address == self._ip4_address,
        )

        self.assertFalse(
            self._ip4_address
            == Ip4Address((int(self._ip4_address) + 1) & 0xFF_FF_FF_FF),
        )

        self.assertFalse(
            self._ip4_address == "not an IPv4 address",
        )

    def test__net_addr__ip4_address__hash(self) -> None:
        """
        Ensure the IPv4 address '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._ip4_address),
            self._results["__hash__"],
        )

    def test__net_addr__ip4_address__version(self) -> None:
        """
        Ensure the IPv4 address 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.version,
            self._results["version"],
        )

    def test__net_addr__ip4_address__unspecified(self) -> None:
        """
        Ensure the IPv4 address 'unspecified' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.unspecified,
            self._results["unspecified"],
        )

    def test__net_addr__ip4_address__is_ip4(self) -> None:
        """
        Ensure the IPv4 address 'is_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_address__is_ip6(self) -> None:
        """
        Ensure the IPv4 address 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_address__is_unspecified(self) -> None:
        """
        Ensure the IPv4 address 'is_unspecified' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_unspecified,
            self._results["is_unspecified"],
        )

    def test__net_addr__ip4_address__is_unicast(self) -> None:
        """
        Ensure the IPv4 address 'is_unicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_unicast,
            self._results["is_unicast"],
        )

    def test__net_addr__ip4_address__is_global(self) -> None:
        """
        Ensure the IPv4 address 'is_global' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_global,
            self._results["is_global"],
        )

    def test__net_addr__ip4_address__is_link_local(self) -> None:
        """
        Ensure the IPv4 address 'is_link_local' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_link_local,
            self._results["is_link_local"],
        )

    def test__net_addr__ip4_address__is_loopback(self) -> None:
        """
        Ensure the IPv4 address 'is_loopback' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_loopback,
            self._results["is_loopback"],
        )

    def test__net_addr__ip4_address__is_multicast(self) -> None:
        """
        Ensure the IPv4 address 'is_multicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_multicast,
            self._results["is_multicast"],
        )

    def test__net_addr__ip4_address__is_private(self) -> None:
        """
        Ensure the IPv4 address 'is_private' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_private,
            self._results["is_private"],
        )

    def test__net_addr__ip4_address__is_reserved(self) -> None:
        """
        Ensure the IPv4 address 'is_reserved' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_reserved,
            self._results["is_reserved"],
        )

    def test__net_addr__ip4_address__is_invalid(self) -> None:
        """
        Ensure the IPv4 address 'is_invalid' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_invalid,
            self._results["is_invalid"],
        )

    def test__net_addr__ip4_address__is_limited_broadcast(self) -> None:
        """
        Ensure the IPv4 address 'is_limited_broadcast' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_address.is_limited_broadcast,
            self._results["is_limited_broadcast"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 address format: '10.10.10.256'",
            "_args": ["10.10.10.256"],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (
                    "The IPv4 address format is invalid: '10.10.10.256'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 address format: '10.10..10'",
            "_args": ["10.10..10"],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (
                    "The IPv4 address format is invalid: '10.10..10'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 address format: '10.10.10,10'",
            "_args": ["10.10.10,10"],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (
                    "The IPv4 address format is invalid: '10.10.10,10'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 address format: b'\xff\xff\xff'",
            "_args": [b"\xff\xff\xff"],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (
                    r"The IPv4 address format is invalid: b'\xff\xff\xff'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 address format: b'\xff\xff\xff\xff\xff'",
            "_args": [b"\xff\xff\xff\xff\xff"],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (
                    r"The IPv4 address format is invalid: b'\xff\xff\xff\xff\xff'"
                ),
            },
        },
        {
            "_description": "Test the IPv4 address format: -1",
            "_args": [-1],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: -1"),
            },
        },
        {
            "_description": "Test the IPv4 address format: 4294967296",
            "_args": [4294967296],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (
                    "The IPv4 address format is invalid: 4294967296"
                ),
            },
        },
        {
            "_description": "Test the IPv4 address format: Ip6Address()",
            "_args": [Ip6Address()],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: Ip6Address('::')",
            },
        },
        {
            "_description": "Test the IPv4 address format: {}",
            "_args": [{}],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: {}",
            },
        },
        {
            "_description": "Test the IPv4 address format: 1.1",
            "_args": [1.1],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: 1.1",
            },
        },
    ]
)
class TestNetAddrIp4AddressErrors(TestCase):
    """
    The NetAddr IPv4 address error tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_address__errors(self) -> None:
        """
        Ensure the IPv4 address raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Address(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )
