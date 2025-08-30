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
This module contains tests for the NetAddr package IPv6 address support class.

net_addr/tests/unit/test__ip6_address.py

ver 3.0.4
"""


from typing import Any

from net_addr import Ip4Address, Ip6Address, Ip6AddressFormatError, IpVersion
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 address: :: (str)",
            "_args": ["::"],
            "_kwargs": {},
            "_results": {
                "__str__": "::",
                "__repr__": "Ip6Address('::')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash("Ip6Address('::')"),
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
            "_args": [None],
            "_kwargs": {},
            "_results": {
                "__str__": "::",
                "__repr__": "Ip6Address('::')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash("Ip6Address('::')"),
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
            "_args": ["::1"],
            "_kwargs": {},
            "_results": {
                "__str__": "::1",
                "__repr__": "Ip6Address('::1')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                "__int__": 1,
                "__hash__": hash("Ip6Address('::1')"),
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
            "_args": ["2000::"],
            "_kwargs": {},
            "_results": {
                "__str__": "2000::",
                "__repr__": "Ip6Address('2000::')",
                "__bytes__": b"\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 42535295865117307932921825928971026432,
                "__hash__": hash("Ip6Address('2000::')"),
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
            "_args": ["3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            "_kwargs": {},
            "_results": {
                "__str__": "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "__repr__": "Ip6Address('3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')",
                "__bytes__": b"\x3f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 85070591730234615865843651857942052863,
                "__hash__": hash(
                    "Ip6Address('3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')"
                ),
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
            "_args": ["fe80::"],
            "_kwargs": {},
            "_results": {
                "__str__": "fe80::",
                "__repr__": "Ip6Address('fe80::')",
                "__bytes__": b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 338288524927261089654018896841347694592,
                "__hash__": hash("Ip6Address('fe80::')"),
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
            "_args": ["febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            "_kwargs": {},
            "_results": {
                "__str__": "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "__repr__": "Ip6Address('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff')",
                "__bytes__": b"\xfe\xbf\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 338620831926207318622244848606417780735,
                "__hash__": hash(
                    "Ip6Address('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff')"
                ),
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
            "_args": ["fc00::"],
            "_kwargs": {},
            "_results": {
                "__str__": "fc00::",
                "__repr__": "Ip6Address('fc00::')",
                "__bytes__": b"\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 334965454937798799971759379190646833152,
                "__hash__": hash("Ip6Address('fc00::')"),
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
            "_args": ["fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            "_kwargs": {},
            "_results": {
                "__str__": "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "__repr__": "Ip6Address('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')",
                "__bytes__": b"\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 337623910929368631717566993311207522303,
                "__hash__": hash(
                    "Ip6Address('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')"
                ),
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
            "_args": ["ff00::"],
            "_kwargs": {},
            "_results": {
                "__str__": "ff00::",
                "__repr__": "Ip6Address('ff00::')",
                "__bytes__": b"\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "__int__": 338953138925153547590470800371487866880,
                "__hash__": hash("Ip6Address('ff00::')"),
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
            "_args": ["ff02::1"],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1",
                "__repr__": "Ip6Address('ff02::1')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                "__int__": 338963523518870617245727861364146307073,
                "__hash__": hash("Ip6Address('ff02::1')"),
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
            "_args": ["ff02::2"],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::2",
                "__repr__": "Ip6Address('ff02::2')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
                "__int__": 338963523518870617245727861364146307074,
                "__hash__": hash("Ip6Address('ff02::2')"),
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
            "_args": ["ff02::1:ff00:0"],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "__hash__": hash("Ip6Address('ff02::1:ff00:0')"),
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
            "_args": ["FF02::1:FF00:0"],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "__hash__": hash("Ip6Address('ff02::1:ff00:0')"),
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
            "_args": [Ip6Address("ff02::1:ff00:0")],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "__hash__": hash("Ip6Address('ff02::1:ff00:0')"),
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
            "_args": [338963523518870617245727861372719464448],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "__hash__": hash("Ip6Address('ff02::1:ff00:0')"),
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
                b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00"
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "__hash__": hash("Ip6Address('ff02::1:ff00:0')"),
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
                bytearray(
                    b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00"
                )
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "__hash__": hash("Ip6Address('ff02::1:ff00:0')"),
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
                memoryview(
                    b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00"
                )
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ff00:0",
                "__repr__": "Ip6Address('ff02::1:ff00:0')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00",
                "__int__": 338963523518870617245727861372719464448,
                "__hash__": hash("Ip6Address('ff02::1:ff00:0')"),
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
            "_args": ["ff02::1:ffff:ffff"],
            "_kwargs": {},
            "_results": {
                "__str__": "ff02::1:ffff:ffff",
                "__repr__": "Ip6Address('ff02::1:ffff:ffff')",
                "__bytes__": b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\xff\xff\xff",
                "__int__": 338963523518870617245727861372736241663,
                "__hash__": hash("Ip6Address('ff02::1:ffff:ffff')"),
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
            "_args": ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
            "_kwargs": {},
            "_results": {
                "__str__": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "__repr__": "Ip6Address('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
                "__int__": 340282366920938463463374607431768211455,
                "__hash__": hash(
                    "Ip6Address('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')"
                ),
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
        """

        self.assertEqual(
            str(self._ip6_address),
            self._results["__str__"],
        )

    def test__net_addr__ip6_address__repr(self) -> None:
        """
        Ensure the IPv6 address '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip6_address),
            self._results["__repr__"],
        )

    def test__net_addr__ip6_address__bytes(self) -> None:
        """
        Ensure the IPv6 address '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._ip6_address),
            self._results["__bytes__"],
        )

    def test__net_addr__ip6_address__int(self) -> None:
        """
        Ensure the IPv6 address '__int__()' method returns a correct value.
        """

        self.assertEqual(
            int(self._ip6_address),
            self._results["__int__"],
        )

    def test__net_addr__ip6_address__eq(self) -> None:
        """
        Ensure the IPv6 address '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip6_address == self._ip6_address,
        )

        self.assertFalse(
            self._ip6_address
            == Ip6Address((int(self._ip6_address) + 1) & 0xFF_FF_FF_FF),
        )

        self.assertFalse(
            self._ip6_address == "not an IPv6 address",
        )

    def test__net_addr__ip6_address__hash(self) -> None:
        """
        Ensure the IPv6 address '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._ip6_address),
            self._results["__hash__"],
        )

    def test__net_addr__ip6_address__version(self) -> None:
        """
        Ensure the IPv6 address 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip6_address.version,
            self._results["version"],
        )

    def test__net_addr__ip6_address__unspecified(self) -> None:
        """
        Ensure the IPv6 address 'unspecified' property returns a correct value.
        """

        self.assertEqual(
            self._ip6_address.unspecified,
            self._results["unspecified"],
        )

    def test__net_addr__ip6_address__is_ip4(self) -> None:
        """
        Ensure the IPv6 address 'is_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_address.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip6_address__is_ip6(self) -> None:
        """
        Ensure the IPv6 address 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_address.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip6_address__is_unspecified(self) -> None:
        """
        Ensure the IPv6 address 'is_unspecified' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_address.is_unspecified,
            self._results["is_unspecified"],
        )

    def test__net_addr__ip6_address__is_unicast(self) -> None:
        """
        Ensure the IPv6 address 'is_unicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_address.is_unicast,
            self._results["is_unicast"],
        )

    def test__net_addr__ip6_address__is_global(self) -> None:
        """
        Ensure the IPv6 address 'is_global' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_address.is_global,
            self._results["is_global"],
        )

    def test__net_addr__ip6_address__is_link_local(self) -> None:
        """
        Ensure the IPv6 address 'is_link_local' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_address.is_link_local,
            self._results["is_link_local"],
        )

    def test__net_addr__ip6_address__is_loopback(self) -> None:
        """
        Ensure the IPv6 address 'is_loopback' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_address.is_loopback,
            self._results["is_loopback"],
        )

    def test__net_addr__ip6_address__is_multicast(self) -> None:
        """
        Ensure the IPv6 address 'is_multicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_address.is_multicast,
            self._results["is_multicast"],
        )

    def test__net_addr__ip6_address__is_multicast__all_nodes(self) -> None:
        """
        Ensure the IPv6 address 'is_multicast__all_nodes' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip6_address.is_multicast__all_nodes,
            self._results["is_multicast__all_nodes"],
        )

    def test__net_addr__ip6_address__is_multicast__all_routers(self) -> None:
        """
        Ensure the IPv6 address 'is_multicast__all_routers' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip6_address.is_multicast__all_routers,
            self._results["is_multicast__all_routers"],
        )

    def test__net_addr__ip6_address__is_private(self) -> None:
        """
        Ensure the IPv6 address 'is_private' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_address.is_private,
            self._results["is_private"],
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 address format: '2000::10000'",
            "_args": ["2000::10000"],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": (
                    "The IPv6 address format is invalid: '2000::10000'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 address format: '2000:::'",
            "_args": ["2000:::"],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": (
                    "The IPv6 address format is invalid: '2000:::'"
                ),
            },
        },
        {
            "_description": "Test the IPv6 address format: '2000;:1'",
            "_args": ["2000;:1"],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": (
                    "The IPv6 address format is invalid: '2000;:1'"
                ),
            },
        },
        {
            "_description": (
                "Test the IPv6 address format: "
                "b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'"
            ),
            "_args": [
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
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
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
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
            "_args": [-1],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": ("The IPv6 address format is invalid: -1"),
            },
        },
        {
            "_description": (
                "Test the IPv6 address format: 340282366920938463463374607431768211456"
            ),
            "_args": [340282366920938463463374607431768211456],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": (
                    "The IPv6 address format is invalid: 340282366920938463463374607431768211456"
                ),
            },
        },
        {
            "_description": "Test the IPv6 address format: Ip4Address()",
            "_args": [Ip4Address()],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": "The IPv6 address format is invalid: Ip4Address('0.0.0.0')",
            },
        },
        {
            "_description": "Test the IPv6 address format: {}",
            "_args": [{}],
            "_kwargs": {},
            "_results": {
                "error": Ip6AddressFormatError,
                "error_message": "The IPv6 address format is invalid: {}",
            },
        },
        {
            "_description": "Test the IPv6 address format: 1.1",
            "_args": [1.1],
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
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip6Address(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )
