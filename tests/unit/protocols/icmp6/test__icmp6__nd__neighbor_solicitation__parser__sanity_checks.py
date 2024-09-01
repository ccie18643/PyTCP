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
Module contains tests for the ICMPv6 ND Neighbor Solicitation message parser sanity
checks.

tests/unit/protocols/icmp6/test__icmp6__nd__neighbor_addvertisement__parser__sanity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.net_addr import Ip6Address
from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp6.icmp6__errors import Icmp6SanityError
from pytcp.protocols.icmp6.icmp6__parser import Icmp6Parser
from tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": (
                "The value of the 'ip6__hop' field must be 255. It's 64."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 64,
                "ip6__src": Ip6Address("2001:db8::2"),
                "ip6__dst": Ip6Address("2001:db8::1"),
            },
            "_results": {
                "error_message": (
                    "ND Neighbor Solicitation - [RFC 4861] The 'ip6__hop' field "
                    "must be 255. Got: 64"
                ),
            },
        },
        {
            "_description": (
                "The value of the 'ip6__hop' field must be 255. It's 255."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::2"),
                "ip6__dst": Ip6Address("2001:db8::1"),
            },
            "_results": {},
        },
        {
            "_description": (
                "The value of the 'ip6__src' must be unicast or unspecified. "
                "It's multicast."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("ff02::1"),
                "ip6__dst": Ip6Address("2001:db8::1"),
            },
            "_results": {
                "error_message": (
                    "ND Neighbor Solicitation - [RFC 4861] The 'ip6__src' address "
                    "must be unicast or unspecified. Got: Ip6Address('ff02::1')"
                ),
            },
        },
        {
            "_description": (
                "The value of the 'ip6__src' must be unicast or unspecified. "
                "It's unicast."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::2"),
                "ip6__dst": Ip6Address("2001:db8::1"),
            },
            "_results": {},
        },
        {
            "_description": (
                "The value of the 'ip6__src' must be unicast or unspecified. "
                "It's unspecified."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("::"),
                "ip6__dst": Ip6Address("2001:db8::1"),
            },
            "_results": {},
        },
        {
            "_description": (
                "The value of the 'ip6__dst' must be same as target address or its "
                "solicited-node multicast address. It's different."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("2001:db8::2"),
            },
            "_results": {
                "error_message": (
                    "ND Neighbor Solicitation - [RFC 4861] The 'ip6__dst' address must "
                    "be the same as 'target_address' address or related solicited-node "
                    "multicast address. Got: Ip6Address('2001:db8::2')"
                ),
            },
        },
        {
            "_description": (
                "The value of the 'ip6__dst' must be same as target address or its "
                "solicited-node multicast address. It's the same as target address."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::2"),
                "ip6__dst": Ip6Address("2001:db8::1"),
            },
            "_results": {},
        },
        {
            "_description": (
                "The value of the 'ip6__dst' must be same as target address or its "
                "solicited-node multicast address. It's the related solicited-node "
                "multicast address."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::2"),
                "ip6__dst": Ip6Address("ff02::1:ff00:1"),
            },
            "_results": {},
        },
        {
            "_description": (
                "The target address must be unicast. It's unspecified."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x78\xff\x00\x00\x00\x00\00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::2"),
                "ip6__dst": Ip6Address("::"),
            },
            "_results": {
                "error_message": (
                    "ND Neighbor Solicitation - [RFC 4861] The 'target_address' address "
                    "must be unicast. Got: Ip6Address('::')"
                ),
            },
        },
        {
            "_description": (
                "The target address must be unicast. It's unicast."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::2"),
                "ip6__dst": Ip6Address("2001:db8::1"),
            },
            "_results": {},
        },
        {
            "_description": (
                "If the 'ip6__src' is unspecified, the 'slla' option must not be present. "
                "It's not present."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\xe3\xa9\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("::"),
                "ip6__dst": Ip6Address("2001:db8::2"),
            },
            "_results": {
                "error_message": (
                    "ND Neighbor Solicitation - [RFC 4861] When the 'ip6__src' is "
                    "unspecified, the 'slla' option must not be included. Got: "
                    "MacAddress('00:11:22:33:44:55')"
                ),
            },
        },
        {
            "_description": (
                "If the 'ip6__src' is unspecified, the 'slla' option must not be present. "
                "It's not present."
            ),
            "_args": {
                "bytes": (
                    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("::"),
                "ip6__dst": Ip6Address("2001:db8::1"),
            },
            "_results": {},
        },
    ]
)
class TestIcmp4NdNeighborSolicitationParserSanityChecks(TestCasePacketRxIp6):
    """
    The ICMPv6 ND Neighbor Solicitation message parser sanity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__nd__neighbor_solicitation__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Solicitation parser raises sanity errors
        on crazy packets.
        """

        if "error_message" in self._results:
            with self.assertRaises(Icmp6SanityError) as error:
                Icmp6Parser(packet_rx=self._packet_rx)

            self.assertEqual(
                str(error.exception),
                f"[SANITY ERROR][ICMPv6] {self._results["error_message"]}",
            )

        else:
            Icmp6Parser(packet_rx=self._packet_rx)
