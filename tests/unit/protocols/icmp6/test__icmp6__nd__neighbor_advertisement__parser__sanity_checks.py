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
Module contains tests for the ICMPv6 ND Neighbor Advertisement message parser
sanity checks.

tests/unit/protocols/icmp6/test__icmp6_ nd__neighbor_addvertisement__parser__sanity_checks.py

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
            "_args": [
                b"\x88\x00\xaa\x44\xa0\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ],
            "_mocked_values": {
                "ip6__hop": 64,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("ff02::1"),
            },
            "_results": {
                "error_message": (
                    "ND Neighbor Advertisement - [RFC 4861] The 'ip6__hop' field must "
                    "be 255. Got: 64"
                ),
            },
        },
        {
            "_description": (
                "The value of the 'ip6__hop' field must be 255. It's 255."
            ),
            "_args": [
                b"\x88\x00\xaa\x44\xa0\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("ff02::1"),
            },
            "_results": {},
        },
        {
            "_description": (
                "The value of the 'ip6__src' field must be unicast. "
                "It's multicast."
            ),
            "_args": [
                b"\x88\x00\xaa\x44\xa0\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("ff02::1"),
                "ip6__dst": Ip6Address("2001:db8::2"),
            },
            "_results": {
                "error_message": (
                    "ND Neighbor Advertisement - [RFC 4861] The 'ip6__src' address "
                    "must be unicast. Got: Ip6Address('ff02::1')"
                ),
            },
        },
        {
            "_description": (
                "The value of the 'ip6__src' field must be unicast. "
                "It's unicast."
            ),
            "_args": [
                b"\x88\x00\xaa\x44\xa0\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("ff02::1"),
            },
            "_results": {},
        },
        {
            "_description": (
                "The 'flag_s' is set and 'ip6__dst' must be unicast or all-nodes multicast. "
                "It's all-routers unicast."
            ),
            "_args": [
                b"\x88\x00\x0a\x45\x40\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("ff02::2"),
            },
            "_results": {
                "error_message": (
                    "ND Neighbor Advertisement - [RFC 4861] If 'na_flag_s' flag is set "
                    "then 'ip6__dst' address must be either unicast or all-nodes multicast. "
                    "Got: Ip6Address('ff02::2')"
                ),
            },
        },
        {
            "_description": (
                "The 'flag_s' is set and 'ip6__dst' must be unicast or all-nodes multicast. "
                "It's unicast."
            ),
            "_args": [
                b"\x88\x00\x0a\x45\x40\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("2001:db8::2"),
            },
            "_results": {},
        },
        {
            "_description": (
                "The 'flag_s' is set and 'ip6__dst' must be unicast or all-nodes multicast. "
                "It's all-nodes multicast."
            ),
            "_args": [
                b"\x88\x00\x0a\x45\x40\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("ff02::1"),
            },
            "_results": {},
        },
        {
            "_description": (
                "The 'flag_s' is not set and 'ip6__dst' must be all-nodes multicast. "
                "It's unicast."
            ),
            "_args": [
                b"\x88\x00\x4a\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("2001:db8::2"),
            },
            "_results": {
                "error_message": (
                    "ND Neighbor Advertisement - [RFC 4861] If 'na_flag_s' flag is not set "
                    "then 'ip6__dst' address must be all-nodes multicast address. Got: "
                    "Ip6Address('2001:db8::2')"
                ),
            },
        },
        {
            "_description": (
                "The 'flag_s' is not set and 'ip6__dst' must be all-nodes multicast. "
                "It's all-nodes multicast."
            ),
            "_args": [
                b"\x88\x00\x4a\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01"
            ],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("ff02::1"),
            },
            "_results": {},
        },
    ]
)
class TestIcmp4NdNeighborAdvertisementParserSanityChecks(TestCasePacketRxIp6):
    """
    The ICMPv6 ND Neighbor Advertisement message parser sanity checks tests.
    """

    _description: str
    _args: list[Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__nd__neighbor_advertisement__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Neighbor Advertisement parser raises sanity errors
        on crazy packets.
        """

        if "error_message" in self._results:
            with self.assertRaises(Icmp6SanityError) as error:
                Icmp6Parser(self._packet_rx)

            self.assertEqual(
                str(error.exception),
                f"[SANITY ERROR][ICMPv6] {self._results["error_message"]}",
            )

        else:
            Icmp6Parser(self._packet_rx)
