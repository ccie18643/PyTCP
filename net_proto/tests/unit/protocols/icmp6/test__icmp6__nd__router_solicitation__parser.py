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


"""
Module contains tests for the ICMPv6 ND Router Solicitation message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__nd__router_solicitation__parser.py

ver 3.0.4
"""


from typing import Any

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6NdRouterSolicitationMessage,
    Icmp6Parser,
    PacketRx,
)
from net_proto.tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6
from parameterized import parameterized_class  # type: ignore


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Router Solicitation message, no options.",
            "_args": [b"\x85\x00\x7a\xff\x00\x00\x00\x00"],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("::"),
                "ip6__dst": Ip6Address("ff02::2"),
            },
            "_results": {
                "message": Icmp6NdRouterSolicitationMessage(
                    cksum=31487,
                    options=Icmp6NdOptions(),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Solicitation message, Slla option present.",
            "_args": [
                b"\x85\x00\x13\x65\x00\x00\x00\x00\x01\x01\x00\x11\x22\x33\x44\x55"
            ],
            "_mocked_values": {
                "ip6__hop": 255,
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("ff02::2"),
            },
            "_results": {
                "message": Icmp6NdRouterSolicitationMessage(
                    cksum=4965,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
    ]
)
class TestIcmp6MessageNdRouterSolicitationParser(TestCasePacketRxIp6):
    """
    The ICMPv6 ND Router Solicitation message parser tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__message__nd__router_solicitation__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 ND Router Solicitation message 'from_bytes()' method
        creates a proper message object.
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
        )
