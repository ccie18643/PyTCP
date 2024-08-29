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
Module contains tests for the ICMPv6 ND Router Advertisement message parser sanity
checks.

tests/unit/protocols/icmp6/test__icmp6__nd__router_addvertisement__parser__sanity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp6.icmp6__errors import Icmp6SanityError
from pytcp.protocols.icmp6.icmp6__parser import Icmp6Parser
from tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": "The value of the 'ip6__hop' field is not 255.",
            "_args": {
                "bytes": b"\x86\x00\x7a\x3e\xff\xc0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            },
            "_mocked_values": {
                "ip6__hop": 64,
            },
            "_results": {
                "error_message": (
                    "ND Router Advertisement - [RFC 4861] The 'ip6__hop' field "
                    "must be 255. Got: 64"
                ),
            },
        },
    ]
)
class TestIcmp4NdRouterAdvertisementParserSanityChecks(TestCasePacketRxIp6):
    """
    The ICMPv4 ND Router Advertisement message parser sanity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__nd__router_advertisement__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 ND Router Advertisement parser raises sanity errors
        on crazy packets.
        """

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(packet_rx=self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][ICMPv6] {self._results["error_message"]}",
        )
