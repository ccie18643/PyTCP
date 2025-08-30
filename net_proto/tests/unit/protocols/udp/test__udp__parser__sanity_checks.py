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
Module contains tests for the UDP packet sanity checks.

net_proto/tests/unit/protocols/udp/test__udp__parser__sanity_checks.py

ver 3.0.4
"""


from typing import Any

from net_proto import PacketRx, UdpParser, UdpSanityError
from net_proto.tests.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4
from net_proto.tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6
from parameterized import parameterized_class  # type: ignore

testcases: list[dict[str, Any]] = [
    {
        "_description": "The value of the 'sport' field equals 0.",
        "_args": [b"\x00\x00\xd4\x31\x00\x08\x2b\xc6"],
        "_kwargs": {},
        "_mocked_values": {},
        "_results": {
            "error_message": (
                "The 'sport' field must be greater than 0. Got: 0"
            ),
        },
    },
    {
        "_description": "The value of the 'dport' field equals 0.",
        "_args": [b"\x30\x39\x00\x00\x00\x08\xcf\xbe"],
        "_kwargs": {},
        "_mocked_values": {},
        "_results": {
            "error_message": (
                "The 'dport' field must be greater than 0. Got: 0"
            ),
        },
    },
]


@parameterized_class(testcases)
class TestUdpParserSanityChecks__Ip4(TestCasePacketRxIp4):
    """
    The UDP packet parser sanity checks tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__udp__parser__from_bytes(self) -> None:
        """
        Ensure the UDP packet parser raises sanity errors on crazy packets.
        """

        with self.assertRaises(UdpSanityError) as error:
            UdpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][UDP] {self._results["error_message"]}",
        )


@parameterized_class(testcases)
class TestUdpParserSanityChecks__Ip6(TestCasePacketRxIp6):
    """
    The UDP packet parser sanity checks tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__udp__parser__from_bytes(self) -> None:
        """
        Ensure the UDP packet parser raises sanity errors on crazy packets.
        """

        with self.assertRaises(UdpSanityError) as error:
            UdpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][UDP] {self._results["error_message"]}",
        )
