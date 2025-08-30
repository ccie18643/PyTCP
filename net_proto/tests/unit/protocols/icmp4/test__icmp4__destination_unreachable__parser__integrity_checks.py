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
Module contains tests for the ICMPv4 Destination Unreachable message parser
integrity checks.

net_proto/tests/unit/protocols/icmp4/test__icmp4__destination_unreachable__parser__integrity_checks.py

ver 3.0.4
"""


from typing import Any

from net_proto import Icmp4IntegrityError, Icmp4Parser, PacketRx
from net_proto.tests.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4
from parameterized import parameterized_class  # type: ignore


@parameterized_class(
    [
        {
            "_description": (
                "ICMPv4 Destination Unreachable message, "
                "the 'ICMP4_HEADER_LEN <= self._ip4_payload_len' condition not met."
            ),
            "_args": [b"\x03\x00\xfb"],
            "_mocked_values": {
                "ip4__payload_len": 3,
            },
            "_results": {
                "error_message": (
                    "The condition 'ICMP4__HEADER__LEN <= self._ip4__payload_len "
                    "<= len(self._frame)' must be met. Got: ICMP4__HEADER__LEN=4, "
                    "self._ip4__payload_len=3, len(self._frame)=3"
                ),
            },
        },
        {
            "_description": (
                "ICMPv4 Destination Unreachable message, "
                "the 'self._ip4_payload_len <= len(self._frame)' condition not met."
            ),
            "_args": [b"\x03\x00\xfb\x94\x30\x39\xd4"],
            "_mocked_values": {
                "ip4__payload_len": 8,
            },
            "_results": {
                "error_message": (
                    "The condition 'ICMP4__HEADER__LEN <= self._ip4__payload_len "
                    "<= len(self._frame)' must be met. Got: ICMP4__HEADER__LEN=4, "
                    "self._ip4__payload_len=8, len(self._frame)=7"
                ),
            },
        },
        {
            "_description": (
                "ICMPv4 Destination Unreachable message, "
                "the 'ICMP4_DESTINATION_UNREACHABLE_LEN <= self._ip4_payload_len' "
                "condition not met."
            ),
            "_args": [b"\x03\x00\xfb\x94\x30\x39\xd4"],
            "_mocked_values": {
                "ip4__payload_len": 7,
            },
            "_results": {
                "error_message": (
                    "The condition 'ICMP4__DESTINATION_UNREACHABLE__LEN <= ip4__payload_len "
                    "<= len(frame)' must be met. Got: ICMP4__DESTINATION_UNREACHABLE__LEN=8, "
                    "ip4__payload_len=7, len(frame)=7"
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable message, invalid checksum.",
            "_args": [b"\x03\x00\x00\x00\x30\x39\xd4\x31"],
            "_mocked_values": {},
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestIcmp4DestinationUnreachableParserIntegrityChecks(TestCasePacketRxIp4):
    """
    The ICMPv4 Destination Unreachable message parser integrity checks tests.
    """

    _description: str
    _args: list[Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp4__destination_unreachable__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message parser raises
        integrity error on malformed packets.
        """

        with self.assertRaises(Icmp4IntegrityError) as error:
            Icmp4Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv4] {self._results["error_message"]}",
        )
