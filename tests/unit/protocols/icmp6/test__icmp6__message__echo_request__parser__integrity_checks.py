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
Module contains tests for the ICMPv6 Echo Request message parser integrity
checks.

tests/unit/protocols/icmp6/test__icmp6__message__echo_request__parser__integrity_checks.py

ver 3.0.1
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import StrictMock, TestCase

from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from pytcp.protocols.icmp6.icmp6__parser import Icmp6Parser
from pytcp.protocols.ip6.ip6__parser import Ip6Parser


@parameterized_class(
    [
        {
            "_description": (
                "ICMPv6 Echo Request message, "
                "the 'ICMP6_HEADER_LEN <= self._ip6_payload_len' condition not met."
            ),
            "_args": {
                "bytes": b"\x80\x00\xfb",
            },
            "_mocked_values": {
                "ip6__dlen": 3,
            },
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__HEADER__LEN <= self._ip6__dlen "
                    "<= len(self._frame)' must be met. Got: ICMP6__HEADER__LEN=4, "
                    "self._ip6__dlen=3, len(self._frame)=3"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 Echo Request message, "
                "the 'self._ip6__dlen <= len(self._frame)' condition not met."
            ),
            "_args": {
                "bytes": b"\x80\x00\xfb\x94\x30\x39\xd4",
            },
            "_mocked_values": {
                "ip6__dlen": 8,
            },
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__HEADER__LEN <= self._ip6__dlen "
                    "<= len(self._frame)' must be met. Got: ICMP6__HEADER__LEN=4, "
                    "self._ip6__dlen=8, len(self._frame)=7"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 Echo Request message, "
                "the 'ICMP6__ECHO_REQUEST__LEN <= self._ip6__dlen' condition not met."
            ),
            "_args": {
                "bytes": b"\x80\x00\xfb\x94\x30\x39\xd4",
            },
            "_mocked_values": {
                "ip6__dlen": 7,
            },
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__ECHO_REQUEST__LEN <= ip6__dlen "
                    "<= len(frame)' must be met. Got: ICMP6__ECHO_REQUEST__LEN=8, "
                    "ip6__dlen=7, len(frame)=7"
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message, invalid checksum.",
            "_args": {
                "bytes": b"\x80\x00\x00\x00\x30\x39\xd4\x31",
            },
            "_mocked_values": {},
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestIcmp6EchoRequestMessageParserIntegrityChecks(TestCase):
    """
    The ICMPv6 Echo Request message parser integrity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__message__echo_request__parser__from_bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 Echo Request message parser raises integrity error
        on malformed packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        packet_rx.ip6 = cast(Ip6Parser, StrictMock(template=Ip6Parser))
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="dlen",
            new_value=self._mocked_values.get(
                "ip6__dlen", len(self._args["bytes"])
            ),
        )
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="pshdr_sum",
            new_value=0,
        )
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="src",
            new_value=Ip6Address(),
        )
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="dst",
            new_value=Ip6Address(),
        )
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="hop",
            new_value=64,
        )

        with self.assertRaises(Icmp6IntegrityError) as error:
            Icmp6Parser(packet_rx=packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv6] {self._results["error_message"]}",
        )
