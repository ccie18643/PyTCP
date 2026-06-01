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
Module contains tests for the ICMPv4 Time Exceeded message parser
operation.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__time_exceeded__parser.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    Icmp4MessageTimeExceeded,
    Icmp4Parser,
    Icmp4TimeExceededCode,
    Ip4Parser,
    PacketRx,
)


def _packet_rx_with_ip4(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub whose 'payload_len' matches
    the full frame.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip4 = cast(Ip4Parser, SimpleNamespace(payload_len=len(frame)))
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Time Exceeded, code 0 (TTL Exceeded in Transit), no data.",
            "_frame_rx": (
                # Type/Code : 11/0, Cksum 0xf4ff, Rest 0x00000000
                b"\x0b\x00\xf4\xff\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageTimeExceeded(
                    code=Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                    cksum=0xF4FF,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Time Exceeded, code 1 (Fragment Reassembly Time Exceeded), no data.",
            "_frame_rx": (
                # Type/Code : 11/1, Cksum 0xf4fe, Rest 0x00000000
                b"\x0b\x01\xf4\xfe\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageTimeExceeded(
                    code=Icmp4TimeExceededCode.FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
                    cksum=0xF4FE,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Time Exceeded, code 0 with embedded IP header + 8 bytes UDP.",
            "_frame_rx": (
                # Type/Code : 11/0, Cksum 0x9304, Rest 0x00000000
                # then 20-byte IPv4 header + 8 bytes UDP header.
                b"\x0b\x00\x93\x04\x00\x00\x00\x00"
                b"\x45\x00\x00\x21\x00\x01\x00\x00\x40\x11\xa8\x6c"
                b"\x0a\x00\x01\x07\x0a\x00\x01\x5b"
                b"\x03\xe8\x07\xd0\x00\x0d\x12\x34"
            ),
            "_results": {
                "message": Icmp4MessageTimeExceeded(
                    code=Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                    cksum=0x9304,
                    data=(
                        b"\x45\x00\x00\x21\x00\x01\x00\x00\x40\x11\xa8\x6c"
                        b"\x0a\x00\x01\x07\x0a\x00\x01\x5b"
                        b"\x03\xe8\x07\xd0\x00\x0d\x12\x34"
                    ),
                ),
            },
        },
    ]
)
class TestIcmp4MessageTimeExceededParser(TestCase):
    """
    The ICMPv4 Time Exceeded message parser-operation tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__icmp4__message__time_exceeded__parser__dispatches_to_time_exceeded(
        self,
    ) -> None:
        """
        Ensure that an inbound frame whose ICMPv4 type byte is 11 routes
        through Icmp4Parser to an Icmp4MessageTimeExceeded instance —
        not to Icmp4MessageUnknown. This is the regression that closes
        the silent-drop gap on Time Exceeded.

        Reference: RFC 792 (Time Exceeded type 11).
        Reference: RFC 1122 §3.2.2.4 (incoming Time Exceeded MUST be
        passed to the transport layer).
        """

        packet_rx = _packet_rx_with_ip4(self._frame_rx)

        Icmp4Parser(packet_rx)

        self.assertIsInstance(
            packet_rx.icmp4.message,
            Icmp4MessageTimeExceeded,
            msg=f"Type-11 frame must route to Icmp4MessageTimeExceeded for case: {self._description}",
        )

    def test__icmp4__message__time_exceeded__parser__decoded_message_matches(
        self,
    ) -> None:
        """
        Ensure the decoded Time Exceeded message equals the expected
        dataclass (code, cksum, data round-trip cleanly).

        Reference: RFC 792 (Time Exceeded wire format).
        """

        packet_rx = _packet_rx_with_ip4(self._frame_rx)

        Icmp4Parser(packet_rx)

        self.assertEqual(
            packet_rx.icmp4.message,
            self._results["message"],
            msg=f"Unexpected decoded Time Exceeded message for case: {self._description}",
        )
