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
Module contains tests for the ICMPv4 Destination Unreachable message parser.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__destination_unreachable__parser.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_proto import (
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Icmp4Parser,
    Ip4Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip4(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub whose 'payload_len' matches
    the full frame (the single field Icmp4Parser reads off 'packet_rx.ip4').
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip4 = cast(Ip4Parser, SimpleNamespace(payload_len=len(frame)))
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Destination Unreachable, code 0 (Network), no data.",
            "_frame_rx": (
                # Type/Code : 3/0, Cksum 0xfcff, Rest 0x00000000
                b"\x03\x00\xfc\xff\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.NETWORK,
                    cksum=0xFCFF,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 1 (Host), no data.",
            "_frame_rx": (
                # Type/Code : 3/1, Cksum 0xfcfe, Rest 0x00000000
                b"\x03\x01\xfc\xfe\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.HOST,
                    cksum=0xFCFE,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 2 (Protocol), no data.",
            "_frame_rx": (
                # Type/Code : 3/2, Cksum 0xfcfd, Rest 0x00000000
                b"\x03\x02\xfc\xfd\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.PROTOCOL,
                    cksum=0xFCFD,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 3 (Port), no data.",
            "_frame_rx": (
                # Type/Code : 3/3, Cksum 0xfcfc, Rest 0x00000000
                b"\x03\x03\xfc\xfc\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=0xFCFC,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 4 (Fragmentation Needed), MTU 1200.",
            "_frame_rx": (
                # Type/Code : 3/4, Cksum 0xf84b, Reserved 0x0000, MTU 0x04b0 (1200)
                b"\x03\x04\xf8\x4b\x00\x00\x04\xb0"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                    cksum=0xF84B,
                    mtu=1200,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 5 (Source Route Failed), no data.",
            "_frame_rx": (
                # Type/Code : 3/5, Cksum 0xfcfa, Rest 0x00000000
                b"\x03\x05\xfc\xfa\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.SOURCE_ROUTE_FAILED,
                    cksum=0xFCFA,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 6 (Network Unknown), no data.",
            "_frame_rx": (
                # Type/Code : 3/6, Cksum 0xfcf9, Rest 0x00000000
                b"\x03\x06\xfc\xf9\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.NETWORK_UNKNOWN,
                    cksum=0xFCF9,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 7 (Host Unknown), no data.",
            "_frame_rx": (
                # Type/Code : 3/7, Cksum 0xfcf8, Rest 0x00000000
                b"\x03\x07\xfc\xf8\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.HOST_UNKNOWN,
                    cksum=0xFCF8,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 8 (Source Host Isolated), no data.",
            "_frame_rx": (
                # Type/Code : 3/8, Cksum 0xfcf7, Rest 0x00000000
                b"\x03\x08\xfc\xf7\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.SOURCE_HOST_ISOLATED,
                    cksum=0xFCF7,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 9 (Network Prohibited), no data.",
            "_frame_rx": (
                # Type/Code : 3/9, Cksum 0xfcf6, Rest 0x00000000
                b"\x03\x09\xfc\xf6\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.NETWORK_PROHIBITED,
                    cksum=0xFCF6,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 10 (Host Prohibited), no data.",
            "_frame_rx": (
                # Type/Code : 3/10, Cksum 0xfcf5, Rest 0x00000000
                b"\x03\x0a\xfc\xf5\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.HOST_PROHIBITED,
                    cksum=0xFCF5,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 11 (Network TOS), no data.",
            "_frame_rx": (
                # Type/Code : 3/11, Cksum 0xfcf4, Rest 0x00000000
                b"\x03\x0b\xfc\xf4\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.NETWORK_TOS,
                    cksum=0xFCF4,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 12 (Host TOS), no data.",
            "_frame_rx": (
                # Type/Code : 3/12, Cksum 0xfcf3, Rest 0x00000000
                b"\x03\x0c\xfc\xf3\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.HOST_TOS,
                    cksum=0xFCF3,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 13 (Communication Prohibited), no data.",
            "_frame_rx": (
                # Type/Code : 3/13, Cksum 0xfcf2, Rest 0x00000000
                b"\x03\x0d\xfc\xf2\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.COMMUNICATION_PROHIBITED,
                    cksum=0xFCF2,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 14 (Host Precedence), no data.",
            "_frame_rx": (
                # Type/Code : 3/14, Cksum 0xfcf1, Rest 0x00000000
                b"\x03\x0e\xfc\xf1\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.HOST_PRECEDENCE,
                    cksum=0xFCF1,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, code 15 (Precedence Cutoff), no data.",
            "_frame_rx": (
                # Type/Code : 3/15, Cksum 0xfcf0, Rest 0x00000000
                b"\x03\x0f\xfc\xf0\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.PRECEDENCE_CUTOFF,
                    cksum=0xFCF0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable, non-empty 16-byte data (code=Port).",
            "_frame_rx": (
                # Type/Code : 3/3, Cksum 0x2e26, Rest 0x00000000
                # Data      : b"0123456789ABCDEF"
                b"\x03\x03\x2e\x26\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=0x2E26,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": (
                "ICMPv4 Destination Unreachable, maximum-length data (548 bytes — "
                "IP4__MIN_MTU minus IP4__HEADER__LEN minus DU__LEN)."
            ),
            "_frame_rx": (
                # Type/Code : 3/3, Cksum 0x6e6e, Rest 0x00000000
                # Data      : b"X" * 548 (truncation cap for the DU data field)
                b"\x03\x03\x6e\x6e\x00\x00\x00\x00"
                + b"X" * 548
            ),
            "_results": {
                "message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    cksum=0x6E6E,
                    data=b"X" * 548,
                ),
            },
        },
    ]
)
class TestIcmp4MessageDestinationUnreachableParser(TestCase):
    """
    The ICMPv4 Destination Unreachable message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build a PacketRx for the parametrized frame.
        """

        self._packet_rx = _packet_rx_with_ip4(self._frame_rx)

    def test__icmp4__message__destination_unreachable__parser(self) -> None:
        """
        Ensure the ICMPv4 parser produces an Icmp4MessageDestinationUnreachable
        whose fields match the expected reference message for each frame.

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 parse).
        """

        icmp4_parser = Icmp4Parser(self._packet_rx)

        # Materialize 'data' from memoryview to bytes for structural equality.
        object.__setattr__(
            icmp4_parser.message,
            "data",
            bytes(cast(Icmp4MessageDestinationUnreachable, icmp4_parser.message).data),
        )

        self.assertEqual(
            icmp4_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp4__message__destination_unreachable__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv4 parser fully consumes 'packet_rx.frame' after
        parsing the Destination Unreachable (so downstream layers see an
        empty remainder).

        Reference: RFC 792 (ICMPv4 Destination Unreachable type 3 parse).
        """

        Icmp4Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
