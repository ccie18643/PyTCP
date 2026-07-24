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
Module contains tests for the ICMPv6 Destination Unreachable message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__destination_unreachable__parser.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip6(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the attributes the
    ICMPv6 parser reads (dlen, pshdr_sum, src, dst, hop).
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame),
            payload_len=len(frame),
            pshdr_sum=0,
            src=Ip6Address(),
            dst=Ip6Address(),
            hop=0,
        ),
    )
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Destination Unreachable (No Route), empty data.",
            "_frame_rx": (
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 0 (No Route)
                #   Checksum : 0xfeff
                #   Reserved : 0x00000000
                #   Data     : none
                b"\x01\x00\xfe\xff\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.NO_ROUTE,
                    cksum=0xFEFF,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Prohibited), empty data.",
            "_frame_rx": (
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 1 (Administratively Prohibited)
                #   Checksum : 0xfefe
                #   Reserved : 0x00000000
                #   Data     : none
                b"\x01\x01\xfe\xfe\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.PROHIBITED,
                    cksum=0xFEFE,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Beyond Scope), empty data.",
            "_frame_rx": (
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 2 (Beyond Scope)
                #   Checksum : 0xfefd
                #   Reserved : 0x00000000
                #   Data     : none
                b"\x01\x02\xfe\xfd\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.SCOPE,
                    cksum=0xFEFD,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Address Unreachable), empty data.",
            "_frame_rx": (
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 3 (Address Unreachable)
                #   Checksum : 0xfefc
                #   Reserved : 0x00000000
                #   Data     : none
                b"\x01\x03\xfe\xfc\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.ADDRESS,
                    cksum=0xFEFC,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Port Unreachable), empty data.",
            "_frame_rx": (
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 4 (Port Unreachable)
                #   Checksum : 0xfefb
                #   Reserved : 0x00000000
                #   Data     : none
                b"\x01\x04\xfe\xfb\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=0xFEFB,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Source Failed Policy), empty data.",
            "_frame_rx": (
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 5 (Source Failed Policy)
                #   Checksum : 0xfefa
                #   Reserved : 0x00000000
                #   Data     : none
                b"\x01\x05\xfe\xfa\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.FAILED_POLICY,
                    cksum=0xFEFA,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Reject Route), empty data.",
            "_frame_rx": (
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 6 (Reject Route)
                #   Checksum : 0xfef9
                #   Reserved : 0x00000000
                #   Data     : none
                b"\x01\x06\xfe\xf9\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.REJECT_ROUTE,
                    cksum=0xFEF9,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Error in Source Routing Header), empty data.",
            "_frame_rx": (
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 7 (Error in Source Routing Header)
                #   Checksum : 0xfef8
                #   Reserved : 0x00000000
                #   Data     : none
                b"\x01\x07\xfe\xf8\x00\x00\x00\x00"
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.SOURCE_ROUTING_HEADER,
                    cksum=0xFEF8,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Port Unreachable), 16-byte data.",
            "_frame_rx": (
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 4 (Port Unreachable)
                #   Checksum : 0x3025
                #   Reserved : 0x00000000
                #   Data     : b"0123456789ABCDEF" (16 bytes)
                b"\x01\x04\x30\x25\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=0x3025,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 Destination Unreachable (Port Unreachable), 1232-byte data "
                "(IP6_MIN_MTU - IP6_HEADER_LEN - ICMP6__DESTINATION_UNREACHABLE__LEN)."
            ),
            "_frame_rx": (
                # ICMPv6 Destination Unreachable (RFC4443 limit: original datagram
                # truncated to fit min-MTU-sized reply)
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 4 (Port Unreachable)
                #   Checksum : 0x6a67
                #   Reserved : 0x00000000
                #   Data     : b"X" * 1232
                b"\x01\x04\x6a\x67\x00\x00\x00\x00"
                + b"X" * 1232
            ),
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=0x6A67,
                    data=b"X" * 1232,
                ),
            },
        },
    ]
)
class TestIcmp6MessageDestinationUnreachableParser(TestCase):
    """
    The ICMPv6 Destination Unreachable message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build a PacketRx for the parametrized frame.
        """

        self._packet_rx = _packet_rx_with_ip6(self._frame_rx)

    def test__icmp6__message__destination_unreachable__parser(self) -> None:
        """
        Ensure the ICMPv6 parser produces an Icmp6MessageDestinationUnreachable
        whose fields match the expected reference message for each frame.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        # Materialize 'data' from memoryview to bytes for structural equality.
        object.__setattr__(
            icmp6_parser.message,
            "data",
            bytes(cast(Icmp6MessageDestinationUnreachable, icmp6_parser.message).data),
        )

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__parser__message_type(self) -> None:
        """
        Ensure the parsed message is an Icmp6MessageDestinationUnreachable
        instance.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertIsInstance(
            icmp6_parser.message,
            Icmp6MessageDestinationUnreachable,
            msg=f"Parsed message must be Icmp6MessageDestinationUnreachable for case: {self._description}",
        )

    def test__icmp6__message__destination_unreachable__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv6 parser advances 'packet_rx.frame' past the
        parsed Destination Unreachable message.

        Reference: RFC 4443 §3.1 (Destination Unreachable type 1).
        """

        Icmp6Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
