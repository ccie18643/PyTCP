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
Module contains tests for the ICMPv6 Echo Request message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__echo_request__parser.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address
from net_proto import (
    Icmp6MessageEchoRequest,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)


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
            "_description": "ICMPv6 Echo Request, empty data.",
            "_frame_rx": (
                # ICMPv6 Echo Request
                #   Type     : 128 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0x7b94
                #   Id       : 0x3039 (12345)
                #   Seq      : 0xd431 (54321)
                #   Data     : none
                b"\x80\x00\x7b\x94\x30\x39\xd4\x31"
            ),
            "_results": {
                "message": Icmp6MessageEchoRequest(
                    cksum=0x7B94,
                    id=12345,
                    seq=54321,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Echo Request, 16-byte data.",
            "_frame_rx": (
                # ICMPv6 Echo Request
                #   Type     : 128 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0xacbd
                #   Id       : 0x3039 (12345)
                #   Seq      : 0xd431 (54321)
                #   Data     : b"0123456789ABCDEF" (16 bytes)
                b"\x80\x00\xac\xbd\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "message": Icmp6MessageEchoRequest(
                    cksum=0xACBD,
                    id=12345,
                    seq=54321,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv6 Echo Request, 65527-byte data (IP6__PAYLOAD__MAX_LEN - ICMP6__ECHO_REQUEST__LEN).",
            "_frame_rx": (
                # ICMPv6 Echo Request (maximum payload that fits in IPv6)
                #   Type     : 128 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0x3357
                #   Id       : 0x2b67 (11111)
                #   Seq      : 0x56ce (22222)
                #   Data     : b"X" * 65527
                b"\x80\x00\x33\x57\x2b\x67\x56\xce"
                + b"X" * 65527
            ),
            "_results": {
                "message": Icmp6MessageEchoRequest(
                    cksum=0x3357,
                    id=11111,
                    seq=22222,
                    data=b"X" * 65527,
                ),
            },
        },
    ]
)
class TestIcmp6MessageEchoRequestParser(TestCase):
    """
    The ICMPv6 Echo Request message parser tests.
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

    def test__icmp6__message__echo_request__parser(self) -> None:
        """
        Ensure the ICMPv6 parser produces an Icmp6MessageEchoRequest
        whose fields match the expected reference message for each frame.

        Reference: RFC 4443 §4.1 (Echo Request type 128).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        # Materialize 'data' from memoryview to bytes for structural equality.
        object.__setattr__(
            icmp6_parser.message,
            "data",
            bytes(cast(Icmp6MessageEchoRequest, icmp6_parser.message).data),
        )

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp6__message__echo_request__parser__message_type(self) -> None:
        """
        Ensure the parsed message is an Icmp6MessageEchoRequest instance.

        Reference: RFC 4443 §4.1 (Echo Request type 128).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertIsInstance(
            icmp6_parser.message,
            Icmp6MessageEchoRequest,
            msg=f"Parsed message must be Icmp6MessageEchoRequest for case: {self._description}",
        )

    def test__icmp6__message__echo_request__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv6 parser advances 'packet_rx.frame' past the
        parsed Echo Request message.

        Reference: RFC 4443 §4.1 (Echo Request type 128).
        """

        Icmp6Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
