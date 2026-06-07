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
Module contains tests for the ICMPv4 Echo Request message parser.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__echo_request__parser.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import Icmp4MessageEchoRequest, Icmp4Parser, Ip4Parser, PacketRx


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
            "_description": "ICMPv4 Echo Request, empty data.",
            "_frame_rx": (
                # ICMPv4 Echo Request
                #   Type     : 8 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0xf394
                #   Id/Seq   : 12345 / 54321
                #   Data     : none
                b"\x08\x00\xf3\x94\x30\x39\xd4\x31"
            ),
            "_results": {
                "message": Icmp4MessageEchoRequest(
                    cksum=0xF394,
                    id=12345,
                    seq=54321,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 Echo Request, non-empty 16-byte data.",
            "_frame_rx": (
                # ICMPv4 Echo Request
                #   Type     : 8 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0x24be
                #   Id/Seq   : 12345 / 54321
                #   Data     : b"0123456789ABCDEF" (16 bytes)
                b"\x08\x00\x24\xbe\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "message": Icmp4MessageEchoRequest(
                    cksum=0x24BE,
                    id=12345,
                    seq=54321,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv4 Echo Request at maximum payload length (65507 bytes).",
            "_frame_rx": (
                # ICMPv4 Echo Request (at IPv4 payload maximum)
                #   Type     : 8 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0x1ecb
                #   Id/Seq   : 11111 / 22222
                #   Data     : b"X" * 65507 (IP4__PAYLOAD__MAX_LEN - ICMP4__ECHO_REQUEST__LEN)
                b"\x08\x00\x1e\xcb\x2b\x67\x56\xce"
                + b"X" * 65507
            ),
            "_results": {
                "message": Icmp4MessageEchoRequest(
                    cksum=0x1ECB,
                    id=11111,
                    seq=22222,
                    data=b"X" * 65507,
                ),
            },
        },
    ]
)
class TestIcmp4MessageEchoRequestParser(TestCase):
    """
    The ICMPv4 Echo Request message parser tests.
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

    def test__icmp4__message__echo_request__parser(self) -> None:
        """
        Ensure the ICMPv4 parser produces an Icmp4MessageEchoRequest whose
        fields match the expected reference message for each frame.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 parse).
        """

        icmp4_parser = Icmp4Parser(self._packet_rx)

        # Materialize 'data' from memoryview to bytes for structural equality.
        object.__setattr__(
            icmp4_parser.message,
            "data",
            bytes(cast(Icmp4MessageEchoRequest, icmp4_parser.message).data),
        )

        self.assertEqual(
            icmp4_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp4__message__echo_request__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv4 parser fully consumes 'packet_rx.frame' after
        parsing the Echo Request (so downstream layers see an empty remainder).

        Reference: RFC 792 (ICMPv4 Echo Request type 8 parse).
        """

        Icmp4Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
