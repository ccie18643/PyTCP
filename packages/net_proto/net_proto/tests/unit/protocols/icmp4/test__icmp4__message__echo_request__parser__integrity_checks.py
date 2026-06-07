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
Module contains tests for the ICMPv4 Echo Request message parser integrity checks.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__echo_request__parser__integrity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_proto import Icmp4IntegrityError, Icmp4Parser, Ip4Parser, PacketRx
from net_proto.protocols.icmp4.message.icmp4__message__echo_request import (
    ICMP4__ECHO_REQUEST__LEN,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip4(frame: bytes, *, ip4__payload_len: int | None = None) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub exposing only the 'payload_len'
    attribute that Icmp4Parser reads off 'packet_rx.ip4'.
    """

    packet_rx = PacketRx(frame)
    ip4_stub = SimpleNamespace(
        payload_len=len(frame) if ip4__payload_len is None else ip4__payload_len,
    )
    packet_rx.ip4 = cast(Ip4Parser, ip4_stub)
    return packet_rx


@parameterized_class(
    [
        {
            "_description": (
                "ICMPv4 Echo Request, the 'ICMP4__HEADER__LEN <= self._ip4__payload_len' "
                "condition is not met (ip4_payload_len < ICMP4__HEADER__LEN)."
            ),
            "_frame_rx": (
                # ICMPv4 Echo Request (truncated, < 4 bytes)
                #   Type     : 8 (Echo Request)
                #   Code     : 0
                #   Checksum : 0xfb-- (missing low byte)
                #   Frame len: 3 bytes
                b"\x08\x00\xfb"
            ),
            "_ip4__payload_len": 3,
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
                "ICMPv4 Echo Request, the 'self._ip4__payload_len <= len(self._frame)' "
                "condition is not met (declared IPv4 payload exceeds frame length)."
            ),
            "_frame_rx": (
                # ICMPv4 Echo Request (frame shorter than declared ip4_payload_len)
                #   Type     : 8 (Echo Request)
                #   Code     : 0
                #   Checksum : 0xfb94
                #   Id/Seq   : 0x3039 / 0xd4-- (missing last byte)
                #   Frame len: 7 bytes
                b"\x08\x00\xfb\x94\x30\x39\xd4"
            ),
            "_ip4__payload_len": 8,
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
                "ICMPv4 Echo Request, the 'ICMP4__ECHO_REQUEST__LEN <= ip4__payload_len' "
                "condition is not met (payload shorter than the 8-byte Echo Request header)."
            ),
            "_frame_rx": (
                # ICMPv4 Echo Request (payload shorter than fixed Echo Request header)
                #   Type     : 8 (Echo Request)
                #   Code     : 0
                #   Checksum : 0xfb94
                #   Id/Seq   : 0x3039 / 0xd4-- (missing last byte)
                #   Frame len: 7 bytes
                b"\x08\x00\xfb\x94\x30\x39\xd4"
            ),
            "_ip4__payload_len": 7,
            "_results": {
                "error_message": (
                    "The condition 'ICMP4__ECHO_REQUEST__LEN <= ip4__payload_len "
                    "<= len(frame)' must be met. Got: ICMP4__ECHO_REQUEST__LEN=8, "
                    "ip4__payload_len=7, len(frame)=7"
                ),
            },
        },
        {
            "_description": "ICMPv4 Echo Request with invalid checksum (all zeros).",
            "_frame_rx": (
                # ICMPv4 Echo Request
                #   Type     : 8 (Echo Request)
                #   Code     : 0
                #   Checksum : 0x0000 (invalid; valid value would be 0xf394)
                #   Id/Seq   : 12345 / 54321
                b"\x08\x00\x00\x00\x30\x39\xd4\x31"
            ),
            "_ip4__payload_len": 8,
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestIcmp4MessageEchoRequestParserIntegrityChecks(TestCase):
    """
    The ICMPv4 Echo Request message parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _ip4__payload_len: int
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build a PacketRx with the parametrized frame and IPv4 payload length.
        """

        self._packet_rx = _packet_rx_with_ip4(self._frame_rx, ip4__payload_len=self._ip4__payload_len)

    def test__icmp4__message__echo_request__parser__integrity_error(self) -> None:
        """
        Ensure the ICMPv4 parser raises Icmp4IntegrityError on malformed
        Echo Request frames with the expected message.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 integrity).
        """

        with self.assertRaises(Icmp4IntegrityError) as error:
            Icmp4Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv4] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIcmp4MessageEchoRequestParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ICMPv4 Echo Request integrity validator.
    """

    def test__icmp4__message__echo_request__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure a frame whose IPv4 payload length equals ICMP4__ECHO_REQUEST__LEN
        (8) — a bare, data-less Echo Request — passes integrity checks and
        parses successfully.

        Reference: RFC 792 (ICMPv4 Echo Request type 8 integrity).
        """

        # ICMPv4 Echo Request at minimum length (8 bytes)
        #   Type     : 8 (Echo Request)
        #   Code     : 0 (Default)
        #   Checksum : 0xf394
        #   Id/Seq   : 12345 / 54321
        frame = b"\x08\x00\xf3\x94\x30\x39\xd4\x31"

        self.assertEqual(len(frame), ICMP4__ECHO_REQUEST__LEN, msg="Fixture must match ICMP4__ECHO_REQUEST__LEN.")

        Icmp4Parser(_packet_rx_with_ip4(frame))
