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
Module contains tests for the unknown ICMPv4 message parser integrity checks.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__unknown__parser__integrity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import Icmp4IntegrityError, Icmp4Parser, Icmp4SanityError, Ip4Parser, PacketRx
from net_proto.protocols.icmp4.message.icmp4__message import ICMP4__HEADER__LEN


def _packet_rx_with_ip4(frame: bytes, *, ip4__payload_len: int | None = None) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub exposing only the 'payload_len'
    attribute the ICMPv4 parser reads.
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
                "ICMPv4 Unknown message, the 'ICMP4__HEADER__LEN <= self._ip4__payload_len' "
                "condition is not met (ip4_payload_len < ICMP4__HEADER__LEN)."
            ),
            "_frame_rx": (
                # ICMPv4 Unknown Message (truncated)
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0xfb-- (missing low byte)
                #   Frame len: 3 bytes (< 4-byte header minimum)
                b"\xff\x00\xfb"
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
                "ICMPv4 Unknown message, the 'self._ip4__payload_len <= len(self._frame)' "
                "condition is not met (declared IPv4 payload exceeds frame length)."
            ),
            "_frame_rx": (
                # ICMPv4 Unknown Message (truncated payload)
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0xfb94
                #   Rest     : 0x3039d4-- (missing last byte)
                #   Frame len: 7 bytes
                b"\xff\x00\xfb\x94\x30\x39\xd4"
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
            "_description": "ICMPv4 Unknown message with invalid checksum (all zeros).",
            "_frame_rx": (
                # ICMPv4 Unknown Message
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0x0000 (invalid; must be 0xfc93)
                #   Rest     : 0x3039d431
                b"\xff\x00\x00\x00\x30\x39\xd4\x31"
            ),
            "_ip4__payload_len": 8,
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestIcmp4MessageUnknownParserIntegrityChecks(TestCase):
    """
    The ICMPv4 unknown message parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _ip4__payload_len: int
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build a PacketRx with the parametrized frame and IPv4 payload length.
        """

        self._packet_rx = _packet_rx_with_ip4(self._frame_rx, ip4__payload_len=self._ip4__payload_len)

    def test__icmp4__message__unknown__parser__integrity_error(self) -> None:
        """
        Ensure the ICMPv4 parser raises Icmp4IntegrityError on malformed
        frames and reports the expected message.

        Reference: RFC 792 (4-byte common header is the structural floor for ICMPv4).
        """

        with self.assertRaises(Icmp4IntegrityError) as error:
            Icmp4Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv4] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIcmp4MessageUnknownParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ICMPv4 unknown-message integrity validator.
    """

    def test__icmp4__message__unknown__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure a frame whose IPv4 payload length equals ICMP4__HEADER__LEN (4)
        — i.e. a bare, data-less unknown header — passes integrity checks
        (the structural floor is met) and then fails sanity with
        Icmp4SanityError because the type is not host-stack-supported.

        Reference: RFC 792 (4-byte common header is the structural floor).
        Reference: RFC 1122 §3.2.2 (unknown-type ICMP — silent discard at sanity).
        """

        # ICMPv4 Unknown Message at minimum length (4 bytes)
        #   Type     : 255 (Unknown)
        #   Code     : 0
        #   Checksum : 0x00ff (valid for these four bytes)
        frame = b"\xff\x00\x00\xff"

        self.assertEqual(len(frame), ICMP4__HEADER__LEN, msg="Fixture must match ICMP4__HEADER__LEN.")

        with self.assertRaises(Icmp4SanityError):
            Icmp4Parser(_packet_rx_with_ip4(frame))

    def test__icmp4__message__unknown__parser__integrity__frame_padding_ignored(self) -> None:
        """
        Ensure trailing padding beyond 'ip4__payload_len' does not trigger the
        integrity upper-bound check — the validator caps the checksummed slice
        to the declared IPv4 payload length. The frame still trips sanity
        because the type byte (0xff) is host-stack-unknown.

        Reference: RFC 792 (checksum coverage = IP-declared payload).
        Reference: RFC 1122 §3.2.2 (unknown-type ICMP — silent discard at sanity).
        """

        # Valid 8-byte unknown ICMPv4 message (checksum 0xfc93) plus 4 bytes of
        # padding that IPv4 tells us is not part of the ICMPv4 payload.
        frame = b"\xff\x00\xfc\x93\x30\x39\xd4\x31\xde\xad\xbe\xef"

        with self.assertRaises(Icmp4SanityError):
            Icmp4Parser(_packet_rx_with_ip4(frame, ip4__payload_len=8))
