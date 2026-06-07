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
This module contains tests for the ICMPv4 packet parser sanity checks.

net_proto/tests/unit/protocols/icmp4/test__icmp4__parser__sanity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import Icmp4Parser, Icmp4SanityError, Ip4Parser, PacketRx
from net_proto.lib.inet_cksum import inet_cksum


def _with_cksum(frame_no_cksum: bytes) -> bytes:
    """
    Replace bytes [2:4] of an ICMPv4 frame with the correct one's-complement
    checksum computed over the whole frame (with bytes [2:4] zeroed).
    """

    zeroed = bytearray(frame_no_cksum)
    zeroed[2:4] = b"\x00\x00"
    cksum = inet_cksum(memoryview(bytes(zeroed)))
    out = bytearray(frame_no_cksum)
    out[2:4] = cksum.to_bytes(2, "big")
    return bytes(out)


def _packet_rx_with_ip4(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub exposing only the 'payload_len'
    attribute that Icmp4Parser reads off 'packet_rx.ip4'.
    """

    packet_rx = PacketRx(frame)
    ip4_stub = SimpleNamespace(payload_len=len(frame))
    packet_rx.ip4 = cast(Ip4Parser, ip4_stub)
    return packet_rx


# Each frame below uses a code value (or type value, for the unknown-type
# case) that the ICMPv4 protocol does NOT define for the message type.
# Frames are sized to the minimum valid message length for that type and
# carry a valid one's-complement checksum so the parser reaches
# _validate_sanity rather than bailing at _validate_integrity.

# Echo Request (type=8); RFC 792 — code MUST be 0.
_ECHO_REQUEST__UNKNOWN_CODE = _with_cksum(b"\x08\x01\x00\x00\x30\x39\xd4\x31")

# Echo Reply (type=0); RFC 792 — code MUST be 0.
_ECHO_REPLY__UNKNOWN_CODE = _with_cksum(b"\x00\x01\x00\x00\x30\x39\xd4\x31")

# Destination Unreachable (type=3); RFC 792 + 1122 + 1812 — codes 0..15
# defined. Code=16 is outside the assigned IANA range.
_DEST_UNREACH__UNKNOWN_CODE = _with_cksum(b"\x03\x10\x00\x00\x00\x00\x00\x00")

# Time Exceeded (type=11); RFC 792 — codes 0..1 defined.
_TIME_EXCEEDED__UNKNOWN_CODE = _with_cksum(b"\x0b\x02\x00\x00\x00\x00\x00\x00")

# Parameter Problem (type=12); RFC 792 + RFC 1122 — codes 0..2 defined.
_PARAM_PROBLEM__UNKNOWN_CODE = _with_cksum(b"\x0c\x03\x00\x00\x00\x00\x00\x00")

# Unknown ICMPv4 type (RFC 792 §"ICMP Type Numbers" defines specific
# types; everything else is unassigned/deprecated). RFC 1122 §3.2.2
# says hosts MUST silently discard unknown-type ICMP messages.
# Source Quench (type=4) is the canonical example — RFC 6633 §3
# explicitly deprecates it.
_UNKNOWN_TYPE = _with_cksum(b"\x04\x00\x00\x00\x00\x00\x00\x00")


@parameterized_class(
    [
        {
            "_description": "Echo Request (type=8) with unknown code=1.",
            "_frame_rx": _ECHO_REQUEST__UNKNOWN_CODE,
            "_results": {
                "error_message": ("The 'code' field of the ICMPv4 Echo Request message must " "be one of [0]. Got: 1."),
            },
        },
        {
            "_description": "Echo Reply (type=0) with unknown code=1.",
            "_frame_rx": _ECHO_REPLY__UNKNOWN_CODE,
            "_results": {
                "error_message": ("The 'code' field of the ICMPv4 Echo Reply message must " "be one of [0]. Got: 1."),
            },
        },
        {
            "_description": "Destination Unreachable (type=3) with unknown code=16.",
            "_frame_rx": _DEST_UNREACH__UNKNOWN_CODE,
            "_results": {
                "error_message": (
                    "The 'code' field of the ICMPv4 Destination Unreachable "
                    "message must be one of [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, "
                    "10, 11, 12, 13, 14, 15]. Got: 16."
                ),
            },
        },
        {
            "_description": "Time Exceeded (type=11) with unknown code=2.",
            "_frame_rx": _TIME_EXCEEDED__UNKNOWN_CODE,
            "_results": {
                "error_message": (
                    "The 'code' field of the ICMPv4 Time Exceeded message " "must be one of [0, 1]. Got: 2."
                ),
            },
        },
        {
            "_description": "Parameter Problem (type=12) with unknown code=3.",
            "_frame_rx": _PARAM_PROBLEM__UNKNOWN_CODE,
            "_results": {
                "error_message": (
                    "The 'code' field of the ICMPv4 Parameter Problem " "message must be one of [0, 1, 2]. Got: 3."
                ),
            },
        },
        {
            "_description": "Unknown ICMPv4 type (Source Quench, type=4).",
            "_frame_rx": _UNKNOWN_TYPE,
            "_results": {
                "error_message": ("The 'type' field value must be one of [0, 3, 8, 11, 12]. " "Got: 4."),
            },
        },
    ]
)
class TestIcmp4ParserSanityChecks(TestCase):
    """
    The ICMPv4 packet parser sanity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx with the IPv4 payload-length
        stub the parser reads.
        """

        self._packet_rx = _packet_rx_with_ip4(self._frame_rx)

    def test__icmp4__parser__sanity_error(self) -> None:
        """
        Ensure the ICMPv4 packet parser raises Icmp4SanityError on a frame
        whose 'type' or 'code' value lies outside the IANA-assigned set, and
        reports the expected message.

        Reference: RFC 792 (ICMP message type and code definitions).
        Reference: RFC 1122 §3.2.2 (hosts MUST silently discard unknown-type ICMP).
        Reference: RFC 1812 §5.2.7.1 (additional Destination Unreachable codes 13-15).
        Reference: RFC 6633 §3 (Source Quench type 4 is deprecated — falls into the unknown-type path).
        """

        with self.assertRaises(Icmp4SanityError) as error:
            Icmp4Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][ICMPv4] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )
