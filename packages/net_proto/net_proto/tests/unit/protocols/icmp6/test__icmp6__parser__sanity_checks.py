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
This module contains tests for the ICMPv6 packet parser sanity checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__parser__sanity_checks.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Icmp6Parser, Icmp6SanityError, Ip6Parser, PacketRx
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.tests.lib.parameterized import parameterized_class


def _with_cksum(frame_no_cksum: bytes) -> bytes:
    """
    Replace bytes [2:4] of an ICMPv6 frame with the correct one's-complement
    checksum computed over the whole frame (with bytes [2:4] zeroed,
    pshdr_sum=0).
    """

    zeroed = bytearray(frame_no_cksum)
    zeroed[2:4] = b"\x00\x00"
    cksum = inet_cksum(memoryview(bytes(zeroed)))
    out = bytearray(frame_no_cksum)
    out[2:4] = cksum.to_bytes(2, "big")
    return bytes(out)


def _packet_rx_with_ip6(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the four fields the
    ICMPv6 parser reads off 'packet_rx.ip6': dlen, pshdr_sum, src, dst, hop.

    Hop Limit = 64 (a normal forwarded value — distinct from RFC 4861's
    Hop = 255 invariant for ND, which the per-message sanity methods
    enforce separately). Source = a global unicast; destination = a global
    unicast; both unrelated to ND target semantics.
    """

    packet_rx = PacketRx(frame)
    ip6_stub = SimpleNamespace(
        dlen=len(frame),
        pshdr_sum=0,
        src=Ip6Address("2001:db8::1"),
        dst=Ip6Address("2001:db8::2"),
        hop=64,
    )
    packet_rx.ip6 = cast(Ip6Parser, ip6_stub)
    return packet_rx


# Each frame uses a code value outside the IANA-assigned set for its
# message type. Frames are sized to the minimum valid length for that
# type and carry a valid one's-complement checksum so the parser
# reaches _validate_sanity rather than bailing at _validate_integrity.

# Destination Unreachable (type=1); RFC 4443 §3.1 + RFC 7610 — codes 0..7.
# Code=8 is unassigned.
_DEST_UNREACH__UNKNOWN_CODE = _with_cksum(b"\x01\x08\x00\x00\x00\x00\x00\x00")

# Packet Too Big (type=2); RFC 4443 §3.2 — code 0 only.
# MTU field (4 bytes) follows the 4-byte header.
_PACKET_TOO_BIG__UNKNOWN_CODE = _with_cksum(b"\x02\x01\x00\x00\x00\x00\x05\xdc")

# Time Exceeded (type=3); RFC 4443 §3.3 — codes 0..1.
_TIME_EXCEEDED__UNKNOWN_CODE = _with_cksum(b"\x03\x02\x00\x00\x00\x00\x00\x00")

# Parameter Problem (type=4); RFC 4443 §3.4 codes 0..2 + RFC 7112 §3
# code 3 (Incomplete IPv6 Header Chain). Code=4 is unassigned.
# Pointer field (4 bytes) follows the 4-byte header.
_PARAM_PROBLEM__UNKNOWN_CODE = _with_cksum(b"\x04\x04\x00\x00\x00\x00\x00\x00")

# Parameter Problem (type=4) with code=3 — RFC 7112 §3 — valid; must parse.
_PARAM_PROBLEM__RFC7112_CODE = _with_cksum(b"\x04\x03\x00\x00\x00\x00\x00\x00")

# Echo Request (type=128); RFC 4443 §4.1 — code MUST be 0.
_ECHO_REQUEST__UNKNOWN_CODE = _with_cksum(b"\x80\x01\x00\x00\x30\x39\xd4\x31")

# Echo Reply (type=129); RFC 4443 §4.2 — code MUST be 0.
_ECHO_REPLY__UNKNOWN_CODE = _with_cksum(b"\x81\x01\x00\x00\x30\x39\xd4\x31")


@parameterized_class(
    [
        {
            "_description": "Destination Unreachable (type=1) with unknown code=8.",
            "_frame_rx": _DEST_UNREACH__UNKNOWN_CODE,
            "_results": {
                "error_message": (
                    "The 'code' field of the ICMPv6 Destination Unreachable "
                    "message must be one of [0, 1, 2, 3, 4, 5, 6, 7]. Got: 8."
                ),
            },
        },
        {
            "_description": "Packet Too Big (type=2) with unknown code=1.",
            "_frame_rx": _PACKET_TOO_BIG__UNKNOWN_CODE,
            "_results": {
                "error_message": (
                    "The 'code' field of the ICMPv6 Packet Too Big message " "must be one of [0]. Got: 1."
                ),
            },
        },
        {
            "_description": "Time Exceeded (type=3) with unknown code=2.",
            "_frame_rx": _TIME_EXCEEDED__UNKNOWN_CODE,
            "_results": {
                "error_message": (
                    "The 'code' field of the ICMPv6 Time Exceeded message " "must be one of [0, 1]. Got: 2."
                ),
            },
        },
        {
            "_description": "Parameter Problem (type=4) with unknown code=4.",
            "_frame_rx": _PARAM_PROBLEM__UNKNOWN_CODE,
            "_results": {
                "error_message": (
                    "The 'code' field of the ICMPv6 Parameter Problem " "message must be one of [0, 1, 2, 3]. Got: 4."
                ),
            },
        },
        {
            "_description": "Echo Request (type=128) with unknown code=1.",
            "_frame_rx": _ECHO_REQUEST__UNKNOWN_CODE,
            "_results": {
                "error_message": ("The 'code' field of the ICMPv6 Echo Request message " "must be one of [0]. Got: 1."),
            },
        },
        {
            "_description": "Echo Reply (type=129) with unknown code=1.",
            "_frame_rx": _ECHO_REPLY__UNKNOWN_CODE,
            "_results": {
                "error_message": ("The 'code' field of the ICMPv6 Echo Reply message " "must be one of [0]. Got: 1."),
            },
        },
    ]
)
class TestIcmp6ParserSanityChecks(TestCase):
    """
    The ICMPv6 packet parser sanity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx with an IPv6 stub.
        """

        self._packet_rx = _packet_rx_with_ip6(self._frame_rx)

    def test__icmp6__parser__sanity_error(self) -> None:
        """
        Ensure the ICMPv6 packet parser raises Icmp6SanityError on a frame
        whose 'code' value lies outside the IANA-assigned set for the given
        type, and reports the expected message.

        Reference: RFC 4443 §3.1 (Destination Unreachable codes 0-6).
        Reference: RFC 4443 §3.2 (Packet Too Big code 0).
        Reference: RFC 4443 §3.3 (Time Exceeded codes 0-1).
        Reference: RFC 4443 §3.4 (Parameter Problem codes 0-2).
        Reference: RFC 4443 §4.1 / §4.2 (Echo Request / Echo Reply code 0).
        Reference: RFC 7610 §5 (Destination Unreachable code 7 — Source Routing Header).
        """

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][ICMPv6] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )


class TestIcmp6ParserSanityHappyPaths(TestCase):
    """
    Happy-path sanity tests — valid frames must pass the sanity validator.
    """

    def test__icmp6__parser__sanity__pp_code_3_rfc7112_accepted(self) -> None:
        """
        Ensure a Parameter Problem with code=3 (Incomplete IPv6 Header
        Chain) parses cleanly. PyTCP accepts this code on RX per Linux
        behavior (`ICMPV6_HDR_INCOMP = 3`); it does not actively emit
        code 3 itself (Linux drops silently on reassembly failure).

        Reference: RFC 7112 §3 (Parameter Problem code 3 — IPv6 first fragment with incomplete IPv6 header chain).
        """

        packet_rx = _packet_rx_with_ip6(_PARAM_PROBLEM__RFC7112_CODE)
        parser = Icmp6Parser(packet_rx)

        self.assertEqual(
            int(parser.message.code),
            3,
            msg="PP code=3 must be exposed on the parsed message as the RFC 7112 code value.",
        )
