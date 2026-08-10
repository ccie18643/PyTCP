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
Module contains tests for the ICMPv6 Echo Request message parser
integrity checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__echo_request__parser__integrity_checks.py

ver 3.0.10
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    ICMP6__ECHO_REQUEST__LEN,
    Icmp6IntegrityError,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip6(frame: bytes, *, ip6__dlen: int | None = None) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the attributes the
    ICMPv6 parser reads off 'packet_rx.ip6' (dlen, pshdr_sum, src, dst, hop).
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame) if ip6__dlen is None else ip6__dlen,
            payload_len=len(frame) if ip6__dlen is None else ip6__dlen,
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
            "_description": (
                "ICMPv6 Echo Request, the 'ICMP6__HEADER__LEN <= self._ip6__dlen' "
                "condition is not met (ip6__dlen < ICMP6__HEADER__LEN)."
            ),
            "_frame_rx": (
                # ICMPv6 Echo Request (truncated, < 4 bytes)
                #   Type     : 128 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0xfb-- (missing low byte)
                #   Frame len: 3 bytes
                b"\x80\x00\xfb"
            ),
            "_ip6__dlen": 3,
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
                "ICMPv6 Echo Request, the 'self._ip6__dlen <= len(self._frame)' "
                "condition is not met (declared IPv6 payload exceeds frame length)."
            ),
            "_frame_rx": (
                # ICMPv6 Echo Request (frame shorter than declared ip6__dlen)
                #   Type     : 128 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0xfb94
                #   Id       : 0x3039 (partial, high word of body)
                #   Seq      : 0xd4-- (missing last byte)
                #   Frame len: 7 bytes
                b"\x80\x00\xfb\x94\x30\x39\xd4"
            ),
            "_ip6__dlen": 8,
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
                "ICMPv6 Echo Request, the 'ICMP6__ECHO_REQUEST__LEN <= ip6__dlen' "
                "condition is not met (payload shorter than the 8-byte header)."
            ),
            "_frame_rx": (
                # ICMPv6 Echo Request (payload shorter than fixed header)
                #   Type     : 128 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0xfb94
                #   Id       : 0x3039
                #   Seq      : 0xd4-- (missing last byte)
                #   Frame len: 7 bytes
                b"\x80\x00\xfb\x94\x30\x39\xd4"
            ),
            "_ip6__dlen": 7,
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__ECHO_REQUEST__LEN <= ip6__dlen "
                    "<= len(frame)' must be met. Got: ICMP6__ECHO_REQUEST__LEN=8, "
                    "ip6__dlen=7, len(frame)=7"
                ),
            },
        },
        {
            "_description": "ICMPv6 Echo Request with invalid checksum (all zeros).",
            "_frame_rx": (
                # ICMPv6 Echo Request
                #   Type     : 128 (Echo Request)
                #   Code     : 0 (Default)
                #   Checksum : 0x0000 (invalid; valid value with pshdr_sum=0 is 0x7b94)
                #   Id       : 0x3039
                #   Seq      : 0xd431
                b"\x80\x00\x00\x00\x30\x39\xd4\x31"
            ),
            "_ip6__dlen": 8,
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestIcmp6MessageEchoRequestParserIntegrityChecks(TestCase):
    """
    The ICMPv6 Echo Request message parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _ip6__dlen: int
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build a PacketRx with the parametrized frame and IPv6 payload length.
        """

        self._packet_rx = _packet_rx_with_ip6(self._frame_rx, ip6__dlen=self._ip6__dlen)

    def test__icmp6__message__echo_request__parser__integrity_error(self) -> None:
        """
        Ensure the ICMPv6 parser raises Icmp6IntegrityError on malformed
        Echo Request frames with the expected message.

        Reference: RFC 4443 §4.1 (Echo Request type 128).
        """

        with self.assertRaises(Icmp6IntegrityError) as error:
            Icmp6Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv6] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIcmp6MessageEchoRequestParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ICMPv6 Echo Request integrity validator.
    """

    def test__icmp6__message__echo_request__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure a frame whose IPv6 payload length equals
        ICMP6__ECHO_REQUEST__LEN (8) — a bare, data-less Echo Request —
        passes integrity checks and parses successfully.

        Reference: RFC 4443 §4.1 (Echo Request type 128).
        """

        # ICMPv6 Echo Request at minimum length (8 bytes)
        #   Type     : 128 (Echo Request)
        #   Code     : 0 (Default)
        #   Checksum : 0x7fff (valid with pshdr_sum=0)
        #   Id       : 0x0000
        #   Seq      : 0x0000
        frame = b"\x80\x00\x7f\xff\x00\x00\x00\x00"

        self.assertEqual(
            len(frame),
            ICMP6__ECHO_REQUEST__LEN,
            msg="Fixture must match ICMP6__ECHO_REQUEST__LEN.",
        )

        Icmp6Parser(_packet_rx_with_ip6(frame))

    def test__icmp6__message__echo_request__parser__integrity__trailing_bytes_accepted(self) -> None:
        """
        Ensure a frame whose raw length exceeds 'ip6__dlen' (the ICMPv6
        message is followed by lower-layer padding) still parses: the
        integrity bound is 'ip6__dlen <= len(frame)', so trailing bytes
        beyond the declared IPv6 payload are tolerated, not rejected.

        Reference: RFC 4443 §4.1 (Echo Request type 128).
        """

        # Minimum 8-byte Echo Request (valid checksum over the 8 octets)
        # followed by 4 octets of lower-layer padding. ip6__dlen=8 is
        # strictly less than len(frame)=12.
        frame = b"\x80\x00\x7f\xff\x00\x00\x00\x00" + b"\x00\x00\x00\x00"

        Icmp6Parser(_packet_rx_with_ip6(frame, ip6__dlen=ICMP6__ECHO_REQUEST__LEN))
