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
Module contains tests for the ICMPv6 unknown message parser integrity
checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__unknown__parser__integrity_checks.py

ver 3.0.10
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Icmp6IntegrityError, Icmp6Parser, Ip6Parser, PacketRx
from net_proto.protocols.icmp6.message.icmp6__message import ICMP6__HEADER__LEN
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip6(frame: bytes, *, ip6__dlen: int | None = None) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing only the attributes
    the ICMPv6 parser reads (dlen, pshdr_sum, src, dst, hop).
    """

    packet_rx = PacketRx(frame)
    ip6_stub = SimpleNamespace(
        dlen=len(frame) if ip6__dlen is None else ip6__dlen,
        payload_len=len(frame) if ip6__dlen is None else ip6__dlen,
        pshdr_sum=0,
        src=Ip6Address(),
        dst=Ip6Address(),
        hop=0,
    )
    packet_rx.ip = packet_rx.ip6 = cast(Ip6Parser, ip6_stub)
    return packet_rx


@parameterized_class(
    [
        {
            "_description": (
                "ICMPv6 Unknown message, the 'ICMP6__HEADER__LEN <= self._ip6__dlen' "
                "condition is not met (ip6__dlen < ICMP6__HEADER__LEN)."
            ),
            "_frame_rx": (
                # ICMPv6 Unknown Message (truncated)
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0xfb-- (missing low byte)
                #   Frame len: 3 bytes (< 4-byte header minimum)
                b"\xff\x00\xfb"
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
                "ICMPv6 Unknown message, the 'self._ip6__dlen <= len(self._frame)' "
                "condition is not met (declared IPv6 payload exceeds frame length)."
            ),
            "_frame_rx": (
                # ICMPv6 Unknown Message (truncated payload)
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0xfb94
                #   Rest     : 0x3039d4-- (missing last byte)
                #   Frame len: 7 bytes
                b"\xff\x00\xfb\x94\x30\x39\xd4"
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
            "_description": "ICMPv6 Unknown message with invalid checksum (all zeros).",
            "_frame_rx": (
                # ICMPv6 Unknown Message
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0x0000 (invalid; must be 0xfc93 with pshdr_sum=0)
                #   Rest     : 0x3039d431
                b"\xff\x00\x00\x00\x30\x39\xd4\x31"
            ),
            "_ip6__dlen": 8,
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestIcmp6MessageUnknownParserIntegrityChecks(TestCase):
    """
    The ICMPv6 unknown message parser integrity checks tests.
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

    def test__icmp6__message__unknown__parser__integrity_error(self) -> None:
        """
        Ensure the ICMPv6 parser raises Icmp6IntegrityError on malformed
        frames and reports the expected message.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        with self.assertRaises(Icmp6IntegrityError) as error:
            Icmp6Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv6] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIcmp6MessageUnknownParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ICMPv6 unknown-message integrity validator.
    """

    def test__icmp6__message__unknown__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure a frame whose IPv6 payload length equals ICMP6__HEADER__LEN (4)
        — i.e. a bare, data-less unknown header — passes integrity checks and
        yields an unknown-message parse.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        # ICMPv6 Unknown Message at minimum length (4 bytes)
        #   Type     : 255 (Unknown)
        #   Code     : 0
        #   Checksum : 0x00ff (valid for these four bytes with pshdr_sum=0)
        frame = b"\xff\x00\x00\xff"

        self.assertEqual(len(frame), ICMP6__HEADER__LEN, msg="Fixture must match ICMP6__HEADER__LEN.")

        Icmp6Parser(_packet_rx_with_ip6(frame))

    def test__icmp6__message__unknown__parser__integrity__frame_padding_ignored(self) -> None:
        """
        Ensure trailing padding beyond 'ip6__dlen' does not trigger the
        integrity upper-bound check — the validator caps the checksummed slice
        to the declared IPv6 payload length.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        # Valid 8-byte unknown ICMPv6 message (checksum 0xfc93) plus 4 bytes of
        # padding that IPv6 tells us is not part of the ICMPv6 payload.
        frame = b"\xff\x00\xfc\x93\x30\x39\xd4\x31\xde\xad\xbe\xef"

        Icmp6Parser(_packet_rx_with_ip6(frame, ip6__dlen=8))
