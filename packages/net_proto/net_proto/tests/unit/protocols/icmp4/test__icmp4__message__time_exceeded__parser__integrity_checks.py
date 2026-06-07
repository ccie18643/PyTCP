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
Module contains tests for the ICMPv4 Time Exceeded message parser
integrity checks.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__time_exceeded__parser__integrity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from net_proto import Icmp4IntegrityError, Icmp4Parser, Ip4Parser, PacketRx
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip4(frame: bytes, *, ip4__payload_len: int | None = None) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub exposing only the
    'payload_len' attribute that Icmp4Parser reads off 'packet_rx.ip4'.
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
                "ICMPv4 Time Exceeded, the 'ICMP4__TIME_EXCEEDED__LEN <= "
                "ip4__payload_len' condition is not met (payload < 8)."
            ),
            "_frame_rx": (
                # ICMPv4 Time Exceeded (truncated, only 7 bytes)
                #   Type     : 11 (Time Exceeded)
                #   Code     : 0 (TTL Exceeded in Transit)
                #   Checksum : 0xf4ff (truncated, missing one byte)
                #   Rest     : 0x000000-- (3 of 4 bytes; integrity violation: < 8)
                b"\x0b\x00\xf4\xff\x00\x00\x00"
            ),
            "_ip4__payload_len": 7,
            "_results": {
                "error_message": (
                    "The condition 'ICMP4__TIME_EXCEEDED__LEN <= ip4__payload_len "
                    "<= len(frame)' must be met. Got: ICMP4__TIME_EXCEEDED__LEN=8, "
                    "ip4__payload_len=7, len(frame)=7"
                ),
            },
        },
        {
            "_description": (
                "ICMPv4 Time Exceeded, ICMP-header-len passes outer check but "
                "fails inner Time-Exceeded-len check (payload < 8 ≤ HEADER_LEN<=4)."
            ),
            "_frame_rx": (
                # ICMPv4 Time Exceeded (5 bytes — passes outer 4<=5 but fails inner 8>5)
                #   Type     : 11 (Time Exceeded)
                #   Code     : 0
                #   Checksum : 0xf4ff
                #   Rest     : 0x-- (1 of 4 bytes; integrity violation: < 8)
                b"\x0b\x00\xf4\xff\x00"
            ),
            "_ip4__payload_len": 5,
            "_results": {
                "error_message": (
                    "The condition 'ICMP4__TIME_EXCEEDED__LEN <= ip4__payload_len "
                    "<= len(frame)' must be met. Got: ICMP4__TIME_EXCEEDED__LEN=8, "
                    "ip4__payload_len=5, len(frame)=5"
                ),
            },
        },
    ]
)
class TestIcmp4MessageTimeExceededParserIntegrityChecks(TestCase):
    """
    The ICMPv4 Time Exceeded message parser integrity-check rejection
    matrix.
    """

    _description: str
    _frame_rx: bytes
    _ip4__payload_len: int
    _results: dict[str, Any]

    def test__icmp4__message__time_exceeded__parser__integrity_error(self) -> None:
        """
        Ensure the parser raises Icmp4IntegrityError with the canonical
        formatted message when the per-message integrity preconditions
        are not met.

        Reference: RFC 792 (Time Exceeded wire-format minimum size = 8
        bytes; ICMP message integrity is governed by the surrounding
        IPv4 payload length).
        """

        packet_rx = _packet_rx_with_ip4(self._frame_rx, ip4__payload_len=self._ip4__payload_len)

        with self.assertRaises(Icmp4IntegrityError) as error:
            Icmp4Parser(packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv4] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIcmp4MessageTimeExceededParserIntegrityBoundary(TestCase):
    """
    The ICMPv4 Time Exceeded message parser integrity-boundary tests.
    Pin the smallest frame that passes every integrity check so a future
    tightening of the bounds is caught immediately.
    """

    def test__icmp4__message__time_exceeded__parser__integrity__minimum_length_accepted(
        self,
    ) -> None:
        """
        Ensure the shortest valid Time Exceeded frame (exactly
        ICMP4__TIME_EXCEEDED__LEN = 8 bytes) parses without raising an
        integrity error.

        Reference: RFC 792 (Time Exceeded wire-format minimum size = 8
        bytes).
        """

        # ICMPv4 Time Exceeded (minimum, code=0, no data, valid cksum)
        #   Type     : 11
        #   Code     : 0
        #   Checksum : 0xf4ff (computed for type=11, code=0, rest=0)
        #   Rest     : 0x00000000
        frame = b"\x0b\x00\xf4\xff\x00\x00\x00\x00"
        packet_rx = _packet_rx_with_ip4(frame)

        Icmp4Parser(packet_rx)
