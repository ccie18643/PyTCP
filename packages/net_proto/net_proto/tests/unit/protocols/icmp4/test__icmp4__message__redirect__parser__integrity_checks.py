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
Module contains tests for the ICMPv4 Redirect message parser integrity
checks.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__redirect__parser__integrity_checks.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    Icmp4IntegrityError,
    Icmp4MessageRedirect,
    Icmp4Parser,
    Icmp4RedirectCode,
    Ip4Parser,
    PacketRx,
)
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
                "ICMPv4 Redirect, the 'ICMP4__REDIRECT__LEN <= " "ip4__payload_len' condition is not met (payload < 8)."
            ),
            "_frame_rx": (
                # ICMPv4 Redirect (truncated, only 7 bytes)
                #   Type     : 5 (Redirect)
                #   Code     : 1 (Host)
                #   Checksum : 0xffff (truncated)
                #   Gateway  : 0x0a0001-- (3 of 4 bytes; integrity violation: < 8)
                b"\x05\x01\xff\xff\x0a\x00\x01"
            ),
            "_ip4__payload_len": 7,
            "_results": {
                "error_message": (
                    "The condition 'ICMP4__REDIRECT__LEN <= ip4__payload_len "
                    "<= len(frame)' must be met. Got: ICMP4__REDIRECT__LEN=8, "
                    "ip4__payload_len=7, len(frame)=7"
                ),
            },
        },
        {
            "_description": (
                "ICMPv4 Redirect, ICMP-header-len passes outer check but "
                "fails inner Redirect-len check (payload 5, < 8)."
            ),
            "_frame_rx": (
                # ICMPv4 Redirect (5 bytes — fails 8 <= 5)
                #   Type     : 5 (Redirect)
                #   Code     : 1 (Host)
                #   Checksum : 0xffff
                #   Gateway  : 0x0a------ (1 of 4 bytes; integrity violation: < 8)
                b"\x05\x01\xff\xff\x0a"
            ),
            "_ip4__payload_len": 5,
            "_results": {
                "error_message": (
                    "The condition 'ICMP4__REDIRECT__LEN <= ip4__payload_len "
                    "<= len(frame)' must be met. Got: ICMP4__REDIRECT__LEN=8, "
                    "ip4__payload_len=5, len(frame)=5"
                ),
            },
        },
    ]
)
class TestIcmp4MessageRedirectParserIntegrityChecks(TestCase):
    """
    The ICMPv4 Redirect message parser integrity-check rejection matrix.
    """

    _description: str
    _frame_rx: bytes
    _ip4__payload_len: int
    _results: dict[str, Any]

    def test__icmp4__message__redirect__parser__integrity_error(self) -> None:
        """
        Ensure the parser raises Icmp4IntegrityError with the canonical
        formatted message when the per-message integrity preconditions
        are not met.

        Reference: RFC 792 (Redirect wire-format minimum size = 8 bytes;
        ICMP message integrity is governed by the surrounding IPv4
        payload length).
        """

        packet_rx = _packet_rx_with_ip4(self._frame_rx, ip4__payload_len=self._ip4__payload_len)

        with self.assertRaises(Icmp4IntegrityError) as error:
            Icmp4Parser(packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv4] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestIcmp4MessageRedirectParserIntegrityBoundary(TestCase):
    """
    The ICMPv4 Redirect message parser integrity-boundary tests.
    """

    def test__icmp4__message__redirect__parser__minimum_length_accepted(self) -> None:
        """
        Ensure the shortest valid Redirect frame (exactly the 8-byte
        header, no embedded data) passes every integrity check and parses.

        Reference: RFC 792 (Redirect minimum size = 8 bytes).
        """

        packet_rx = _packet_rx_with_ip4(b"\x05\x01\xef\xfd\x0a\x00\x01\x01")

        Icmp4Parser(packet_rx)

        message = cast(Icmp4MessageRedirect, packet_rx.icmp4.message)
        self.assertEqual(
            message.code,
            Icmp4RedirectCode.HOST,
            msg="Minimum-length Redirect must decode its code.",
        )
        self.assertEqual(
            message.gateway,
            Ip4Address("10.0.1.1"),
            msg="Minimum-length Redirect must decode its gateway.",
        )
