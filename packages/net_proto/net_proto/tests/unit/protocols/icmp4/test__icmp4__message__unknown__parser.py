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
Module contains tests for the ICMPv4 unknown message parser.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__unknown__parser.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_proto import (
    Icmp4Parser,
    Icmp4SanityError,
    Ip4Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip4(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub whose 'payload_len' matches
    the full frame (the only field Icmp4Parser reads off 'packet_rx.ip4').
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip4 = cast(Ip4Parser, SimpleNamespace(payload_len=len(frame)))
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv4 unknown message (type 255, code 255), 16-byte data.",
            "_frame_rx": (
                # ICMPv4 Unknown Message
                #   Type     : 255 (Unknown)
                #   Code     : 255 (Unknown)
                #   Checksum : 0x3129
                #   Data     : b"0123456789ABCDEF" (16 bytes)
                b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46"
            ),
            "_results": {
                "error_message": ("The 'type' field value must be one of [0, 3, 8, 11, 12]. Got: 255."),
            },
        },
        {
            "_description": "ICMPv4 unknown message (type 1, code 2), empty data.",
            "_frame_rx": (
                # ICMPv4 Unknown Message
                #   Type     : 1 (Unknown)
                #   Code     : 2 (Unknown)
                #   Checksum : 0xfefd
                #   Data     : none (bare 4-byte header)
                b"\x01\x02\xfe\xfd"
            ),
            "_results": {
                "error_message": ("The 'type' field value must be one of [0, 3, 8, 11, 12]. Got: 1."),
            },
        },
        {
            "_description": "ICMPv4 unknown message (type 1, code 0), maximum data (65511 bytes).",
            "_frame_rx": (
                # ICMPv4 Unknown Message (at IPv4 payload maximum)
                #   Type     : 1 (Unknown)
                #   Code     : 0
                #   Checksum : 0xf74f
                #   Data     : b"X" * 65511 (IP4__PAYLOAD__MAX_LEN - ICMP4__HEADER__LEN)
                b"\x01\x00\xf7\x4f"
                + b"X" * 65511
            ),
            "_results": {
                "error_message": ("The 'type' field value must be one of [0, 3, 8, 11, 12]. Got: 1."),
            },
        },
    ]
)
class TestIcmp4MessageUnknownParser(TestCase):
    """
    The ICMPv4 unknown-type rejection tests — RFC 1122 §3.2.2.
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

    def test__icmp4__message__unknown__parser(self) -> None:
        """
        Ensure the ICMPv4 parser rejects a frame whose 'type' is not one of
        the five host-stack-supported values (0, 3, 8, 11, 12) with
        Icmp4SanityError.

        Reference: RFC 792 (defined ICMP type numbers).
        Reference: RFC 1122 §3.2.2 (hosts MUST silently discard unknown-type ICMP).
        """

        with self.assertRaises(Icmp4SanityError) as error:
            Icmp4Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][ICMPv4] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )

    def test__icmp4__message__unknown__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv4 parser does NOT advance 'packet_rx.frame' when it
        rejects an unknown-type frame at sanity (the frame stays addressable
        to the caller for telemetry / logging).

        Reference: RFC 1122 §3.2.2 (unknown-type ICMP — silent discard).
        """

        with self.assertRaises(Icmp4SanityError):
            Icmp4Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            len(self._frame_rx),
            msg=f"Frame must remain intact after sanity rejection for case: {self._description}",
        )
