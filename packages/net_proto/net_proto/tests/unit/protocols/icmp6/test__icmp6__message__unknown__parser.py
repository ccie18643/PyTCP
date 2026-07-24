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
Module contains tests for the ICMPv6 unknown message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__unknown__parser.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import Any, cast, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6Code,
    Icmp6MessageUnknown,
    Icmp6Parser,
    Icmp6Type,
    Ip6Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip6(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the attributes the
    ICMPv6 parser reads (dlen, pshdr_sum, src, dst, hop).
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame),
            payload_len=len(frame),
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
            "_description": "ICMPv6 unknown message (type 255, code 255), 16-byte data.",
            "_frame_rx": (
                # ICMPv6 Unknown Message
                #   Type     : 255 (Unknown)
                #   Code     : 255 (Unknown)
                #   Checksum : 0x3129
                #   Data     : b"0123456789ABCDEF" (16 bytes)
                b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46"
            ),
            "_results": {
                "message": Icmp6MessageUnknown(
                    type=Icmp6Type.from_int(255),
                    code=Icmp6Code.from_int(255),
                    cksum=0x3129,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv6 unknown message (type 5, code 2), empty data.",
            "_frame_rx": (
                # ICMPv6 Unknown Message
                #   Type     : 5 (Unknown; type 1 is Destination Unreachable)
                #   Code     : 2 (Unknown)
                #   Checksum : 0xfafd
                #   Data     : none (bare 4-byte header)
                b"\x05\x02\xfa\xfd"
            ),
            "_results": {
                "message": Icmp6MessageUnknown(
                    type=Icmp6Type.from_int(5),
                    code=Icmp6Code.from_int(2),
                    cksum=0xFAFD,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 unknown message (type 100, code 0), 65531-byte data (IPv6 payload maximum).",
            "_frame_rx": (
                # ICMPv6 Unknown Message (at IPv6 payload maximum)
                #   Type     : 100 (unassigned, not in Icmp6Type enum)
                #   Code     : 0
                #   Checksum : 0x20dc
                #   Data     : b"X" * 65531 (IP6__PAYLOAD__MAX_LEN - ICMP6__HEADER__LEN)
                b"\x64\x00\x20\xdc"
                + b"X" * 65531
            ),
            "_results": {
                "message": Icmp6MessageUnknown(
                    type=Icmp6Type.from_int(100),
                    code=Icmp6Code.from_int(0),
                    cksum=0x20DC,
                    data=b"X" * 65531,
                ),
            },
        },
    ]
)
class TestIcmp6MessageUnknownParser(TestCase):
    """
    The ICMPv6 unknown message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build a PacketRx for the parametrized frame.
        """

        self._packet_rx = _packet_rx_with_ip6(self._frame_rx)

    def test__icmp6__message__unknown__parser(self) -> None:
        """
        Ensure the ICMPv6 parser produces an Icmp6MessageUnknown instance
        whose fields match the expected reference message for each frame.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        # Materialize 'data' from memoryview to bytes for structural equality.
        object.__setattr__(
            icmp6_parser.message,
            "data",
            bytes(cast(Icmp6MessageUnknown, icmp6_parser.message).data),
        )

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp6__message__unknown__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv6 parser advances 'packet_rx.frame' past the
        parsed unknown message.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        Icmp6Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
