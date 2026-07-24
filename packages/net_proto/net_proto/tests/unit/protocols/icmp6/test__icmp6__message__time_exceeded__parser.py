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
Module contains tests for the ICMPv6 Time Exceeded message parser
operation.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__time_exceeded__parser.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6MessageTimeExceeded,
    Icmp6Parser,
    Icmp6TimeExceededCode,
    Ip6Parser,
    PacketRx,
)
from net_proto.tests.lib.parameterized import parameterized_class


def _packet_rx_with_ip6(frame: bytes, *, ip6__dlen: int | None = None) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the four
    attributes Icmp6Parser reads off 'packet_rx.ip6'. 'ip6__dlen' defaults
    to the full frame length, or is overridden to model a frame followed
    by lower-layer padding.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame) if ip6__dlen is None else ip6__dlen,
            hop=64,
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
            pshdr_sum=0,
        ),
    )
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Time Exceeded, code 0 (Hop Limit Exceeded In Transit), no data.",
            "_code": Icmp6TimeExceededCode.HOP_LIMIT_EXCEEDED_IN_TRANSIT,
        },
        {
            "_description": "ICMPv6 Time Exceeded, code 1 (Fragment Reassembly Time Exceeded), no data.",
            "_code": Icmp6TimeExceededCode.FRAGMENT_REASSEMBLY_TIME_EXCEEDED,
        },
    ]
)
class TestIcmp6MessageTimeExceededParser(TestCase):
    """
    The ICMPv6 Time Exceeded message parser-operation tests.
    """

    _description: str
    _code: Icmp6TimeExceededCode

    def test__icmp6__message__time_exceeded__parser__dispatches_to_time_exceeded(
        self,
    ) -> None:
        """
        Ensure that an inbound frame whose ICMPv6 type byte is 3 routes
        through Icmp6Parser to an Icmp6MessageTimeExceeded instance —
        not to Icmp6MessageUnknown. Closes the silent-drop gap on
        ICMPv6 Time Exceeded.

        Reference: RFC 4443 §3.3 (Time Exceeded type 3).
        Reference: RFC 1122 §3.2.2.4 (incoming Time Exceeded MUST be
        passed to transport — applies symmetrically to v6 via
        RFC 4443 mapping).
        """

        # Build a wire frame using the Assembler so the cksum field
        # carries a syntactically-valid value (the parser itself does
        # not verify ICMPv6 cksum without a pseudo-header).
        from net_proto.protocols.icmp6.icmp6__assembler import Icmp6Assembler  # noqa: PLC0415

        asm = Icmp6Assembler(icmp6__message=Icmp6MessageTimeExceeded(code=self._code, data=b""))
        frame = bytes(asm)

        packet_rx = _packet_rx_with_ip6(frame)

        Icmp6Parser(packet_rx)

        self.assertIsInstance(
            packet_rx.icmp6.message,
            Icmp6MessageTimeExceeded,
            msg=f"Type-3 frame must route to Icmp6MessageTimeExceeded for case: {self._description}",
        )
        self.assertEqual(
            cast(Any, packet_rx.icmp6.message).code,
            self._code,
            msg=f"Decoded code must round-trip for case: {self._description}",
        )


class TestIcmp6MessageTimeExceededParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ICMPv6 Time Exceeded integrity validator.
    """

    def test__icmp6__message__time_exceeded__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure the shortest valid Time Exceeded frame (exactly 8 bytes —
        type, code, checksum, unused) parses without raising an integrity
        error.

        Reference: RFC 4443 §3.3 (Time Exceeded type 3).
        """

        # ICMPv6 Time Exceeded at minimum length (8 bytes, valid cksum)
        frame = b"\x03\x00\xfc\xff\x00\x00\x00\x00"

        Icmp6Parser(_packet_rx_with_ip6(frame))

    def test__icmp6__message__time_exceeded__parser__integrity__trailing_bytes_accepted(self) -> None:
        """
        Ensure a frame whose raw length exceeds 'ip6__dlen' (the ICMPv6
        message is followed by lower-layer padding) still parses: the
        integrity bound is 'ip6__dlen <= len(frame)', so trailing bytes
        beyond the declared IPv6 payload are tolerated, not rejected.

        Reference: RFC 4443 §3.3 (Time Exceeded type 3).
        """

        # Minimum 8-byte Time Exceeded (valid checksum over the 8 octets)
        # followed by 4 octets of lower-layer padding. ip6__dlen=8 is
        # strictly less than len(frame)=12.
        frame = b"\x03\x00\xfc\xff\x00\x00\x00\x00" + b"\x00\x00\x00\x00"

        Icmp6Parser(_packet_rx_with_ip6(frame, ip6__dlen=8))
