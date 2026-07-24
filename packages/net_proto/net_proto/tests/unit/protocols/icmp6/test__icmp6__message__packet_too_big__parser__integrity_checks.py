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
Module contains tests for the ICMPv6 Packet Too Big parser integrity bounds.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__packet_too_big__parser__integrity_checks.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import cast
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import ICMP6__PACKET_TOO_BIG__LEN, Icmp6Parser, Ip6Parser, PacketRx


def _packet_rx_with_ip6(frame: bytes, *, ip6__dlen: int | None = None) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the attributes the
    ICMPv6 parser reads off 'packet_rx.ip6'. 'ip6__dlen' defaults to the
    full frame length, or is overridden to model a frame followed by
    lower-layer padding.
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


class TestIcmp6MessagePacketTooBigParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ICMPv6 Packet Too Big integrity validator. The
    Packet Too Big message has no other parser test, so these pin its
    'ICMP6__PACKET_TOO_BIG__LEN <= ip6__dlen <= len(frame)' integrity
    bound at both ends.
    """

    def test__icmp6__message__packet_too_big__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure the shortest valid Packet Too Big frame (exactly 8 bytes —
        type, code, checksum, MTU) parses without raising an integrity
        error.

        Reference: RFC 4443 §3.2 (Packet Too Big type 2).
        """

        # ICMPv6 Packet Too Big at minimum length (8 bytes, valid cksum,
        # MTU=1280).
        frame = b"\x02\x00\xf8\xff\x00\x00\x05\x00"

        self.assertEqual(
            len(frame),
            ICMP6__PACKET_TOO_BIG__LEN,
            msg="Fixture must match ICMP6__PACKET_TOO_BIG__LEN.",
        )

        Icmp6Parser(_packet_rx_with_ip6(frame))

    def test__icmp6__message__packet_too_big__parser__integrity__trailing_bytes_accepted(self) -> None:
        """
        Ensure a frame whose raw length exceeds 'ip6__dlen' (the ICMPv6
        message is followed by lower-layer padding) still parses: the
        integrity bound is 'ip6__dlen <= len(frame)', so trailing bytes
        beyond the declared IPv6 payload are tolerated, not rejected.

        Reference: RFC 4443 §3.2 (Packet Too Big type 2).
        """

        # Minimum 8-byte Packet Too Big (valid checksum over the 8 octets)
        # followed by 4 octets of lower-layer padding. ip6__dlen=8 is
        # strictly less than len(frame)=12.
        frame = b"\x02\x00\xf8\xff\x00\x00\x05\x00" + b"\x00\x00\x00\x00"

        Icmp6Parser(_packet_rx_with_ip6(frame, ip6__dlen=ICMP6__PACKET_TOO_BIG__LEN))
