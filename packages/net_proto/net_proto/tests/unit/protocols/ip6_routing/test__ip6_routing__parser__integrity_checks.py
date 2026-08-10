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
This module contains the IPv6 Routing parser integrity-check tests.

net_proto/tests/unit/protocols/ip6_routing/test__ip6_routing__parser__integrity_checks.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ip6_routing.ip6_routing__errors import (
    Ip6RoutingIntegrityError,
)
from net_proto.protocols.ip6_routing.ip6_routing__parser import Ip6RoutingParser


class TestIp6RoutingParserIntegrity(TestCase):
    """
    The IPv6 Routing parser integrity-check tests.
    """

    def test__ip6_routing__parser__integrity__rejects_truncated_below_prefix(self) -> None:
        """
        Ensure a frame smaller than the 4-byte fixed prefix is
        rejected with 'Ip6RoutingIntegrityError'.

        Reference: RFC 8200 §4.4 (Routing Header fixed 4-byte prefix).
        """

        with self.assertRaises(Ip6RoutingIntegrityError):
            Ip6RoutingParser(PacketRx(b"\x06\x00\x04"))

    def test__ip6_routing__parser__integrity__rejects_hdr_ext_len_overrun(self) -> None:
        """
        Ensure a frame whose declared 'hdr_ext_len' demands more
        bytes than the buffer provides is rejected.

        Reference: RFC 8200 §4.4 (total Routing = (Hdr Ext Len + 1) * 8).
        """

        # Routing wire frame (4 bytes):
        #   Byte 0 : 0x06 -> next=TCP
        #   Byte 1 : 0x05 -> hdr_ext_len=5 ((5+1)*8 = 48 bytes claimed)
        #   Byte 2 : 0x04 -> routing_type=RH4
        #   Byte 3 : 0x02 -> segments_left=2
        # Buffer has only 4 bytes — overrun.
        with self.assertRaises(Ip6RoutingIntegrityError):
            Ip6RoutingParser(PacketRx(b"\x06\x05\x04\x02"))

    def test__ip6_routing__parser__integrity__rh0_hard_drop(self) -> None:
        """
        Ensure receipt of routing_type=0 (RH0) is hard-dropped with
        'Ip6RoutingIntegrityError' carrying the canonical pointer
        offset (2, the position of the Routing Type byte within the
        Routing Header). The chain-walker dispatch in Phase 8 reads
        this pointer and emits ICMPv6 Parameter Problem code 0.

        Reference: RFC 5095 §3 (Type 0 Routing Header deprecation,
                hard-drop with Param Problem code 0).
        """

        # Routing wire frame (8 bytes, header-only):
        #   Byte 0    : 0x06 -> next=TCP
        #   Byte 1    : 0x00 -> hdr_ext_len=0 (8-byte total)
        #   Byte 2    : 0x00 -> routing_type=RH0 (DEPRECATED)
        #   Byte 3    : 0x02 -> segments_left=2
        #   Bytes 4-7 : 00 00 00 00 -> reserved
        with self.assertRaises(Ip6RoutingIntegrityError) as ctx:
            Ip6RoutingParser(PacketRx(b"\x06\x00\x00\x02\x00\x00\x00\x00"))

        self.assertEqual(
            ctx.exception.pointer,
            2,
            msg="RH0 hard-drop pointer must equal 2 (Routing Type offset within RH).",
        )
        self.assertIn(
            "RFC 5095 §3",
            str(ctx.exception),
            msg="RH0 hard-drop error message must cite RFC 5095 §3.",
        )

    def test__ip6_routing__parser__integrity__error_message_carries_proto_tag(self) -> None:
        """
        Ensure the raised error message starts with the canonical
        '[INTEGRITY ERROR][IPv6 Routing]' prefix.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip6RoutingIntegrityError) as ctx:
            Ip6RoutingParser(PacketRx(b"\x06"))
        self.assertIn(
            "[INTEGRITY ERROR][IPv6 Routing]",
            str(ctx.exception),
            msg="Ip6RoutingIntegrityError must carry canonical [INTEGRITY ERROR][IPv6 Routing] prefix.",
        )

    def test__ip6_routing__parser__integrity__rh4_accepted(self) -> None:
        """
        Ensure a Type 4 (Segment Routing) Routing Header parses
        cleanly — non-RH0 types are not rejected at the integrity
        layer.

        Reference: RFC 8200 §4.4 (non-RH0 routing types pass through).
        """

        # Routing wire frame (8 bytes):
        #   Bytes 0-3 : 06 00 04 02 -> next=TCP, hdr_ext_len=0, RH4, sl=2
        #   Bytes 4-7 : aa bb cc dd -> type-specific data
        parser = Ip6RoutingParser(PacketRx(b"\x06\x00\x04\x02\xaa\xbb\xcc\xdd"))
        self.assertEqual(parser.segments_left, 2, msg="RH4 segments_left must round-trip.")
        self.assertEqual(parser.data, b"\xaa\xbb\xcc\xdd", msg="RH4 data must round-trip byte-for-byte.")
