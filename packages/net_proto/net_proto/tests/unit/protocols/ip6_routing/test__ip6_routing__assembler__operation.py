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
This module contains tests for the IPv6 Routing assembler operation.

net_proto/tests/unit/protocols/ip6_routing/test__ip6_routing__assembler__operation.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Buffer
from net_proto.lib.enums import IpProto
from net_proto.protocols.ip6_routing.ip6_routing__assembler import (
    Ip6RoutingAssembler,
)
from net_proto.protocols.ip6_routing.ip6_routing__enums import Ip6RoutingType


class TestIp6RoutingAssemblerOperation(TestCase):
    """
    The IPv6 Routing packet assembler tests.
    """

    def test__ip6_routing__assembler__defaults_reject_misaligned(self) -> None:
        """
        Ensure constructing with no kwargs trips the alignment
        assert. The default header is 4 bytes (no data), which
        violates the 8-octet-alignment rule.

        Reference: RFC 8200 §4.4 (Routing Header total length must
                be a multiple of 8 octets).
        """

        with self.assertRaises(AssertionError):
            Ip6RoutingAssembler()

    def test__ip6_routing__assembler__minimum_8_byte_header(self) -> None:
        """
        Ensure a minimum-sized 8-byte Routing Header (4-byte fixed
        prefix + 4-byte data) assembles correctly with hdr_ext_len=0.

        Reference: RFC 8200 §4.4 (8-octet minimum total length).
        """

        asm = Ip6RoutingAssembler(
            ip6_routing__next=IpProto.TCP,
            ip6_routing__routing_type=Ip6RoutingType.RH4,
            ip6_routing__segments_left=2,
            ip6_routing__data=b"\xaa\xbb\xcc\xdd",
            ip6_routing__payload=b"",
        )

        self.assertEqual(
            asm.header.hdr_ext_len,
            0,
            msg="8-byte total RH must yield hdr_ext_len=0.",
        )

        buffers: list[Buffer] = []
        asm.assemble(buffers)
        # Routing wire frame (8 bytes, header-only):
        #   Bytes 0-3 : 06 00 04 02 -> next=TCP, hdr_ext_len=0, RH4, sl=2
        #   Bytes 4-7 : aa bb cc dd -> data
        self.assertEqual(
            b"".join(bytes(b) for b in buffers),
            b"\x06\x00\x04\x02\xaa\xbb\xcc\xdd",
            msg="Minimum-RH wire frame mismatch.",
        )

    def test__ip6_routing__assembler__rejects_non_8_aligned(self) -> None:
        """
        Ensure constructing with a data block that doesn't pad the
        header to a multiple of 8 octets trips the alignment assert.

        Reference: RFC 8200 §4.4 (8-octet alignment).
        """

        # 4-byte fixed + 2-byte data = 6 bytes total — not aligned.
        with self.assertRaises(AssertionError):
            Ip6RoutingAssembler(ip6_routing__data=b"\xaa\xbb")

    def test__ip6_routing__assembler__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble' appends three buffers in order: header,
        data, payload.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        asm = Ip6RoutingAssembler(
            ip6_routing__data=b"\xaa\xbb\xcc\xdd",
            ip6_routing__payload=b"PAYLOAD",
        )
        buffers: list[Buffer] = []
        asm.assemble(buffers)

        self.assertEqual(len(buffers), 3, msg="assemble must append exactly 3 buffers.")
        self.assertEqual(len(buffers[0]), 4, msg="First buffer is the 4-byte fixed prefix.")
        self.assertEqual(bytes(buffers[1]), b"\xaa\xbb\xcc\xdd", msg="Second buffer is the data block.")
        self.assertEqual(bytes(buffers[2]), b"PAYLOAD", msg="Third buffer is the payload.")

    def test__ip6_routing__assembler__hdr_ext_len_for_16_byte_header(self) -> None:
        """
        Ensure a 16-byte RH (4-byte prefix + 12-byte data) yields
        hdr_ext_len=1.

        Reference: RFC 8200 §4.4 (Hdr Ext Len in 8-octet units).
        """

        asm = Ip6RoutingAssembler(ip6_routing__data=b"\x00" * 12)
        self.assertEqual(
            asm.header.hdr_ext_len,
            1,
            msg="16-byte RH must yield hdr_ext_len=1.",
        )

    def test__ip6_routing__assembler__rh0_rejected(self) -> None:
        """
        Ensure constructing an Ip6RoutingAssembler with
        routing_type=RH0 raises AssertionError. The parser's
        integrity check at `Ip6RoutingParser._validate_integrity`
        already rejects inbound RH0; the assembler-side prohibition
        closes the symmetric TX gap so PyTCP itself cannot
        originate a deprecated RH0 frame.

        Reference: RFC 5095 §3 (RH0 is deprecated; MUST NOT be originated).
        """

        with self.assertRaises(AssertionError) as error:
            Ip6RoutingAssembler(
                ip6_routing__routing_type=Ip6RoutingType.RH0,
                ip6_routing__data=b"\x00" * 12,
            )

        self.assertIn(
            "MUST NOT be RH0",
            str(error.exception),
            msg="AssertionError must cite the RFC 5095 §3 RH0 prohibition.",
        )

    def test__ip6_routing__assembler__rh2_rh3_rh4_accepted(self) -> None:
        """
        Ensure constructing an Ip6RoutingAssembler with
        non-deprecated routing types (RH2 / RH3 / RH4) is
        accepted — the deprecation ban applies to RH0 only.

        Reference: RFC 5095 §3 (RH0 only; other routing types unaffected).
        """

        for routing_type in (
            Ip6RoutingType.RH2,
            Ip6RoutingType.RH3,
            Ip6RoutingType.RH4,
        ):
            with self.subTest(routing_type=routing_type):
                # Should not raise.
                Ip6RoutingAssembler(
                    ip6_routing__routing_type=routing_type,
                    ip6_routing__data=b"\x00" * 12,
                )
