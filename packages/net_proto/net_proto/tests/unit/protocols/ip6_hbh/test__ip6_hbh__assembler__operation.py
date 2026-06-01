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
This module contains tests for the IPv6 HBH packet assembler operation.

net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__assembler__operation.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto.lib.buffer import Buffer
from net_proto.lib.enums import IpProto
from net_proto.protocols.ip6_hbh.ip6_hbh__assembler import Ip6HbhAssembler
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__pad1 import (
    Ip6HbhOptionPad1,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__padn import (
    Ip6HbhOptionPadN,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions


class TestIp6HbhAssemblerOperation(TestCase):
    """
    The IPv6 HBH packet assembler happy-path tests.
    """

    def test__ip6_hbh__assembler__defaults(self) -> None:
        """
        Ensure constructing 'Ip6HbhAssembler' with no kwargs trips
        the alignment assert. With completely empty options the
        header would be 2 bytes, which violates the 8-octet
        alignment requirement — a default construction with no
        options is intentionally invalid until the caller pads.

        Reference: RFC 8200 §4.3 (HBH header total length must be
                multiple of 8 octets).
        """

        # Default construction (no options) violates 8-octet
        # alignment; assert must fire.
        with self.assertRaises(AssertionError):
            Ip6HbhAssembler()

    def test__ip6_hbh__assembler__minimum_padding(self) -> None:
        """
        Ensure a minimum-sized HBH (8-octet total: 2-byte fixed
        prefix + 6 bytes of PadN data) assembles to the expected
        wire frame with hdr_ext_len=0.

        Reference: RFC 8200 §4.3 (HBH header total length).
        """

        opts = Ip6HbhOptions(Ip6HbhOptionPadN(b"\x00\x00\x00\x00"))
        asm = Ip6HbhAssembler(
            ip6_hbh__next=IpProto.TCP,
            ip6_hbh__options=opts,
            ip6_hbh__payload=b"",
        )

        self.assertEqual(
            asm.header.hdr_ext_len,
            0,
            msg="8-byte total HBH must yield hdr_ext_len=0 (RFC 8200 §4.3).",
        )

        buffers: list[Buffer] = []
        asm.assemble(buffers)
        # HBH wire frame (8 bytes, header-only):
        #   Bytes 0-1 : 06 00       -> next=TCP, hdr_ext_len=0
        #   Bytes 2-7 : 01 04 00 00 00 00 -> PadN(4) data zero-zero-zero-zero
        self.assertEqual(
            b"".join(bytes(b) for b in buffers),
            b"\x06\x00\x01\x04\x00\x00\x00\x00",
            msg="Minimum-padding HBH must produce the canonical 8-byte wire frame.",
        )

    def test__ip6_hbh__assembler__pad1_only_block(self) -> None:
        """
        Ensure an HBH using only Pad1's to fill the 6-byte options
        slot (six 0x00 bytes) assembles cleanly with hdr_ext_len=0.

        Reference: RFC 8200 §4.2 (Pad1 option, single 0x00 byte).
        """

        opts = Ip6HbhOptions(*[Ip6HbhOptionPad1() for _ in range(6)])
        asm = Ip6HbhAssembler(
            ip6_hbh__next=IpProto.UDP,
            ip6_hbh__options=opts,
            ip6_hbh__payload=b"",
        )
        buffers: list[Buffer] = []
        asm.assemble(buffers)
        # HBH wire frame (8 bytes):
        #   Bytes 0-1 : 11 00       -> next=UDP, hdr_ext_len=0
        #   Bytes 2-7 : 00 00 00 00 00 00 -> six Pad1's
        self.assertEqual(
            b"".join(bytes(b) for b in buffers),
            b"\x11\x00\x00\x00\x00\x00\x00\x00",
            msg="Six-Pad1 HBH must produce the canonical 8-byte wire frame.",
        )

    def test__ip6_hbh__assembler__rejects_non_8_aligned_options(self) -> None:
        """
        Ensure constructing the assembler with options whose total
        length plus the 2-byte prefix is not a multiple of 8 octets
        trips the alignment assert.

        Reference: RFC 8200 §4.3 (HBH header total length must be
                multiple of 8 octets).
        """

        # PadN(2) is 4 bytes total; with the 2-byte prefix the
        # total would be 6 bytes — not a multiple of 8.
        opts = Ip6HbhOptions(Ip6HbhOptionPadN(b"\x00\x00"))
        with self.assertRaises(AssertionError):
            Ip6HbhAssembler(ip6_hbh__options=opts)

    def test__ip6_hbh__assembler__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble' appends exactly three buffers in order:
        the fixed-prefix header, the options block, the payload.
        Downstream code relies on positional indexing of the
        emitted buffer list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opts = Ip6HbhOptions(Ip6HbhOptionPadN(b"\x00\x00\x00\x00"))
        asm = Ip6HbhAssembler(
            ip6_hbh__next=IpProto.TCP,
            ip6_hbh__options=opts,
            ip6_hbh__payload=b"PAYLOAD",
        )
        buffers: list[Buffer] = []
        asm.assemble(buffers)

        self.assertEqual(len(buffers), 3, msg="assemble must append exactly 3 buffers.")
        self.assertEqual(len(buffers[0]), 2, msg="First buffer is the 2-byte HBH prefix.")
        self.assertEqual(len(buffers[1]), 6, msg="Second buffer is the options block.")
        self.assertEqual(bytes(buffers[2]), b"PAYLOAD", msg="Third buffer is the payload.")

    def test__ip6_hbh__assembler__hdr_ext_len_for_16_byte_header(self) -> None:
        """
        Ensure a 16-byte HBH (2-byte prefix + 14-byte options)
        produces hdr_ext_len=1, matching RFC 8200's
        '(hdr_ext_len + 1) * 8' total-length formula.

        Reference: RFC 8200 §4.3 (Hdr Ext Len in 8-octet units,
                excluding first 8 octets).
        """

        # PadN(12) = 14 bytes; total HBH = 16 bytes; hdr_ext_len = 1.
        opts = Ip6HbhOptions(Ip6HbhOptionPadN(b"\x00" * 12))
        asm = Ip6HbhAssembler(
            ip6_hbh__next=IpProto.ICMP6,
            ip6_hbh__options=opts,
        )
        self.assertEqual(
            asm.header.hdr_ext_len,
            1,
            msg="16-byte HBH must yield hdr_ext_len=1.",
        )

    def test__ip6_hbh__assembler__rejects_oversize_options(self) -> None:
        """
        Ensure the assembler rejects an options block exceeding
        IP6_HBH__OPTIONS__MAX_LEN (2046 bytes). The Hdr Ext Len
        uint8 ceiling caps the total HBH header at (255+1)*8 =
        2048 bytes, of which 2 bytes are the fixed prefix.

        Reference: RFC 8200 §4.3 (Hdr Ext Len uint8 ceiling).
        """

        # PadN with 245 bytes data is 247 bytes total. We need to
        # exceed 2046 — let's stack PadNs. Use a single PadN with
        # 253 bytes (max single PadN = 255 bytes). 9 * 255 = 2295 >
        # 2046. Construct a list to hit the over-limit case.
        opts = Ip6HbhOptions(*[Ip6HbhOptionPadN(b"\x00" * 253) for _ in range(9)])
        with self.assertRaises(AssertionError):
            Ip6HbhAssembler(ip6_hbh__options=opts)
