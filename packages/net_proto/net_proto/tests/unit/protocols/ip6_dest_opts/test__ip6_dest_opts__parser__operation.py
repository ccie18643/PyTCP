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
This module contains the IPv6 Dest Opts parser happy-path operation tests.

net_proto/tests/unit/protocols/ip6_dest_opts/test__ip6_dest_opts__parser__operation.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto.lib.enums import IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__parser import Ip6DestOptsParser


class TestIp6DestOptsParserOperation(TestCase):
    """
    The IPv6 Dest Opts parser happy-path operation tests.
    """

    def test__ip6_dest_opts__parser__header(self) -> None:
        """
        Ensure the parsed header reflects the wire bytes' Next
        Header and Hdr Ext Len fields exactly.

        Reference: RFC 8200 §4.6 (DestOpts header wire format).
        """

        # DestOpts wire frame (8 bytes, header-only):
        #   Bytes 0-1 : 06 00 -> next=TCP, hdr_ext_len=0
        #   Bytes 2-7 : 01 04 00 00 00 00 -> PadN(4) zero data
        parser = Ip6DestOptsParser(PacketRx(b"\x06\x00\x01\x04\x00\x00\x00\x00"))

        self.assertIs(
            parser.header.next,
            IpProto.TCP,
            msg="Parsed 'next' field must equal the wire byte's IpProto.",
        )
        self.assertEqual(
            parser.header.hdr_ext_len,
            0,
            msg="Parsed 'hdr_ext_len' field must equal the wire byte.",
        )

    def test__ip6_dest_opts__parser__options(self) -> None:
        """
        Ensure the parsed options container contains exactly the
        options present in the wire frame's options block.

        Reference: RFC 8200 §4.2 (TLV option encoding).
        """

        # DestOpts wire frame (8 bytes):
        #   Bytes 0-1 : 06 00 -> next=TCP, hdr_ext_len=0
        #   Byte 2    : 0x00 -> Pad1
        #   Bytes 3-7 : 01 03 00 00 00 -> PadN(3)
        parser = Ip6DestOptsParser(PacketRx(b"\x06\x00\x00\x01\x03\x00\x00\x00"))
        opts = list(parser.options)
        self.assertEqual(len(opts), 2, msg="Two options expected: Pad1 + PadN.")
        self.assertEqual(opts[0].len, 1, msg="First option must be Pad1 (length 1).")
        self.assertEqual(opts[1].len, 5, msg="Second option must be PadN(3) (length 5).")

    def test__ip6_dest_opts__parser__payload(self) -> None:
        """
        Ensure the parsed payload contains exactly the bytes
        following the declared DestOpts region — what the chain-walker
        will hand off to the next protocol.

        Reference: RFC 8200 §4.6 (DestOpts header followed by next header).
        """

        # DestOpts wire frame:
        #   Bytes 0-1 : 06 00 -> next=TCP, hdr_ext_len=0 (8-byte total)
        #   Bytes 2-7 : 01 04 00 00 00 00 -> PadN(4) zero data
        #   Bytes 8+  : "PAYLOAD"
        frame = b"\x06\x00\x01\x04\x00\x00\x00\x00PAYLOAD"
        parser = Ip6DestOptsParser(PacketRx(frame))
        self.assertEqual(
            bytes(parser.payload),
            b"PAYLOAD",
            msg="Parsed payload must equal the post-header bytes.",
        )

    def test__ip6_dest_opts__parser__packet_rx_ip6_dest_opts(self) -> None:
        """
        Ensure the parser installs itself onto 'packet_rx.ip6_dest_opts'
        — the canonical attribute the chain-walker dispatch reads
        to advance the chain.

        Reference: RFC 8200 §4.1 (extension-header chain order).
        """

        packet_rx = PacketRx(b"\x06\x00\x01\x04\x00\x00\x00\x00")
        parser = Ip6DestOptsParser(packet_rx)
        self.assertIs(
            packet_rx.ip6_dest_opts,
            parser,
            msg="Parser must install itself onto packet_rx.ip6_dest_opts.",
        )

    def test__ip6_dest_opts__parser__packet_rx_frame_advanced_past_header(self) -> None:
        """
        Ensure 'packet_rx.frame' has been advanced past the entire
        DestOpts region (fixed prefix + options) so the next protocol's
        parser sees only its own header.

        Reference: RFC 8200 §4.1 (extension-header chain order).
        """

        # DestOpts wire frame:
        #   Bytes 0-7 : full 8-byte DestOpts header
        #   Bytes 8+  : "TCP_HEADER_AND_DATA" — payload for next layer
        frame = b"\x06\x00\x01\x04\x00\x00\x00\x00TCP_HEADER_AND_DATA"
        packet_rx = PacketRx(frame)
        Ip6DestOptsParser(packet_rx)
        self.assertEqual(
            bytes(packet_rx.frame),
            b"TCP_HEADER_AND_DATA",
            msg="packet_rx.frame must be advanced past the DestOpts region.",
        )

    def test__ip6_dest_opts__parser__multi_octet_hdr_ext_len(self) -> None:
        """
        Ensure a 16-byte HBH (hdr_ext_len=1, total = 16 bytes)
        parses correctly with a longer options block. Validates
        the '(hdr_ext_len + 1) * 8' length formula on a non-zero
        hdr_ext_len.

        Reference: RFC 8200 §4.6 (Hdr Ext Len in 8-octet units).
        """

        # DestOpts wire frame (16 bytes, header-only):
        #   Byte 0     : 0x06 -> next=TCP
        #   Byte 1     : 0x01 -> hdr_ext_len=1 (total 16 bytes)
        #   Byte 2     : 0x01 -> PadN type
        #   Byte 3     : 0x0c -> opt_data_len=12
        #   Bytes 4-15 : 12 zero bytes -> PadN data
        frame = b"\x06\x01\x01\x0c" + b"\x00" * 12
        parser = Ip6DestOptsParser(PacketRx(frame))
        self.assertEqual(
            parser.header.hdr_ext_len,
            1,
            msg="hdr_ext_len=1 must parse cleanly.",
        )
        self.assertEqual(
            len(list(parser.options)),
            1,
            msg="Single PadN(12) option expected in the parsed container.",
        )
