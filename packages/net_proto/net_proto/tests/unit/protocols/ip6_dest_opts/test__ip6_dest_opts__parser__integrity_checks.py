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
This module contains the IPv6 Dest Opts parser integrity-check tests.

net_proto/tests/unit/protocols/ip6_dest_opts/test__ip6_dest_opts__parser__integrity_checks.py

ver 3.0.10
"""

from unittest import TestCase

from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__errors import Ip6DestOptsIntegrityError
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__parser import Ip6DestOptsParser


class TestIp6DestOptsParserIntegrity(TestCase):
    """
    The IPv6 Dest Opts parser integrity-check tests.
    """

    def test__ip6_dest_opts__parser__integrity__rejects_truncated_below_prefix(self) -> None:
        """
        Ensure a frame smaller than the 2-byte HBH fixed prefix is
        rejected with 'Ip6DestOptsIntegrityError' — the parser cannot
        even read Next Header / Hdr Ext Len.

        Reference: RFC 8200 §4.6 (DestOpts header fixed 2-byte prefix).
        """

        # Frame is a single byte; less than IP6_DEST_OPTS__HEADER__LEN.
        with self.assertRaises(Ip6DestOptsIntegrityError):
            Ip6DestOptsParser(PacketRx(b"\x06"))

    def test__ip6_dest_opts__parser__integrity__rejects_hdr_ext_len_overrun(self) -> None:
        """
        Ensure a frame whose declared 'hdr_ext_len' demands more
        bytes than the buffer provides is rejected — guards
        against malformed senders or truncated transit.

        Reference: RFC 8200 §4.6 (total HBH = (Hdr Ext Len + 1) * 8).
        """

        # DestOpts wire frame (2 bytes, header-only):
        #   Byte 0 : 0x06 -> next=TCP
        #   Byte 1 : 0x05 -> hdr_ext_len=5 (claims (5+1)*8 = 48 total)
        # Buffer has only 2 bytes — overrun.
        with self.assertRaises(Ip6DestOptsIntegrityError):
            Ip6DestOptsParser(PacketRx(b"\x06\x05"))

    def test__ip6_dest_opts__parser__integrity__rejects_malformed_options_block(self) -> None:
        """
        Ensure a frame whose options block contains a TLV option
        that overruns the declared DestOpts region is rejected.

        Reference: RFC 8200 §4.2 (option length must fit in block).
        """

        # DestOpts wire frame (8 bytes, header):
        #   Byte 0    : 0x06 -> next=TCP
        #   Byte 1    : 0x00 -> hdr_ext_len=0 (total 8 bytes)
        #   Byte 2    : 0x01 -> option type=PADN
        #   Byte 3    : 0x10 -> opt_data_len=16 (way too long, only 4 bytes left)
        #   Bytes 4-7 : 00 00 00 00 -> remaining bytes (insufficient)
        with self.assertRaises(Ip6DestOptsIntegrityError):
            Ip6DestOptsParser(PacketRx(b"\x06\x00\x01\x10\x00\x00\x00\x00"))

    def test__ip6_dest_opts__parser__integrity__accepts_minimum_valid_frame(self) -> None:
        """
        Ensure the smallest spec-valid HBH frame (8 bytes total:
        2-byte prefix + PadN(4)) parses cleanly. Boundary-accepted
        case so future tightening of integrity checks doesn't
        silently reject the minimum-valid packet.

        Reference: RFC 8200 §4.6 (8-octet minimum DestOpts header).
        """

        # DestOpts wire frame (8 bytes, header-only):
        #   Bytes 0-1 : 06 00 -> next=TCP, hdr_ext_len=0
        #   Bytes 2-7 : 01 04 00 00 00 00 -> PadN(4) zero data
        parser = Ip6DestOptsParser(PacketRx(b"\x06\x00\x01\x04\x00\x00\x00\x00"))
        self.assertEqual(
            parser.header.hdr_ext_len,
            0,
            msg="Minimum HBH (8 bytes) must parse with hdr_ext_len=0.",
        )

    def test__ip6_dest_opts__parser__integrity__error_message_carries_proto_tag(self) -> None:
        """
        Ensure the raised error message starts with the canonical
        '[INTEGRITY ERROR][IPv6 Dest Opts]' prefix produced by the
        protocol's error subclass — the chain-walker grep-matches
        on this tag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip6DestOptsIntegrityError) as ctx:
            Ip6DestOptsParser(PacketRx(b"\x06"))
        self.assertIn(
            "[INTEGRITY ERROR][IPv6 Dest Opts]",
            str(ctx.exception),
            msg="Ip6DestOptsIntegrityError must carry canonical [INTEGRITY ERROR][IPv6 Dest Opts] prefix.",
        )
