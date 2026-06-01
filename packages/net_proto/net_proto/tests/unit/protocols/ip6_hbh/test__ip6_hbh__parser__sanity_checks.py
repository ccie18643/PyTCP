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
This module contains the IPv6 HBH parser sanity-check tests.

net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__parser__sanity_checks.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhSanityError
from net_proto.protocols.ip6_hbh.ip6_hbh__parser import Ip6HbhParser


class TestIp6HbhParserSanity(TestCase):
    """
    The IPv6 HBH parser sanity-check tests.

    Sanity validation applies the RFC 8200 §4.2 action-on-
    unrecognized rule to every option in the (already integrity-
    checked) options block. The chain-walker dispatch in Phase 8
    catches these errors, reads the 'pointer' / 'multicast_only'
    fields, and emits ICMPv6 Parameter Problem code 2 accordingly.
    """

    def test__ip6_hbh__parser__sanity__skip_action_passes(self) -> None:
        """
        Ensure an unrecognized option whose top-2-bits encode action
        00 (skip) is accepted silently — the parser continues and
        the option appears in the parsed options as Unknown.

        Reference: RFC 8200 §4.2 (action 00: skip the option).
        """

        # HBH wire frame (8 bytes):
        #   Bytes 0-1 : 06 00 -> next=TCP, hdr_ext_len=0
        #   Byte 2    : 0x06 -> unknown type (IANA-unassigned), top-2-bits=00 (skip)
        #   Byte 3    : 0x04 -> opt_data_len=4
        #   Bytes 4-7 : 00 00 00 00 -> data
        parser = Ip6HbhParser(PacketRx(b"\x06\x00\x06\x04\x00\x00\x00\x00"))
        self.assertEqual(
            len(list(parser.options)),
            1,
            msg="Skip-action unknown option must still parse into the options container.",
        )

    def test__ip6_hbh__parser__sanity__discard_action_raises(self) -> None:
        """
        Ensure an unrecognized option with action 01 (discard +
        no ICMP) raises 'Ip6HbhSanityError' with 'pointer=None' so
        the chain-walker discards the packet silently.

        Reference: RFC 8200 §4.2 (action 01: discard, no ICMP).
        """

        # HBH wire frame (8 bytes):
        #   Bytes 0-1 : 06 00 -> next=TCP, hdr_ext_len=0
        #   Byte 2    : 0x45 -> unknown, top-2-bits=01 (discard)
        #   Byte 3    : 0x04 -> opt_data_len=4
        #   Bytes 4-7 : 00 00 00 00 -> data
        with self.assertRaises(Ip6HbhSanityError) as ctx:
            Ip6HbhParser(PacketRx(b"\x06\x00\x45\x04\x00\x00\x00\x00"))
        self.assertIsNone(
            ctx.exception.pointer,
            msg="Action 01 must produce no ICMP pointer (silent discard).",
        )

    def test__ip6_hbh__parser__sanity__param_problem_action_raises_with_pointer(self) -> None:
        """
        Ensure an unrecognized option with action 10 (discard +
        Param Problem code 2) raises 'Ip6HbhSanityError' with the
        offset of the offending option as 'pointer'. The chain-
        walker uses this to build the ICMPv6 Param Problem reply.

        Reference: RFC 8200 §4.2 (action 10: discard + Param Problem).
        """

        # HBH wire frame (8 bytes):
        #   Bytes 0-1 : 06 00 -> next=TCP, hdr_ext_len=0
        #   Byte 2    : 0x85 -> unknown, top-2-bits=10 (discard + Param Problem)
        #   Byte 3    : 0x04 -> opt_data_len=4
        #   Bytes 4-7 : 00 00 00 00 -> data
        with self.assertRaises(Ip6HbhSanityError) as ctx:
            Ip6HbhParser(PacketRx(b"\x06\x00\x85\x04\x00\x00\x00\x00"))
        self.assertEqual(
            ctx.exception.pointer,
            0,
            msg="Action 10 pointer must equal the offset of the offending option (within options block).",
        )

    def test__ip6_hbh__parser__sanity__error_message_carries_proto_tag(self) -> None:
        """
        Ensure the sanity-error message starts with the canonical
        '[SANITY ERROR][IPv6 HBH]' prefix produced by the protocol's
        error subclass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip6HbhSanityError) as ctx:
            Ip6HbhParser(PacketRx(b"\x06\x00\x85\x04\x00\x00\x00\x00"))
        self.assertIn(
            "[SANITY ERROR][IPv6 HBH]",
            str(ctx.exception),
            msg="Ip6HbhSanityError must carry canonical [SANITY ERROR][IPv6 HBH] prefix.",
        )
