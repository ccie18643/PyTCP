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
This module contains tests for the IPv6 Dest Opts options container.

net_proto/tests/unit/protocols/ip6_dest_opts/test__ip6_dest_opts__options.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__errors import (
    Ip6DestOptsIntegrityError,
    Ip6DestOptsSanityError,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__pad1 import (
    Ip6DestOptsOptionPad1,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__padn import (
    Ip6DestOptsOptionPadN,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__unknown import (
    Ip6DestOptsOptionUnknown,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__options import Ip6DestOptsOptions


class TestIp6DestOptsOptionsComposition(TestCase):
    """
    The IPv6 Dest Opts options container composition tests.
    """

    def test__ip6_dest_opts__options__empty(self) -> None:
        """
        Ensure an empty options container reports zero length and
        empty bytes — the canonical "no options" state.

        Reference: RFC 8200 §4.6 (DestOpts header may carry zero options).
        """

        opts = Ip6DestOptsOptions()
        self.assertEqual(len(opts), 0, msg="Empty options must have length 0.")
        self.assertEqual(bytes(opts), b"", msg="Empty options must serialize to empty bytes.")

    def test__ip6_dest_opts__options__pad1_padn_mix(self) -> None:
        """
        Ensure a mixed Pad1+PadN block serializes as the byte-wise
        concatenation of its options in the order constructed.

        Reference: RFC 8200 §4.2 (Pad1, PadN options).
        """

        opts = Ip6DestOptsOptions(
            Ip6DestOptsOptionPad1(),
            Ip6DestOptsOptionPadN(b"\x00\x00\x00\x00"),
            Ip6DestOptsOptionPad1(),
        )
        # Wire frame (7 bytes):
        #   Byte 0    : 0x00       -> Pad1
        #   Bytes 1-6 : 01 04 00 00 00 00 -> PadN(4)
        #   Byte 7    : 0x00       -> Pad1
        self.assertEqual(
            bytes(opts),
            b"\x00\x01\x04\x00\x00\x00\x00\x00",
            msg="Options bytes must be the concatenation of each option's bytes in order.",
        )
        self.assertEqual(
            len(opts),
            8,
            msg="Mixed Pad1+PadN(4)+Pad1 must report total length 8.",
        )

    def test__ip6_dest_opts__options__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer' parses a serialized options block back
        into an equal options container — the round-trip identity
        relied upon by the parser.

        Reference: RFC 8200 §4.2 (TLV option encoding).
        """

        original = Ip6DestOptsOptions(
            Ip6DestOptsOptionPadN(b"\x00\x00"),
            Ip6DestOptsOptionPad1(),
            Ip6DestOptsOptionPadN(b"\xaa\xbb\xcc"),
        )
        recovered = Ip6DestOptsOptions.from_buffer(bytes(original))
        self.assertEqual(
            bytes(recovered),
            bytes(original),
            msg="from_buffer round-trip must produce identical bytes.",
        )

    def test__ip6_dest_opts__options__from_buffer_synthesizes_unknown(self) -> None:
        """
        Ensure 'from_buffer' wraps any option type that is not a
        currently-known option in 'Ip6DestOptsOptionUnknown' so the
        option's type byte and data payload are preserved for a
        future Phase-2 forwarder.

        Reference: RFC 8200 §4.2 (unrecognized options preserved).
        """

        # Synthetic unknown-type option with action-bits 00 (skip):
        # Type=0x06 (top-2-bits=00, IANA-unassigned), Opt Data Len=2, data=AB CD.
        buffer = b"\x06\x02\xab\xcd"
        opts = Ip6DestOptsOptions.from_buffer(buffer)
        self.assertEqual(len(list(opts)), 1, msg="Buffer must parse to exactly one option.")
        self.assertIsInstance(
            opts[0],
            Ip6DestOptsOptionUnknown,
            msg="Non-known option must be wrapped in Ip6DestOptsOptionUnknown.",
        )
        self.assertEqual(
            int(opts[0].type),
            0x06,
            msg="Unknown option must preserve its original Type byte.",
        )


class TestIp6DestOptsOptionsValidateIntegrity(TestCase):
    """
    The IPv6 Dest Opts options 'validate_integrity' walker tests.
    """

    def test__ip6_dest_opts__options__validate_integrity__empty_ok(self) -> None:
        """
        Ensure 'validate_integrity' accepts an empty options buffer
        without raising — an HBH may carry zero actual options when
        the padding-only block already reaches the 8-octet boundary.

        Reference: RFC 8200 §4.6 (DestOpts options block can be padding-only).
        """

        Ip6DestOptsOptions.validate_integrity(buffer=b"")

    def test__ip6_dest_opts__options__validate_integrity__rejects_truncated_tail(self) -> None:
        """
        Ensure 'validate_integrity' raises 'Ip6DestOptsIntegrityError'
        when a non-Pad1 option appears at the tail without enough
        bytes left for its 1-byte Opt Data Len.

        Reference: RFC 8200 §4.2 (TLV options must carry full header).
        """

        # Buffer ends with a single 0x05 byte — non-Pad1 type with
        # no length byte following it.
        with self.assertRaises(Ip6DestOptsIntegrityError):
            Ip6DestOptsOptions.validate_integrity(buffer=b"\x05")

    def test__ip6_dest_opts__options__validate_integrity__rejects_overrun(self) -> None:
        """
        Ensure 'validate_integrity' raises 'Ip6DestOptsIntegrityError'
        when an option's Opt Data Len would extend past the end of
        the options block.

        Reference: RFC 8200 §4.2 (option length must fit in block).
        """

        # PadN frame with opt_data_len=10 but only 2 bytes remain.
        with self.assertRaises(Ip6DestOptsIntegrityError):
            Ip6DestOptsOptions.validate_integrity(buffer=b"\x01\x0a\x00\x00")


class TestIp6DestOptsOptionsValidateSanity(TestCase):
    """
    The IPv6 Dest Opts options 'validate_sanity' walker — RFC 8200 §4.2
    action-on-unrecognized enforcement.
    """

    def test__ip6_dest_opts__options__validate_sanity__skip_action_passes(self) -> None:
        """
        Ensure an unrecognized option whose top-2-bits encode action
        00 (skip) is accepted silently — the receiver continues
        processing as if the option were not present.

        Reference: RFC 8200 §4.2 (action 00: skip the option).
        """

        # Type=0x06 (top-2-bits=00, IANA-unassigned), Opt Data Len=2, data=zero-zero.
        # Walker must accept without raising.
        Ip6DestOptsOptions.validate_sanity(buffer=b"\x06\x02\x00\x00")

    def test__ip6_dest_opts__options__validate_sanity__discard_action_raises_no_pointer(self) -> None:
        """
        Ensure an unrecognized option with action 01 (discard +
        no ICMP) raises 'Ip6DestOptsSanityError' with 'pointer' set to
        None — the chain-walker reads None as "silent discard".

        Reference: RFC 8200 §4.2 (action 01: discard, no ICMP).
        """

        # Type=0x45 (top-2-bits=01), Opt Data Len=2, data=zero-zero.
        with self.assertRaises(Ip6DestOptsSanityError) as ctx:
            Ip6DestOptsOptions.validate_sanity(buffer=b"\x45\x02\x00\x00")
        self.assertIsNone(
            ctx.exception.pointer,
            msg="Action 01 must produce no ICMP pointer (silent discard).",
        )

    def test__ip6_dest_opts__options__validate_sanity__param_problem_raises_with_pointer(self) -> None:
        """
        Ensure an unrecognized option with action 10 (discard +
        Param Problem code 2) raises 'Ip6DestOptsSanityError' with
        'pointer' set to the option's offset within the options
        block — the chain-walker uses the pointer to build the
        ICMPv6 Parameter Problem reply.

        Reference: RFC 8200 §4.2 (action 10: discard + Param Problem).
        """

        # Two Pad1's then an action-10 unknown at offset 2.
        # Wire frame:
        #   Byte 0   : 0x00 -> Pad1
        #   Byte 1   : 0x00 -> Pad1
        #   Byte 2   : 0x85 -> unknown (top-2-bits=10)
        #   Byte 3   : 0x02 -> opt_data_len=2
        #   Bytes 4-5: 00 00 -> data
        with self.assertRaises(Ip6DestOptsSanityError) as ctx:
            Ip6DestOptsOptions.validate_sanity(buffer=b"\x00\x00\x85\x02\x00\x00")
        self.assertEqual(
            ctx.exception.pointer,
            2,
            msg="Action 10 pointer must equal the offset of the offending option.",
        )

    def test__ip6_dest_opts__options__validate_sanity__action_11_unicast_raises_with_pointer(self) -> None:
        """
        Ensure an unrecognized option with action 11 emits Param
        Problem code 2 when the destination is unicast — pointer
        is set to the option's offset.

        Reference: RFC 8200 §4.2 (action 11: Param Problem if unicast).
        """

        # Unknown at offset 0, type 0xC5 (top-2-bits=11).
        with self.assertRaises(Ip6DestOptsSanityError) as ctx:
            Ip6DestOptsOptions.validate_sanity(
                buffer=b"\xc5\x02\x00\x00",
                ip6_dst_is_multicast=False,
            )
        self.assertEqual(
            ctx.exception.pointer,
            0,
            msg="Action 11 on unicast dst must produce a pointer for Param Problem.",
        )
        self.assertFalse(
            ctx.exception.multicast_only,
            msg="Action 11 on unicast dst must NOT flag multicast_only.",
        )

    def test__ip6_dest_opts__options__validate_sanity__action_11_multicast_silently_discards(self) -> None:
        """
        Ensure action 11 on a multicast destination raises with
        'pointer=None' and 'multicast_only=True' so the chain-
        walker discards the packet without emitting ICMP — RFC
        8200 §4.2's multicast suppression rule.

        Reference: RFC 8200 §4.2 (action 11: skip ICMP on multicast dst).
        """

        with self.assertRaises(Ip6DestOptsSanityError) as ctx:
            Ip6DestOptsOptions.validate_sanity(
                buffer=b"\xc5\x02\x00\x00",
                ip6_dst_is_multicast=True,
            )
        self.assertIsNone(
            ctx.exception.pointer,
            msg="Action 11 on multicast dst must produce no ICMP pointer.",
        )
        self.assertTrue(
            ctx.exception.multicast_only,
            msg="Action 11 on multicast dst must flag multicast_only=True.",
        )
