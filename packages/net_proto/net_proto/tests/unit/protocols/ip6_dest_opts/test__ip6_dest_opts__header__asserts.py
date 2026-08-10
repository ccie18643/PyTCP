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
This module contains the IPv6 Dest Opts header dataclass __post_init__ asserts.

net_proto/tests/unit/protocols/ip6_dest_opts/test__ip6_dest_opts__header__asserts.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto.lib.enums import IpProto
from net_proto.lib.int_checks import UINT_8__MAX
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__header import (
    IP6_DEST_OPTS__HEADER__LEN,
    Ip6DestOptsHeader,
)


class TestIp6DestOptsHeaderAsserts(TestCase):
    """
    The IPv6 Dest Opts header constructor invariant tests.
    """

    def test__ip6_dest_opts__header__defaults_accepted(self) -> None:
        """
        Ensure a minimal valid header (next=RAW, hdr_ext_len=0)
        constructs cleanly and reports the expected fixed-prefix
        length — guards against future regressions that tighten
        either field's bounds.

        Reference: RFC 8200 §4.6 (DestOpts header fixed 2-byte prefix).
        """

        header = Ip6DestOptsHeader(next=IpProto.RAW, hdr_ext_len=0)
        self.assertEqual(
            len(header),
            IP6_DEST_OPTS__HEADER__LEN,
            msg="Default Ip6DestOptsHeader must report fixed 2-byte prefix length.",
        )

    def test__ip6_dest_opts__header__rejects_non_ipproto_next(self) -> None:
        """
        Ensure passing a non-IpProto value to the 'next' field trips
        the dataclass __post_init__ assert — protocol parsers rely
        on 'header.next' being an enum member for match dispatch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Ip6DestOptsHeader(next=6, hdr_ext_len=0)  # type: ignore[arg-type]

    def test__ip6_dest_opts__header__rejects_negative_hdr_ext_len(self) -> None:
        """
        Ensure 'hdr_ext_len' rejects negative values — the wire
        field is a uint8.

        Reference: RFC 8200 §4.6 (Hdr Ext Len 8-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6DestOptsHeader(next=IpProto.RAW, hdr_ext_len=-1)

    def test__ip6_dest_opts__header__rejects_overflow_hdr_ext_len(self) -> None:
        """
        Ensure 'hdr_ext_len' rejects values above the uint8 ceiling.

        Reference: RFC 8200 §4.6 (Hdr Ext Len 8-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6DestOptsHeader(next=IpProto.RAW, hdr_ext_len=UINT_8__MAX + 1)

    def test__ip6_dest_opts__header__accepts_uint8_max(self) -> None:
        """
        Ensure 'hdr_ext_len' accepts the uint8 maximum (255) —
        bounds-inclusive on the upper edge.

        Reference: RFC 8200 §4.6 (Hdr Ext Len 8-bit unsigned, 0..255).
        """

        header = Ip6DestOptsHeader(next=IpProto.RAW, hdr_ext_len=UINT_8__MAX)
        self.assertEqual(
            header.hdr_ext_len,
            255,
            msg="hdr_ext_len=255 must be accepted (uint8 maximum).",
        )

    def test__ip6_dest_opts__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent IPv6
        DestOpts fixed-prefix header — locks in pack/unpack symmetry
        of the two-byte 'next' + 'hdr_ext_len' prefix.

        Reference: RFC 8200 §4.6 (DestOpts header wire format).
        """

        original = Ip6DestOptsHeader(next=IpProto.TCP, hdr_ext_len=7)

        rebuilt = Ip6DestOptsHeader.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )
