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
This module contains tests for the IPv6 HBH Pad1 option.

net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__option__pad1.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import Ip6HbhOptionType
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__pad1 import (
    IP6_HBH__OPTION__PAD1__LEN,
    Ip6HbhOptionPad1,
)


class TestIp6HbhOptionPad1(TestCase):
    """
    The IPv6 HBH Pad1 option tests.
    """

    def test__ip6_hbh__option__pad1__len(self) -> None:
        """
        Ensure the Pad1 option reports a total wire length of exactly
        1 byte — no length, no data, just the Type=0 byte.

        Reference: RFC 8200 §4.2 (Pad1 option, single 0x00 byte).
        """

        opt = Ip6HbhOptionPad1()
        self.assertEqual(
            len(opt),
            IP6_HBH__OPTION__PAD1__LEN,
            msg="Pad1 must occupy exactly 1 byte on the wire.",
        )
        self.assertEqual(
            len(opt),
            1,
            msg="IP6_HBH__OPTION__PAD1__LEN must equal 1.",
        )

    def test__ip6_hbh__option__pad1__bytes(self) -> None:
        """
        Ensure the Pad1 option serializes to a single 0x00 byte —
        its IANA-assigned option type with no length/data fields.

        Reference: RFC 8200 §4.2 (Pad1 option, type 0).
        """

        opt = Ip6HbhOptionPad1()

        # Pad1 wire frame (1 byte):
        #   Byte 0 : 0x00 -> type=PAD1
        self.assertEqual(
            bytes(opt),
            b"\x00",
            msg="Pad1 bytes must equal b'\\x00' (RFC 8200 §4.2).",
        )

    def test__ip6_hbh__option__pad1__type(self) -> None:
        """
        Ensure the Pad1 option's 'type' field is the canonical
        Ip6HbhOptionType.PAD1 enum member, not a synthesised
        unknown.

        Reference: RFC 8200 §4.2 (Pad1 option type 0).
        """

        opt = Ip6HbhOptionPad1()
        self.assertIs(
            opt.type,
            Ip6HbhOptionType.PAD1,
            msg="Pad1 option type must be Ip6HbhOptionType.PAD1.",
        )

    def test__ip6_hbh__option__pad1__str(self) -> None:
        """
        Ensure the Pad1 option's log string is the lowercase token
        'pad1' so log lines stay consistent with the TCP NOP/EOL
        convention.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opt = Ip6HbhOptionPad1()
        self.assertEqual(
            str(opt),
            "pad1",
            msg="Pad1 __str__ must be 'pad1'.",
        )

    def test__ip6_hbh__option__pad1__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer' parses a single 0x00 byte back into a
        Pad1 instance equal to a freshly-constructed one — pinning
        the round-trip identity required by the chain-walker.

        Reference: RFC 8200 §4.2 (Pad1 option, type 0).
        """

        opt = Ip6HbhOptionPad1.from_buffer(b"\x00")
        self.assertEqual(
            opt,
            Ip6HbhOptionPad1(),
            msg="from_buffer(b'\\x00') must round-trip to Ip6HbhOptionPad1().",
        )
        self.assertEqual(
            bytes(opt),
            b"\x00",
            msg="Round-tripped Pad1 must serialise back to b'\\x00'.",
        )

    def test__ip6_hbh__option__pad1__from_buffer_rejects_wrong_type(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer whose first byte is
        not the Pad1 type byte (0x00) — an invariant enforced by
        the parser's 'assert' guard. The chain-walker dispatcher
        is what selects the right option class; this guard is the
        last-line defensive check.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionPad1.from_buffer(b"\x01")
