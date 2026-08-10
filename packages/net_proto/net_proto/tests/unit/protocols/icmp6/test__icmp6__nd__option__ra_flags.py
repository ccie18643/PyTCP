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
Module contains tests for the ICMPv6 ND RA Flags option per
RFC 5175. Type 26; carries a 6-byte opaque flag-bits field
reserved for future allocation by the IETF.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__ra_flags.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import Icmp6IntegrityError, Icmp6NdOptionRaFlags
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "All-zero flags (length=1, 8 bytes total).",
            "_kwargs": {"flags": 0},
            "_results": {
                "__len__": 8,
                "__bytes__": (
                    # Type=26, Length=1, 6 zero bytes.
                    b"\x1a\x01\x00\x00\x00\x00\x00\x00"
                ),
                "__str__": "ra_flags (0x000000000000)",
            },
        },
        {
            "_description": "All-ones flags (48-bit ceiling).",
            "_kwargs": {"flags": (1 << 48) - 1},
            "_results": {
                "__len__": 8,
                "__bytes__": b"\x1a\x01\xff\xff\xff\xff\xff\xff",
                "__str__": "ra_flags (0xffffffffffff)",
            },
        },
        {
            "_description": "Single bit set in MSB.",
            "_kwargs": {"flags": 1 << 47},
            "_results": {
                "__len__": 8,
                "__bytes__": b"\x1a\x01\x80\x00\x00\x00\x00\x00",
                "__str__": "ra_flags (0x800000000000)",
            },
        },
    ]
)
class TestIcmp6NdOptionRaFlagsAssembler(TestCase):
    """
    The ICMPv6 ND RA Flags option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the option from _kwargs.
        """

        self._option = Icmp6NdOptionRaFlags(**self._kwargs)

    def test__icmp6__nd__option__ra_flags__len(self) -> None:
        """
        Ensure '__len__' returns the on-wire byte length (8).

        Reference: RFC 5175 §3 (RA Flags option byte length).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__ra_flags__bytes(self) -> None:
        """
        Ensure '__bytes__' produces the expected wire encoding —
        type byte, length=1, big-endian 48-bit flags field.

        Reference: RFC 5175 §3 (RA Flags wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__ra_flags__str(self) -> None:
        """
        Ensure '__str__' produces the canonical log representation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "All-zero flags.",
            "_frame": b"\x1a\x01\x00\x00\x00\x00\x00\x00",
            "_results": {"flags": 0},
        },
        {
            "_description": "All-ones flags.",
            "_frame": b"\x1a\x01\xff\xff\xff\xff\xff\xff",
            "_results": {"flags": (1 << 48) - 1},
        },
        {
            "_description": "Single bit set in MSB.",
            "_frame": b"\x1a\x01\x80\x00\x00\x00\x00\x00",
            "_results": {"flags": 1 << 47},
        },
    ]
)
class TestIcmp6NdOptionRaFlagsParser(TestCase):
    """
    The ICMPv6 ND RA Flags option parser tests.
    """

    _description: str
    _frame: bytes
    _results: dict[str, Any]

    def test__icmp6__nd__option__ra_flags__from_buffer(self) -> None:
        """
        Ensure 'from_buffer' decodes the wire bytes into the
        expected 48-bit flag value.

        Reference: RFC 5175 §3 (RA Flags wire format).
        """

        option = Icmp6NdOptionRaFlags.from_buffer(self._frame)

        self.assertEqual(
            option.flags,
            self._results["flags"],
            msg=f"Unexpected flags for case: {self._description}",
        )


class TestIcmp6NdOptionRaFlagsAsserts(TestCase):
    """
    Constructor argument validation for the RA Flags option.
    """

    def test__icmp6__nd__option__ra_flags__rejects_negative_flags(self) -> None:
        """
        Ensure the constructor rejects a negative 'flags' value.

        Reference: RFC 5175 §3 (RA Flags is a 48-bit unsigned field).
        """

        with self.assertRaises(AssertionError):
            Icmp6NdOptionRaFlags(flags=-1)

    def test__icmp6__nd__option__ra_flags__rejects_oversized_flags(self) -> None:
        """
        Ensure the constructor rejects a 'flags' value above the
        48-bit ceiling.

        Reference: RFC 5175 §3 (RA Flags is a 48-bit unsigned field).
        """

        with self.assertRaises(AssertionError):
            Icmp6NdOptionRaFlags(flags=1 << 48)


class TestIcmp6NdOptionRaFlagsIntegrity(TestCase):
    """
    Integrity-check rejection / acceptance cases for the RA
    Flags option parser. Per RFC 5175 §4 senders MUST emit
    length=1 but receivers MUST accept length ≥ 1 to allow
    future-RFC bit allocations to extend the option without
    breaking older parsers.
    """

    def test__icmp6__nd__option__ra_flags__from_buffer__zero_length_rejected(self) -> None:
        """
        Ensure a length-field of 0 is rejected — length=0 means
        a zero-byte option, which would loop the option
        dispatcher and is forbidden by the receiver "MUST
        ignore the option if the Length is less than 1" rule.

        Reference: RFC 5175 §4 (length < 1 ignore rule).
        """

        bad = b"\x1a\x00\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(Icmp6IntegrityError):
            Icmp6NdOptionRaFlags.from_buffer(bad)

    def test__icmp6__nd__option__ra_flags__from_buffer__length_two_accepted(self) -> None:
        """
        Ensure a length-field of 2 (a future-RFC extension that
        adds 8 more flag bytes after the spec's first six)
        parses without error. The parser captures only the
        first 6 flag bytes (the spec-defined region) and stores
        the on-wire length so the option dispatcher skips the
        rest correctly.

        Reference: RFC 5175 §4 (receiver MUST recognize length and skip unrecognized bits).
        """

        # Length=2 → 16 bytes total. First 6 bytes are the
        # recognized flag region; remaining 8 bytes are
        # "unrecognized" by this specification but the parser
        # MUST accept the option.
        wire = (
            b"\x1a\x02"
            b"\xab\xcd\xef\x12\x34\x56"  # recognized flags
            b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"  # unrecognized tail
        )

        option = Icmp6NdOptionRaFlags.from_buffer(wire)

        self.assertEqual(
            option.flags,
            0xABCDEF123456,
            msg=f"Parser must extract the first 6 flag bytes regardless of total length. Got: {option.flags!r}",
        )
        self.assertEqual(
            option.len,
            16,
            msg=(
                "Parsed option's 'len' must reflect the on-wire length so "
                "the option-dispatcher loop advances past the unrecognized "
                f"tail. Got: {option.len!r}"
            ),
        )

    def test__icmp6__nd__option__ra_flags__assembler_always_emits_length_one(self) -> None:
        """
        Ensure the assembler always emits Length=1 per the
        sender requirement, regardless of how a parsed instance
        was constructed.

        Reference: RFC 5175 §4 ("An implementation of this specification MUST set the Length to 1").
        """

        # Construct via parse from a length=2 frame, then re-emit.
        wire = b"\x1a\x02" b"\xab\xcd\xef\x12\x34\x56" b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
        option = Icmp6NdOptionRaFlags.from_buffer(wire)
        emitted = bytes(option)

        self.assertEqual(
            len(emitted),
            8,
            msg=f"Assembler must emit 8 bytes (length=1) regardless of parsed length. Got: {len(emitted)}",
        )
        self.assertEqual(
            emitted[1],
            1,
            msg=f"Assembler Length byte must be 1. Got: {emitted[1]}",
        )
