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
This module contains tests for the IPv6 HBH CALIPSO option.

net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__option__calipso.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_proto.lib.int_checks import UINT_8__MAX, UINT_16__MAX, UINT_32__MAX
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhIntegrityError
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import Ip6HbhOptionType
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__calipso import (
    IP6_HBH__OPTION__CIPSO__FIXED_LEN,
    Ip6HbhOptionCalipso,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__pad1 import (
    Ip6HbhOptionPad1,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "CALIPSO with no compartment bitmap (cmpt_length=0).",
            "_kwargs": {
                "doi": 0x12345678,
                "sens_level": 1,
                "checksum": 0xABCD,
                "compartment_bitmap": b"",
            },
            "_results": {
                "len": 10,
                "bytes": b"\x07\x08\x12\x34\x56\x78\x00\x01\xab\xcd",
                "cmpt_length": 0,
            },
        },
        {
            "_description": "CALIPSO with one 32-bit compartment word.",
            "_kwargs": {
                "doi": 0,
                "sens_level": 5,
                "checksum": 0,
                "compartment_bitmap": b"\xaa\xbb\xcc\xdd",
            },
            "_results": {
                "len": 14,
                "bytes": b"\x07\x0c\x00\x00\x00\x00\x01\x05\x00\x00\xaa\xbb\xcc\xdd",
                "cmpt_length": 1,
            },
        },
        {
            "_description": "CALIPSO with two 32-bit compartment words.",
            "_kwargs": {
                "doi": 0xFFFFFFFF,
                "sens_level": 0,
                "checksum": 0xFFFF,
                "compartment_bitmap": b"\x01\x02\x03\x04\x05\x06\x07\x08",
            },
            "_results": {
                "len": 18,
                "bytes": (b"\x07\x10\xff\xff\xff\xff\x02\x00\xff\xff" b"\x01\x02\x03\x04\x05\x06\x07\x08"),
                "cmpt_length": 2,
            },
        },
    ]
)
class TestIp6HbhOptionCalipso(TestCase):
    """
    The IPv6 HBH CALIPSO option happy-path matrix.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__ip6_hbh__option__calipso__len(self) -> None:
        """
        Ensure the CALIPSO option total wire length equals 8 fixed
        bytes plus the compartment-bitmap byte length.

        Reference: RFC 5570 §4 (CALIPSO option total length).
        """

        opt = Ip6HbhOptionCalipso(**self._kwargs)
        self.assertEqual(
            len(opt),
            self._results["len"],
            msg=f"Unexpected CALIPSO length for case: {self._description}.",
        )

    def test__ip6_hbh__option__calipso__bytes(self) -> None:
        """
        Ensure the CALIPSO option serialises to Type=0x07,
        Opt Data Len, DOI, Cmpt Length, Sens Level, Checksum,
        Compartment Bitmap — in that order.

        Reference: RFC 5570 §4 (CALIPSO wire format).
        """

        opt = Ip6HbhOptionCalipso(**self._kwargs)
        self.assertEqual(
            bytes(opt),
            self._results["bytes"],
            msg=f"Unexpected CALIPSO bytes for case: {self._description}.",
        )

    def test__ip6_hbh__option__calipso__cmpt_length(self) -> None:
        """
        Ensure the CALIPSO option's 'cmpt_length' attribute returns
        the compartment-bitmap length in 32-bit words (i.e.
        len(bitmap) / 4).

        Reference: RFC 5570 §4 (Cmpt Length in 32-bit units).
        """

        opt = Ip6HbhOptionCalipso(**self._kwargs)
        self.assertEqual(
            opt.cmpt_length,
            self._results["cmpt_length"],
            msg=f"Unexpected CALIPSO cmpt_length for case: {self._description}.",
        )

    def test__ip6_hbh__option__calipso__type(self) -> None:
        """
        Ensure the option's 'type' field is the canonical
        Ip6HbhOptionType.CALIPSO enum member (0x07).

        Reference: RFC 5570 §4 (CALIPSO type 0x07).
        """

        opt = Ip6HbhOptionCalipso(**self._kwargs)
        self.assertIs(
            opt.type,
            Ip6HbhOptionType.CALIPSO,
            msg=f"CALIPSO type must be Ip6HbhOptionType.CALIPSO for case: {self._description}.",
        )

    def test__ip6_hbh__option__calipso__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer' on the serialised bytes produces an
        instance equal to the original — round-trip identity.

        Reference: RFC 5570 §4 (CALIPSO wire format).
        """

        original = Ip6HbhOptionCalipso(**self._kwargs)
        recovered = Ip6HbhOptionCalipso.from_buffer(bytes(original))
        self.assertEqual(
            recovered,
            original,
            msg=f"Round-trip from_buffer must equal original for case: {self._description}.",
        )


class TestIp6HbhOptionCalipsoAsserts(TestCase):
    """
    The IPv6 HBH CALIPSO constructor and parser-guard tests.
    """

    def test__ip6_hbh__option__calipso__rejects_overflow_doi(self) -> None:
        """
        Ensure constructing with a DOI above the uint32 ceiling
        trips the is_uint32 assert.

        Reference: RFC 5570 §4 (DOI 32-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionCalipso(
                doi=UINT_32__MAX + 1,
                sens_level=0,
                checksum=0,
                compartment_bitmap=b"",
            )

    def test__ip6_hbh__option__calipso__rejects_overflow_sens_level(self) -> None:
        """
        Ensure constructing with sens_level above uint8 ceiling
        trips the is_uint8 assert.

        Reference: RFC 5570 §4 (Sens Level 8-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionCalipso(
                doi=0,
                sens_level=UINT_8__MAX + 1,
                checksum=0,
                compartment_bitmap=b"",
            )

    def test__ip6_hbh__option__calipso__rejects_overflow_checksum(self) -> None:
        """
        Ensure constructing with checksum above uint16 ceiling
        trips the is_uint16 assert.

        Reference: RFC 5570 §4 (Checksum CRC-16, 16-bit).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionCalipso(
                doi=0,
                sens_level=0,
                checksum=UINT_16__MAX + 1,
                compartment_bitmap=b"",
            )

    def test__ip6_hbh__option__calipso__rejects_misaligned_bitmap(self) -> None:
        """
        Ensure constructing with a compartment bitmap whose length
        is not a multiple of 4 bytes trips the alignment assert.

        Reference: RFC 5570 §4 (Cmpt Length is in 32-bit units;
                   bitmap length must therefore be a multiple of 4).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionCalipso(
                doi=0,
                sens_level=0,
                checksum=0,
                compartment_bitmap=b"\x00\x00\x00",  # 3 bytes
            )

    def test__ip6_hbh__option__calipso__rejects_overflow_total_len(self) -> None:
        """
        Ensure constructing with a compartment bitmap large enough
        to push 'len' past uint8 ceiling 255 trips the is_uint8
        assert.

        Reference: RFC 5570 §4 (Opt Data Len 8-bit unsigned).
        """

        # 248 + 8 fixed = 256 — overflows uint8.
        with self.assertRaises(AssertionError):
            Ip6HbhOptionCalipso(
                doi=0,
                sens_level=0,
                checksum=0,
                compartment_bitmap=b"\x00" * 248,
            )

    def test__ip6_hbh__option__calipso__from_buffer_rejects_wrong_type(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer whose first byte is
        not 0x07.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Wire frame with type=0x05 (Router Alert) instead of 0x07.
        with self.assertRaises(AssertionError):
            Ip6HbhOptionCalipso.from_buffer(b"\x05\x08\x00\x00\x00\x00\x00\x00\x00\x00")

    def test__ip6_hbh__option__calipso__from_buffer_rejects_truncated(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer shorter than the
        10-byte minimum (when no compartment bitmap is present).

        Reference: RFC 5570 §4 (CALIPSO minimum length 10 octets).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionCalipso.from_buffer(b"\x07\x08\x00\x00\x00\x00\x00")

    def test__ip6_hbh__option__calipso__minimum_accepted_form(self) -> None:
        """
        Ensure a 10-byte CALIPSO with no compartment bitmap
        (cmpt_length=0) is accepted — boundary-accepted case so
        future tightening doesn't silently reject the spec
        minimum.

        Reference: RFC 5570 §4 (CALIPSO minimum 10 octets).
        """

        opt = Ip6HbhOptionCalipso(
            doi=0,
            sens_level=0,
            checksum=0,
            compartment_bitmap=b"",
        )
        self.assertEqual(
            len(opt),
            IP6_HBH__OPTION__CIPSO__FIXED_LEN,
            msg="Minimum-form CALIPSO must report length equal to fixed-prefix length.",
        )


class TestIp6HbhOptionCalipsoIntegrity(TestCase):
    """
    The IPv6 HBH CALIPSO 'from_buffer' integrity-check tests.
    Hostile-wire defense-in-depth — these inputs must raise
    Ip6HbhIntegrityError so the IPv6 chain walker's
    PacketValidationError catch can drop the frame cleanly. The
    pre-fix behaviour was a bare AssertionError that leaked past
    the catch.
    """

    def test__ip6_hbh__option__calipso__integrity__opt_data_len__mismatch(self) -> None:
        """
        Ensure 'from_buffer' raises Ip6HbhIntegrityError when the
        wire Opt Data Len contradicts the Cmpt Length field — the
        Opt Data Len MUST equal 8 (fixed prefix bytes) plus
        cmpt_length * 4 (compartment bitmap bytes).

        Reference: RFC 5570 §4 (Cmpt Length / Opt Data Len consistency).
        """

        # Wire frame:
        #   Byte 0    : 0x07 -> CALIPSO type
        #   Byte 1    : 0x08 -> Opt Data Len = 8 (claims no bitmap)
        #   Bytes 2-5 : 00 00 00 00 -> DOI
        #   Byte 6    : 0x05 -> cmpt_length = 5 (demands 20 bytes of bitmap)
        #   Byte 7    : 0x00 -> sens_level
        #   Bytes 8-9 : 00 00 -> checksum
        # Opt Data Len=8 but cmpt_length*4 + 8 = 28 → mismatch.
        buffer = b"\x07\x08\x00\x00\x00\x00\x05\x00\x00\x00"

        with self.assertRaises(Ip6HbhIntegrityError) as error:
            Ip6HbhOptionCalipso.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv6 HBH] The IPv6 HBH CALIPSO Opt Data Len must equal "
                "8 + cmpt_length * 4. Got: opt_data_len=8, cmpt_length=5"
            ),
            msg="Unexpected integrity-error message for Opt Data Len mismatch.",
        )


class TestIp6HbhOptionsCalipsoProperty(TestCase):
    """
    The 'Ip6HbhOptions.calipso' accessor property tests.
    """

    def test__ip6_hbh__options__calipso__present(self) -> None:
        """
        Ensure 'Ip6HbhOptions.calipso' returns the contained
        CALIPSO option when one is present.

        Reference: RFC 5570 §4 (CALIPSO option presence).
        """

        cipso = Ip6HbhOptionCalipso(
            doi=0x12345678,
            sens_level=1,
            checksum=0xABCD,
            compartment_bitmap=b"",
        )
        opts = Ip6HbhOptions(cipso)
        self.assertIs(
            opts.calipso,
            cipso,
            msg="calipso property must return the contained CALIPSO option.",
        )

    def test__ip6_hbh__options__calipso__absent_returns_none(self) -> None:
        """
        Ensure 'calipso' returns None when no CALIPSO option is
        present in the container.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opts = Ip6HbhOptions(Ip6HbhOptionPad1())
        self.assertIsNone(
            opts.calipso,
            msg="calipso property must return None when no CALIPSO option is present.",
        )

    def test__ip6_hbh__options__calipso__from_buffer_synthesises_typed_option(self) -> None:
        """
        Ensure 'Ip6HbhOptions.from_buffer' walks the TLV block
        and synthesises a typed 'Ip6HbhOptionCalipso' for the
        0x07 type byte (rather than wrapping it in
        'Ip6HbhOptionUnknown').

        Reference: RFC 5570 §4 (CALIPSO type 0x07 typed dispatch).
        """

        # Wire frame (10 bytes):
        #   Byte 0    : 0x07 -> CALIPSO type
        #   Byte 1    : 0x08 -> Opt Data Len = 8
        #   Bytes 2-5 : 12 34 56 78 -> DOI
        #   Byte 6    : 0x00 -> cmpt_length = 0
        #   Byte 7    : 0x01 -> sens_level = 1
        #   Bytes 8-9 : ab cd -> checksum
        opts = Ip6HbhOptions.from_buffer(b"\x07\x08\x12\x34\x56\x78\x00\x01\xab\xcd")
        cipso = opts.calipso
        self.assertIsNotNone(
            cipso,
            msg="from_buffer must synthesise a typed CALIPSO option.",
        )
        assert cipso is not None  # mypy hint
        self.assertEqual(
            cipso.doi,
            0x12345678,
            msg="CALIPSO DOI must round-trip through Ip6HbhOptions.from_buffer.",
        )
