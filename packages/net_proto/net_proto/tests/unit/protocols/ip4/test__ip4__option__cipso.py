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
Module contains tests for the IPv4 CIPSO (Commercial IP Security
Option) shallow option code (FIPS-188 / Linux NetLabel).

net_proto/tests/unit/protocols/ip4/test__ip4__option__cipso.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    IP4__OPTION__CIPSO__DOI_LEN,
    IP4__OPTION__CIPSO__HDR_LEN,
    Ip4IntegrityError,
    Ip4OptionCipso,
    Ip4OptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestIp4OptionCipsoAsserts(TestCase):
    """
    The IPv4 CIPSO option constructor argument assert tests.
    """

    def test__ip4__option__cipso__doi__under_min(self) -> None:
        """
        Ensure the IPv4 CIPSO option constructor rejects a negative
        DOI.

        Reference: FIPS-188 (DOI is a 32-bit unsigned integer).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionCipso(doi=-1, tags=[])

        self.assertEqual(
            str(error.exception),
            "The 'doi' field must be a 32-bit unsigned integer. Got: -1",
            msg="Unexpected assertion message for 'doi' < 0.",
        )

    def test__ip4__option__cipso__tag__too_short(self) -> None:
        """
        Ensure the constructor rejects a tag whose total length is
        below the 2-byte minimum (type + length bytes).

        Reference: FIPS-188 §A.4 (each CIPSO tag has type + length
        + content, minimum 2 bytes).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionCipso(doi=0, tags=[b"\x01"])  # 1 byte tag (no length byte)

        self.assertIn(
            "Each CIPSO tag must be at least 2 bytes",
            str(error.exception),
            msg="Unexpected assertion message for too-short tag.",
        )

    def test__ip4__option__cipso__tag__length_mismatch(self) -> None:
        """
        Ensure the constructor rejects a tag whose embedded length
        byte (tag[1]) does not equal the actual tag length.

        Reference: FIPS-188 §A.4 (CIPSO tag length byte is total
        tag length including type+length bytes).
        """

        # Tag claims length=4 in byte 1 but is actually 3 bytes total
        bad_tag = b"\x01\x04\xff"

        with self.assertRaises(AssertionError) as error:
            Ip4OptionCipso(doi=0, tags=[bad_tag])

        self.assertIn(
            "length byte must equal its actual length",
            str(error.exception),
            msg="Unexpected assertion message for tag length mismatch.",
        )


@parameterized_class(
    [
        {
            "_description": "CIPSO option with DOI only (no tags).",
            "_doi": 0xCAFE0001,
            "_tags": [],
            "_results": {
                "__len__": 6,
                "__str__": "cipso doi=3405643777 tags=[]",
                "__repr__": "Ip4OptionCipso(doi=3405643777, tags=[])",
                # IPv4 CIPSO wire frame (6 bytes = 2-byte hdr + 4-byte DOI):
                #   Byte  0    : 0x86       -> type=Ip4OptionType.CIPSO (134)
                #   Byte  1    : 0x06       -> len=6 (header + DOI, no tags)
                #   Bytes 2-5  : 0xcafe0001 -> DOI=3405643777
                "__bytes__": b"\x86\x06\xca\xfe\x00\x01",
                "length": IP4__OPTION__CIPSO__HDR_LEN + IP4__OPTION__CIPSO__DOI_LEN,
            },
        },
        {
            "_description": "CIPSO option with one 8-byte rbitmap-style tag.",
            "_doi": 0xDEADBEEF,
            "_tags": [b"\x01\x08\x00\x00\x10\x20\x30\x40"],
            "_results": {
                "__len__": 14,
                "__str__": "cipso doi=3735928559 tags=[0108000010203040]",
                "__repr__": ("Ip4OptionCipso(doi=3735928559, " "tags=[b'\\x01\\x08\\x00\\x00\\x10 0@'])"),
                # IPv4 CIPSO wire frame (14 bytes = 2-byte hdr + 4-byte DOI + 8-byte tag):
                #   Byte  0     : 0x86       -> type=134
                #   Byte  1     : 0x0e       -> len=14
                #   Bytes 2-5   : 0xdeadbeef -> DOI
                #   Bytes 6-13  : tag1 = 0x01 0x08 0x00 0x00 0x10 0x20 0x30 0x40
                "__bytes__": b"\x86\x0e\xde\xad\xbe\xef\x01\x08\x00\x00\x10\x20\x30\x40",
                "length": 14,
            },
        },
        {
            "_description": "CIPSO option with two tags of different sizes.",
            "_doi": 0x12345678,
            "_tags": [
                b"\x01\x04\xaa\xbb",  # 4-byte tag
                b"\x05\x06\x11\x22\x33\x44",  # 6-byte tag
            ],
            "_results": {
                "__len__": 16,
                "__str__": "cipso doi=305419896 tags=[0104aabb, 050611223344]",
                "__repr__": (
                    "Ip4OptionCipso(doi=305419896, " "tags=[b'\\x01\\x04\\xaa\\xbb', b'\\x05\\x06\\x11\"3D'])"
                ),
                # IPv4 CIPSO wire frame (16 bytes):
                #   Byte  0     : 0x86       -> type=134
                #   Byte  1     : 0x10       -> len=16
                #   Bytes 2-5   : 0x12345678 -> DOI
                #   Bytes 6-9   : tag1 = 0x01 0x04 0xaa 0xbb
                #   Bytes 10-15 : tag2 = 0x05 0x06 0x11 0x22 0x33 0x44
                "__bytes__": (b"\x86\x10\x12\x34\x56\x78" b"\x01\x04\xaa\xbb" b"\x05\x06\x11\x22\x33\x44"),
                "length": 16,
            },
        },
    ]
)
class TestIp4OptionCipsoAssembler(TestCase):
    """
    The IPv4 CIPSO option assembler tests.
    """

    _description: str
    _doi: int
    _tags: list[bytes]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an Ip4OptionCipso from the parametrized 'doi' / 'tags'.
        """

        self._option = Ip4OptionCipso(doi=self._doi, tags=self._tags)

    def test__ip4__option__cipso__len(self) -> None:
        """
        Ensure '__len__' reports 2-byte header + 4-byte DOI + sum of
        per-tag lengths.

        Reference: FIPS-188 (CIPSO length = 6 + sum of tag sizes).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected '__len__' for case: {self._description}",
        )

    def test__ip4__option__cipso__str(self) -> None:
        """
        Ensure '__str__' renders DOI and hex-encoded tag list in a
        readable single-line log form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected '__str__' for case: {self._description}",
        )

    def test__ip4__option__cipso__bytes(self) -> None:
        """
        Ensure 'bytes()' serialises the option to the canonical
        FIPS-188 wire format: type=134 / length / DOI (network byte
        order) / opaque tags.

        Reference: FIPS-188 §A (CIPSO wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected 'bytes()' for case: {self._description}",
        )

    def test__ip4__option__cipso__type(self) -> None:
        """
        Ensure the option's 'type' field is Ip4OptionType.CIPSO (the
        wire value 134) regardless of construction arguments.

        Reference: FIPS-188 (CIPSO type byte = 134).
        """

        self.assertIs(
            self._option.type,
            Ip4OptionType.CIPSO,
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__ip4__option__cipso__roundtrip(self) -> None:
        """
        Ensure an option assembled to bytes and re-parsed via
        'from_buffer' equals the original — DOI, opaque tag bytes,
        type, len all round-trip without loss.

        Reference: FIPS-188 §A (CIPSO wire format).
        """

        roundtripped = Ip4OptionCipso.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            roundtripped,
            self._option,
            msg=f"Unexpected roundtrip result for case: {self._description}",
        )


class TestIp4OptionCipsoIntegrity(TestCase):
    """
    The IPv4 CIPSO option 'from_buffer' integrity-check tests.
    """

    def test__ip4__option__cipso__integrity__length__under_min(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the encoded
        length byte is below the 6-byte minimum (header + DOI).

        Reference: FIPS-188 (CIPSO length >= 6).
        """

        # Bytes: 0x86=type, 0x05=len (one byte short), partial DOI ...
        buffer = b"\x86\x05\xca\xfe\x00\x01"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionCipso.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 CIPSO option length must be at least 6 bytes. Got: 5",
            msg="Unexpected integrity-error message for length < 6.",
        )

    def test__ip4__option__cipso__integrity__tag_length_too_small(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when an embedded
        tag's length byte is < 2 (the per-tag header minimum).

        Reference: FIPS-188 §A.4 (tag length byte includes type+length).
        """

        # 0x86=type, 0x09=len, 4-byte DOI, then tag with length=1 (invalid)
        buffer = b"\x86\x09\xca\xfe\x00\x01\x01\x01\xff"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionCipso.from_buffer(buffer)

        self.assertIn(
            "tag's length byte must be at least 2",
            str(error.exception),
            msg="Unexpected integrity-error message for too-small tag length.",
        )

    def test__ip4__option__cipso__integrity__tag_extends_past_option(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when an embedded
        tag's length byte makes it extend past the option boundary.

        Reference: FIPS-188 §A.4 (tags are bounded by option length).
        """

        # 0x86=type, 0x09=len=9 (so option has 1 tag byte after DOI),
        # 4-byte DOI, then tag with type=0x01, length=0x05 (claims 5 bytes
        # but only 1 byte remains in the option)
        buffer = b"\x86\x09\xca\xfe\x00\x01\x01\x05\xff"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionCipso.from_buffer(buffer)

        self.assertIn(
            "tag's length byte must not extend past the option boundary",
            str(error.exception),
            msg="Unexpected integrity-error message for tag-length-overrun.",
        )


class TestIp4OptionCipsoWrongType(TestCase):
    """
    The IPv4 CIPSO option wrong-kind-byte parser tests.
    """

    def test__ip4__option__cipso__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the kind byte equals
        Ip4OptionType.CIPSO and rejects a kind byte below it, pinning
        the equality check against a '<=' relaxation.

        Reference: FIPS-188 §A.1 (CIPSO option kind byte).
        """

        with self.assertRaises(AssertionError):
            Ip4OptionCipso.from_buffer(b"\x00\x0e\xde\xad\xbe\xef\x01\x08\x00\x00\x10\x20\x30\x40")

    def test__ip4__option__cipso__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects a kind byte above
        Ip4OptionType.CIPSO, pinning the equality check against a
        '>=' relaxation.

        Reference: FIPS-188 §A.1 (CIPSO option kind byte).
        """

        with self.assertRaises(AssertionError):
            Ip4OptionCipso.from_buffer(b"\xff\x0e\xde\xad\xbe\xef\x01\x08\x00\x00\x10\x20\x30\x40")


class TestIp4OptionCipsoMinimalTag(TestCase):
    """
    The IPv4 CIPSO option minimal-tag boundary parser tests.
    """

    def test__ip4__option__cipso__from_buffer_minimal_tag_accepted(self) -> None:
        """
        Ensure 'from_buffer()' accepts a tag occupying exactly
        TAG_HDR_LEN (2) bytes — a type+length header with no tag data —
        pinning both the walker's 'remaining < TAG_HDR_LEN' check and
        the per-tag 'tag_len < TAG_HDR_LEN' check against a '<='
        over-rejection of the inclusive minimum.

        Reference: FIPS-188 §A.3 (a CIPSO tag is at least 2 octets: type + length).
        """

        # IPv4 CIPSO option, one 2-byte tag (the inclusive minimum):
        #   Byte 0     : 0x86       -> type=CIPSO (134)
        #   Byte 1     : 0x08       -> len=8 (2 header + 4 DOI + 2 tag)
        #   Bytes 2-5  : 0x01020304 -> doi
        #   Bytes 6-7  : 0x05 0x02  -> tag: type=5, length=2 (no data)
        decoded = Ip4OptionCipso.from_buffer(b"\x86\x08\x01\x02\x03\x04\x05\x02")

        self.assertEqual(
            [bytes(tag) for tag in decoded.tags],
            [b"\x05\x02"],
            msg=f"A minimal 2-byte CIPSO tag must round-trip intact. Got {decoded.tags!r}.",
        )
