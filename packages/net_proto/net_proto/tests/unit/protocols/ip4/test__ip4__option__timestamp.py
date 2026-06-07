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
Module contains tests for the IPv4 Timestamp option code (RFC 791 §3.1).

net_proto/tests/unit/protocols/ip4/test__ip4__option__timestamp.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    Ip4IntegrityError,
    Ip4OptionTimestamp,
    Ip4OptionTimestampFlag,
    Ip4OptionType,
    Ip4TimestampEntry,
)
from net_proto.lib.proto_enum import ProtoEnumByte
from net_proto.tests.lib.parameterized import parameterized_class


class TestIp4OptionTimestampFlagEnum(TestCase):
    """
    The IPv4 Timestamp option 'flag' codepoint enum tests.
    """

    def test__ip4__option__timestamp__flag_is_proto_enum_byte(self) -> None:
        """
        Ensure 'Ip4OptionTimestampFlag' is a 'ProtoEnumByte' whose
        members carry the defined codepoint integers (0/1/3, with 2 the
        reserved gap), so the flag is a typed wire codepoint rather than
        a bare int.

        Reference: RFC 791 §3.1 (flag 0 = TS only, 1 = TS+addr, 3 = prespecified).
        """

        self.assertTrue(
            issubclass(Ip4OptionTimestampFlag, ProtoEnumByte),
            msg="Ip4OptionTimestampFlag must be a ProtoEnumByte.",
        )
        self.assertEqual(
            (
                int(Ip4OptionTimestampFlag.TS_ONLY),
                int(Ip4OptionTimestampFlag.TS_AND_ADDR),
                int(Ip4OptionTimestampFlag.TS_PRESPEC),
            ),
            (0, 1, 3),
            msg="The TS_ONLY / TS_AND_ADDR / TS_PRESPEC members must carry codepoints 0 / 1 / 3.",
        )


class TestIp4OptionTimestampAsserts(TestCase):
    """
    The IPv4 Timestamp option constructor argument assert tests.
    """

    def test__ip4__option__timestamp__pointer__under_min(self) -> None:
        """
        Ensure the IPv4 Timestamp option constructor rejects a 'pointer'
        below the canonical minimum of 5 (the byte offset where entry
        data begins).

        Reference: RFC 791 §3.1 (Timestamp pointer minimum is 5).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionTimestamp(
                pointer=4,
                overflow=0,
                flag=Ip4OptionTimestampFlag.TS_ONLY,
                entries=[Ip4TimestampEntry(timestamp=0)],
            )

        self.assertEqual(
            str(error.exception),
            "The 'pointer' field must be at least 5. Got: 4",
            msg="Unexpected assertion message for 'pointer' < 5.",
        )

    def test__ip4__option__timestamp__overflow__over_max(self) -> None:
        """
        Ensure the constructor rejects 'overflow' values that don't
        fit in the 4-bit wire field.

        Reference: RFC 791 §3.1 (Timestamp overflow field is 4 bits).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionTimestamp(
                pointer=5,
                overflow=16,
                flag=Ip4OptionTimestampFlag.TS_ONLY,
                entries=[Ip4TimestampEntry(timestamp=0)],
            )

        self.assertEqual(
            str(error.exception),
            "The 'overflow' field must fit in 4 bits (0..15). Got: 16",
            msg="Unexpected assertion message for 'overflow' > 15.",
        )

    def test__ip4__option__timestamp__flag__invalid(self) -> None:
        """
        Ensure the constructor rejects flag values other than 0, 1, 3.
        Flag 2 is reserved and not defined.

        Reference: RFC 791 §3.1 (Timestamp flag is one of 0, 1, 3).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionTimestamp(
                pointer=5,
                overflow=0,
                flag=Ip4OptionTimestampFlag.from_int(2),
                entries=[Ip4TimestampEntry(timestamp=0)],
            )

        self.assertEqual(
            str(error.exception),
            "The 'flag' field must be one of {0, 1, 3}. Got: 2",
            msg="Unexpected assertion message for invalid 'flag'.",
        )

    def test__ip4__option__timestamp__pointer__misaligned_for_flag_0(self) -> None:
        """
        Ensure the constructor rejects a pointer that doesn't land on
        a 4-byte boundary when flag=0 (timestamp-only entries).

        Reference: RFC 791 §3.1 (entry size is 4 bytes for flag=0).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionTimestamp(
                pointer=6,
                overflow=0,
                flag=Ip4OptionTimestampFlag.TS_ONLY,
                entries=[Ip4TimestampEntry(timestamp=0)],
            )

        self.assertEqual(
            str(error.exception),
            "The 'pointer' field must be aligned to the 4-byte entry boundary for flag=0. Got: 6",
            msg="Unexpected assertion message for misaligned 'pointer' (flag=0).",
        )

    def test__ip4__option__timestamp__pointer__misaligned_for_flag_1(self) -> None:
        """
        Ensure the constructor rejects a pointer that doesn't land on
        an 8-byte boundary when flag=1 (addr+timestamp entries).

        Reference: RFC 791 §3.1 (entry size is 8 bytes for flag=1).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionTimestamp(
                pointer=9,
                overflow=0,
                flag=Ip4OptionTimestampFlag.TS_AND_ADDR,
                entries=[Ip4TimestampEntry(timestamp=0, address=Ip4Address("10.0.0.1"))],
            )

        self.assertEqual(
            str(error.exception),
            "The 'pointer' field must be aligned to the 8-byte entry boundary for flag=1. Got: 9",
            msg="Unexpected assertion message for misaligned 'pointer' (flag=1).",
        )

    def test__ip4__option__timestamp__entries__empty(self) -> None:
        """
        Ensure the constructor rejects an empty entries list — a
        Timestamp option with zero entries is meaningless.

        Reference: RFC 791 §3.1 (Timestamp option must carry at least
        one entry slot).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionTimestamp(
                pointer=5,
                overflow=0,
                flag=Ip4OptionTimestampFlag.TS_ONLY,
                entries=[],
            )

        self.assertEqual(
            str(error.exception),
            "The 'entries' field must have at least 1 entry. Got: 0",
            msg="Unexpected assertion message for empty 'entries'.",
        )

    def test__ip4__option__timestamp__entries__overflows_uint8_length(self) -> None:
        """
        Ensure the constructor rejects an entries list whose total
        option length (4-byte header + 4-byte ts-only entry per
        entry, for flag=0) would overflow the single-octet
        option-length byte. With 64 ts-only entries the total is
        4 + 4*64 = 260 > 255.

        Reference: RFC 791 §3.1 (option-length byte is one octet).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionTimestamp(
                pointer=5,
                overflow=0,
                flag=Ip4OptionTimestampFlag.TS_ONLY,
                entries=[Ip4TimestampEntry(timestamp=0) for _ in range(64)],
            )

        self.assertIn(
            "must fit in a single uint8 length byte",
            str(error.exception),
            msg="AssertionError must cite the uint8 length-byte overflow.",
        )

    def test__ip4__option__timestamp__entries__address_mismatch_flag_0(self) -> None:
        """
        Ensure the constructor rejects entries that carry an address
        when flag=0 (timestamp-only mode).

        Reference: RFC 791 §3.1 (flag=0 entries are 4-byte timestamps,
        no address).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionTimestamp(
                pointer=5,
                overflow=0,
                flag=Ip4OptionTimestampFlag.TS_ONLY,
                entries=[Ip4TimestampEntry(timestamp=0, address=Ip4Address("10.0.0.1"))],
            )

        self.assertIn(
            "All entries must be timestamp-only (no address) when flag=0",
            str(error.exception),
            msg="Unexpected assertion message for address-with-flag-0.",
        )

    def test__ip4__option__timestamp__entries__address_missing_flag_1(self) -> None:
        """
        Ensure the constructor rejects entries that lack an address
        when flag=1 (addr+timestamp mode).

        Reference: RFC 791 §3.1 (flag=1 entries are 8-byte addr+timestamp).
        """

        with self.assertRaises(AssertionError) as error:
            Ip4OptionTimestamp(
                pointer=5,
                overflow=0,
                flag=Ip4OptionTimestampFlag.TS_AND_ADDR,
                entries=[Ip4TimestampEntry(timestamp=0)],
            )

        self.assertIn(
            "All entries must carry an address when flag=1",
            str(error.exception),
            msg="Unexpected assertion message for missing-address-with-flag-1.",
        )


@parameterized_class(
    [
        {
            "_description": "Timestamp option flag=0 (TS only) with one entry, pointer at start.",
            "_pointer": 5,
            "_overflow": 0,
            "_flag": Ip4OptionTimestampFlag.TS_ONLY,
            "_entries": [Ip4TimestampEntry(timestamp=0)],
            "_results": {
                "__len__": 8,
                "__str__": "timestamp [0] ptr=5 oflw=0 flag=0",
                "__repr__": (
                    "Ip4OptionTimestamp(pointer=5, overflow=0, flag=<Ip4OptionTimestampFlag.TS_ONLY: 0>, "
                    "entries=[Ip4TimestampEntry(timestamp=0, address=None)])"
                ),
                # IPv4 Timestamp wire frame (8 bytes):
                #   Byte 0     : 0x44   -> type=Ip4OptionType.TIMESTAMP (68)
                #   Byte 1     : 0x08   -> len=8 (4-byte hdr + 1x 4-byte entry)
                #   Byte 2     : 0x05   -> pointer=5 (slot 0)
                #   Byte 3     : 0x00   -> overflow=0 (high nibble) | flag=0 (low nibble)
                #   Bytes 4-7  : 0x00000000 -> entry[0].timestamp=0
                "__bytes__": b"\x44\x08\x05\x00\x00\x00\x00\x00",
            },
        },
        {
            "_description": "Timestamp option flag=0 (TS only) with two entries, pointer past last.",
            "_pointer": 13,
            "_overflow": 0,
            "_flag": Ip4OptionTimestampFlag.TS_ONLY,
            "_entries": [
                Ip4TimestampEntry(timestamp=1234),
                Ip4TimestampEntry(timestamp=5678),
            ],
            "_results": {
                "__len__": 12,
                "__str__": "timestamp [1234, 5678] ptr=13 oflw=0 flag=0",
                "__repr__": (
                    "Ip4OptionTimestamp(pointer=13, overflow=0, flag=<Ip4OptionTimestampFlag.TS_ONLY: 0>, "
                    "entries=[Ip4TimestampEntry(timestamp=1234, address=None), "
                    "Ip4TimestampEntry(timestamp=5678, address=None)])"
                ),
                # IPv4 Timestamp wire frame (12 bytes):
                #   Byte 0     : 0x44       -> type=68
                #   Byte 1     : 0x0c       -> len=12 (4-byte hdr + 2x 4-byte entry)
                #   Byte 2     : 0x0d       -> pointer=13 (past last slot)
                #   Byte 3     : 0x00       -> overflow=0 | flag=0
                #   Bytes 4-7  : 0x000004d2 -> entry[0].timestamp=1234
                #   Bytes 8-11 : 0x0000162e -> entry[1].timestamp=5678
                "__bytes__": (b"\x44\x0c\x0d\x00\x00\x00\x04\xd2\x00\x00\x16\x2e"),
            },
        },
        {
            "_description": "Timestamp option flag=1 (addr+TS) with two entries.",
            "_pointer": 21,
            "_overflow": 3,
            "_flag": Ip4OptionTimestampFlag.TS_AND_ADDR,
            "_entries": [
                Ip4TimestampEntry(timestamp=1234, address=Ip4Address("10.0.0.1")),
                Ip4TimestampEntry(timestamp=5678, address=Ip4Address("10.0.0.2")),
            ],
            "_results": {
                "__len__": 20,
                "__str__": ("timestamp [10.0.0.1:1234, 10.0.0.2:5678] ptr=21 oflw=3 flag=1"),
                "__repr__": (
                    "Ip4OptionTimestamp(pointer=21, overflow=3, flag=<Ip4OptionTimestampFlag.TS_AND_ADDR: 1>, entries=["
                    "Ip4TimestampEntry(timestamp=1234, address=Ip4Address('10.0.0.1')), "
                    "Ip4TimestampEntry(timestamp=5678, address=Ip4Address('10.0.0.2'))])"
                ),
                # IPv4 Timestamp wire frame (20 bytes):
                #   Byte 0      : 0x44       -> type=68
                #   Byte 1      : 0x14       -> len=20 (4-byte hdr + 2x 8-byte entry)
                #   Byte 2      : 0x15       -> pointer=21 (past last slot)
                #   Byte 3      : 0x31       -> overflow=3 (high) | flag=1 (low)
                #   Bytes 4-7   : 0x0a000001 -> entry[0].address=10.0.0.1
                #   Bytes 8-11  : 0x000004d2 -> entry[0].timestamp=1234
                #   Bytes 12-15 : 0x0a000002 -> entry[1].address=10.0.0.2
                #   Bytes 16-19 : 0x0000162e -> entry[1].timestamp=5678
                "__bytes__": (
                    b"\x44\x14\x15\x31" b"\x0a\x00\x00\x01\x00\x00\x04\xd2" b"\x0a\x00\x00\x02\x00\x00\x16\x2e"
                ),
            },
        },
        {
            "_description": "Timestamp option flag=3 (prespecified addrs) with one entry.",
            "_pointer": 13,
            "_overflow": 0,
            "_flag": Ip4OptionTimestampFlag.TS_PRESPEC,
            "_entries": [
                Ip4TimestampEntry(timestamp=1234, address=Ip4Address("10.0.0.1")),
            ],
            "_results": {
                "__len__": 12,
                "__str__": "timestamp [10.0.0.1:1234] ptr=13 oflw=0 flag=3",
                "__repr__": (
                    "Ip4OptionTimestamp(pointer=13, overflow=0, flag=<Ip4OptionTimestampFlag.TS_PRESPEC: 3>, entries=["
                    "Ip4TimestampEntry(timestamp=1234, address=Ip4Address('10.0.0.1'))])"
                ),
                # IPv4 Timestamp wire frame (12 bytes, flag=3):
                #   Byte 0     : 0x44       -> type=68
                #   Byte 1     : 0x0c       -> len=12
                #   Byte 2     : 0x0d       -> pointer=13
                #   Byte 3     : 0x03       -> overflow=0 | flag=3
                #   Bytes 4-7  : 0x0a000001 -> entry[0].address
                #   Bytes 8-11 : 0x000004d2 -> entry[0].timestamp
                "__bytes__": b"\x44\x0c\x0d\x03\x0a\x00\x00\x01\x00\x00\x04\xd2",
            },
        },
    ]
)
class TestIp4OptionTimestampAssembler(TestCase):
    """
    The IPv4 Timestamp option assembler tests.
    """

    _description: str
    _pointer: int
    _overflow: int
    _flag: Ip4OptionTimestampFlag
    _entries: list[Ip4TimestampEntry]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an Ip4OptionTimestamp from the parametrized fields.
        """

        self._option = Ip4OptionTimestamp(
            pointer=self._pointer,
            overflow=self._overflow,
            flag=self._flag,
            entries=self._entries,
        )

    def test__ip4__option__timestamp__len(self) -> None:
        """
        Ensure '__len__' reports the canonical 4-byte header plus
        per-entry size (4 for flag=0, 8 for flag=1/3) times entry count.

        Reference: RFC 791 §3.1 (Timestamp length = 4 + entry_size * N).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected '__len__' for case: {self._description}",
        )

    def test__ip4__option__timestamp__str(self) -> None:
        """
        Ensure '__str__' renders entries, pointer, overflow and flag in
        a readable single-line log form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected '__str__' for case: {self._description}",
        )

    def test__ip4__option__timestamp__repr(self) -> None:
        """
        Ensure '__repr__' is the canonical dataclass form with pointer,
        overflow, flag, and entries as visible fields.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected '__repr__' for case: {self._description}",
        )

    def test__ip4__option__timestamp__bytes(self) -> None:
        """
        Ensure 'bytes()' serialises the option to the canonical RFC 791
        wire format: type=68 / length / pointer / packed (overflow|flag)
        / N entries.

        Reference: RFC 791 §3.1 (Timestamp wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected 'bytes()' for case: {self._description}",
        )

    def test__ip4__option__timestamp__type(self) -> None:
        """
        Ensure the option's 'type' field is Ip4OptionType.TIMESTAMP
        (the wire value 68) regardless of construction arguments.

        Reference: RFC 791 §3.1 (Timestamp type byte = 68).
        """

        self.assertIs(
            self._option.type,
            Ip4OptionType.TIMESTAMP,
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__ip4__option__timestamp__roundtrip(self) -> None:
        """
        Ensure an option assembled to bytes and re-parsed via
        'from_buffer' equals the original — pointer, overflow, flag,
        entries all round-trip without loss for every flag value.

        Reference: RFC 791 §3.1 (Timestamp wire format).
        """

        roundtripped = Ip4OptionTimestamp.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            roundtripped,
            self._option,
            msg=f"Unexpected roundtrip result for case: {self._description}",
        )


class TestIp4OptionTimestampIntegrity(TestCase):
    """
    The IPv4 Timestamp option 'from_buffer' integrity-check tests.
    """

    def test__ip4__option__timestamp__integrity__flag__invalid(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the wire
        flag value is not one of {0, 1, 3}.

        Reference: RFC 791 §3.1 (Timestamp flag must be 0, 1, or 3).
        """

        # Bytes: type=0x44, len=8, pointer=5, oflw|flag=0x02 (flag=2 reserved)
        buffer = b"\x44\x08\x05\x02\x00\x00\x00\x00"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionTimestamp.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Timestamp option flag value must be one of {0, 1, 3}. Got: 2",
            msg="Unexpected integrity-error message for invalid flag.",
        )

    def test__ip4__option__timestamp__integrity__length__under_min(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the encoded
        length byte is below the minimum for the chosen flag (8 for
        flag=0).

        Reference: RFC 791 §3.1 (Timestamp length >= 4 + entry_size).
        """

        # Bytes: type=0x44, len=7 (one byte short for flag=0), pointer=5, oflw|flag=0
        buffer = b"\x44\x07\x05\x00\x00\x00\x00"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionTimestamp.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Timestamp option length must be at least 8 bytes for flag=0. Got: 7",
            msg="Unexpected integrity-error message for length < 8 (flag=0).",
        )

    def test__ip4__option__timestamp__integrity__entries_misaligned(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the entries
        section length is not a multiple of the per-entry size.

        Reference: RFC 791 §3.1 (entries are fixed-size 4 or 8 bytes).
        """

        # Bytes: type=0x44, len=11 (4-byte hdr + 7 bytes — not a multiple of 4 entry slot),
        # pointer=5, flag=0, partial entry
        buffer = b"\x44\x0b\x05\x00\x00\x00\x00\x00\xff\xff\xff"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionTimestamp.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv4] The IPv4 Timestamp option entries length must "
                "be a multiple of 4 bytes for flag=0. Got: 11"
            ),
            msg="Unexpected integrity-error message for misaligned entries.",
        )

    def test__ip4__option__timestamp__integrity__pointer__under_base(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the wire
        pointer byte is below the canonical minimum of 5 (the byte
        offset where entry data begins). Hostile-wire defense-in-depth
        — the __post_init__ assert would otherwise leak as a bare
        AssertionError.

        Reference: RFC 791 §3.1 (Timestamp pointer minimum is 5).
        """

        # Bytes: type=0x44, len=8, pointer=4 (< 5), oflw|flag=0, one ts entry.
        buffer = b"\x44\x08\x04\x00\x00\x00\x00\x00"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionTimestamp.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 Timestamp option pointer must be at least 5. Got: 4",
            msg="Unexpected integrity-error message for pointer < 5.",
        )

    def test__ip4__option__timestamp__integrity__pointer__misaligned(self) -> None:
        """
        Ensure 'from_buffer' raises Ip4IntegrityError when the wire
        pointer is not aligned to the per-entry boundary implied by
        the flag (4 bytes for flag=0; 8 bytes for flag=1/3).

        Reference: RFC 791 §3.1 (pointer addresses the next entry slot).
        """

        # Bytes: type=0x44, len=8, pointer=6 (mid-entry for flag=0), flag=0, ts entry.
        # (pointer - 5) % 4 = 1 ≠ 0 → misaligned.
        buffer = b"\x44\x08\x06\x00\x00\x00\x00\x00"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4OptionTimestamp.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv4] The IPv4 Timestamp option pointer must be aligned "
                "to the 4-byte entry boundary for flag=0. Got: 6"
            ),
            msg="Unexpected integrity-error message for misaligned pointer (flag=0).",
        )
