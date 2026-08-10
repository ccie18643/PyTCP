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
This module contains tests for the NetProto ProtoEnum base enum class.

net_proto/tests/unit/lib/test__lib__proto_enum.py

ver 3.0.10
"""

import enum
import os
import subprocess
import sys
from typing import override
from unittest import TestCase

from net_proto.lib.proto_enum import ProtoEnum, ProtoEnumByte, ProtoEnumWord


class TestNetProtoLibProtoEnumNoAenum(TestCase):
    """
    The NetProto ProtoEnum stdlib-only (no 'aenum') contract tests.
    """

    def test__net_proto__lib__proto_enum__import_does_not_pull_aenum(self) -> None:
        """
        Ensure importing net_proto (hence proto_enum) does not import
        the third-party 'aenum' package — the unknown-codepoint
        mechanism is native stdlib 'enum'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        env = {**os.environ, "PYTHONPATH": ""}
        result = subprocess.run(
            [sys.executable, "-c", "import sys, net_proto; print('aenum' in sys.modules)"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"Probe interpreter must exit cleanly. stderr: {result.stderr!r}",
        )
        self.assertEqual(
            result.stdout.strip(),
            "False",
            msg="Importing net_proto must not pull in the 'aenum' dependency.",
        )

    def test__net_proto__lib__proto_enum__base_is_stdlib_enum(self) -> None:
        """
        Ensure 'ProtoEnum' is built on the standard-library
        'enum.Enum', not a third-party enum implementation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIn(
            enum.Enum,
            ProtoEnum.__mro__,
            msg="ProtoEnum must subclass the stdlib enum.Enum.",
        )
        self.assertEqual(
            type(ProtoEnum).__module__,
            "enum",
            msg="ProtoEnum's metaclass must be the stdlib enum metaclass.",
        )

    def test__net_proto__lib__proto_enum__direct_call_stays_strict(self) -> None:
        """
        Ensure the strict 'cls(value)' constructor still raises for
        an unrecognised value — only 'from_int' is tolerant. This
        preserves the aenum-era contract that parsers rely on to
        reject invalid codes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class WordEnum(ProtoEnumWord):
            KNOWN = 0x0800

        with self.assertRaises(ValueError):
            WordEnum(0x4242)

    def test__net_proto__lib__proto_enum__from_int_unknown_then_cached(self) -> None:
        """
        Ensure that once 'from_int' has materialised an unknown,
        the strict 'cls(value)' resolves to that same cached
        member (mirrors aenum post-'extend_enum' behaviour) and
        the member is a genuine instance of the enum class.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class WordEnum(ProtoEnumWord):
            KNOWN = 0x0800

        member = WordEnum.from_int(0x4242)

        self.assertIsInstance(
            member,
            WordEnum,
            msg="An unknown member must be a genuine instance of the enum class.",
        )
        self.assertIs(
            WordEnum(0x4242),
            member,
            msg="After from_int(), strict WordEnum(value) must return the same cached member.",
        )
        self.assertIs(
            WordEnum.from_int(0x4242),
            member,
            msg="Repeated from_int() on the same unknown must be identity-stable.",
        )


class TestNetProtoLibProtoEnumHierarchy(TestCase):
    """
    The NetProto ProtoEnum class hierarchy tests.
    """

    def test__net_proto__lib__proto_enum__byte_is_proto_enum(self) -> None:
        """
        Ensure 'ProtoEnumByte' subclasses 'ProtoEnum'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(issubclass(ProtoEnumByte, ProtoEnum))

    def test__net_proto__lib__proto_enum__word_is_proto_enum(self) -> None:
        """
        Ensure 'ProtoEnumWord' subclasses 'ProtoEnum'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(issubclass(ProtoEnumWord, ProtoEnum))


class TestNetProtoLibProtoEnumByteBasics(TestCase):
    """
    The NetProto ProtoEnumByte known-member tests.
    """

    @override
    def setUp(self) -> None:
        class ByteEnum(ProtoEnumByte):
            """Test-scoped byte enum."""

            ALPHA = 0x01
            BETA_GAMMA = 0x02

        self._enum = ByteEnum

    def test__net_proto__lib__proto_enum__byte__int(self) -> None:
        """
        Ensure 'int()' returns the numeric value of a known byte member.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(int(self._enum.ALPHA), 0x01)
        self.assertEqual(int(self._enum.BETA_GAMMA), 0x02)

    def test__net_proto__lib__proto_enum__byte__str(self) -> None:
        """
        Ensure '__str__()' title-cases the member name and strips underscores.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(str(self._enum.ALPHA), "Alpha")
        self.assertEqual(str(self._enum.BETA_GAMMA), "Beta Gamma")

    def test__net_proto__lib__proto_enum__byte__bytes(self) -> None:
        """
        Ensure 'bytes()' serializes a ProtoEnumByte member as one big-endian byte.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(bytes(self._enum.ALPHA), b"\x01")
        self.assertEqual(bytes(self._enum.BETA_GAMMA), b"\x02")

    def test__net_proto__lib__proto_enum__byte__is_unknown_false(self) -> None:
        """
        Ensure known byte enum members report 'is_unknown' as False.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(self._enum.ALPHA.is_unknown)
        self.assertFalse(self._enum.BETA_GAMMA.is_unknown)

    def test__net_proto__lib__proto_enum__byte__get_known_values(self) -> None:
        """
        Ensure 'get_known_values()' returns every declared member value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            sorted(self._enum.get_known_values()),
            [0x01, 0x02],
        )

    def test__net_proto__lib__proto_enum__byte__contains_instance(self) -> None:
        """
        Ensure the overridden instance-level '__contains__' uses known values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIn(0x01, self._enum.ALPHA)
        self.assertNotIn(0x99, self._enum.ALPHA)


class TestNetProtoLibProtoEnumByteFromInt(TestCase):
    """
    The NetProto ProtoEnumByte from_int() tests.
    """

    @override
    def setUp(self) -> None:
        class ByteEnum(ProtoEnumByte):
            KNOWN = 5

        self._enum = ByteEnum

    def test__net_proto__lib__proto_enum__byte__from_int_known(self) -> None:
        """
        Ensure 'from_int()' returns the known member for its declared value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(self._enum.from_int(5), self._enum.KNOWN)

    def test__net_proto__lib__proto_enum__byte__from_int_unknown(self) -> None:
        """
        Ensure 'from_int()' registers and returns an 'UNKNOWN_{value}' member.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        member = self._enum.from_int(77)

        self.assertEqual(member.value, 77)
        self.assertTrue(member.is_unknown)
        self.assertEqual(member.name, "UNKNOWN_77")

    def test__net_proto__lib__proto_enum__byte__from_int_unknown_idempotent(
        self,
    ) -> None:
        """
        Ensure repeated 'from_int()' on the same unknown value returns the same member.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = self._enum.from_int(123)
        second = self._enum.from_int(123)

        self.assertIs(first, second)

    def test__net_proto__lib__proto_enum__byte__unknown_excluded_from_known_values(
        self,
    ) -> None:
        """
        Ensure newly registered unknowns are not reported by 'get_known_values()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._enum.from_int(200)

        self.assertNotIn(200, self._enum.get_known_values())

    def test__net_proto__lib__proto_enum__byte__unknown_str_title(self) -> None:
        """
        Ensure 'UNKNOWN_{value}' renders via the default 'title()' formatter
        on the base ProtoEnum class (ProtoEnumByte does not override __str__).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        member = self._enum.from_int(45)
        self.assertEqual(str(member), "Unknown 45")


class TestNetProtoLibProtoEnumByteFromBytes(TestCase):
    """
    The NetProto ProtoEnumByte from_bytes() tests.
    """

    @override
    def setUp(self) -> None:
        class ByteEnum(ProtoEnumByte):
            A = 0x10
            B = 0xFE

        self._enum = ByteEnum

    def test__net_proto__lib__proto_enum__byte__from_bytes_known(self) -> None:
        """
        Ensure 'from_bytes()' returns the known member for an exact single-byte input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(self._enum.from_bytes(b"\x10"), self._enum.A)
        self.assertIs(self._enum.from_bytes(b"\xfe"), self._enum.B)

    def test__net_proto__lib__proto_enum__byte__from_bytes_truncates(self) -> None:
        """
        Ensure 'from_bytes()' only consumes the first byte of the input buffer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(self._enum.from_bytes(b"\x10\xff\xab"), self._enum.A)

    def test__net_proto__lib__proto_enum__byte__from_bytes_unknown(self) -> None:
        """
        Ensure 'from_bytes()' registers and returns an unknown for a novel value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        member = self._enum.from_bytes(b"\x99")

        self.assertEqual(member.value, 0x99)
        self.assertTrue(member.is_unknown)

    def test__net_proto__lib__proto_enum__byte__from_bytes_empty(self) -> None:
        """
        Ensure 'from_bytes()' treats an empty buffer as the integer value 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        member = self._enum.from_bytes(b"")

        self.assertEqual(member.value, 0)
        self.assertTrue(member.is_unknown)


class TestNetProtoLibProtoEnumWordBasics(TestCase):
    """
    The NetProto ProtoEnumWord known-member tests.
    """

    @override
    def setUp(self) -> None:
        class WordEnum(ProtoEnumWord):
            HEAD = 0x1234
            TAIL_END = 0xABCD

        self._enum = WordEnum

    def test__net_proto__lib__proto_enum__word__int(self) -> None:
        """
        Ensure 'int()' returns the numeric value of a known word member.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(int(self._enum.HEAD), 0x1234)
        self.assertEqual(int(self._enum.TAIL_END), 0xABCD)

    def test__net_proto__lib__proto_enum__word__bytes(self) -> None:
        """
        Ensure 'bytes()' serializes a ProtoEnumWord member as two big-endian bytes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(bytes(self._enum.HEAD), b"\x12\x34")
        self.assertEqual(bytes(self._enum.TAIL_END), b"\xab\xcd")

    def test__net_proto__lib__proto_enum__word__str(self) -> None:
        """
        Ensure '__str__()' title-cases the member name and strips underscores.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(str(self._enum.HEAD), "Head")
        self.assertEqual(str(self._enum.TAIL_END), "Tail End")

    def test__net_proto__lib__proto_enum__word__is_unknown_false(self) -> None:
        """
        Ensure known word enum members report 'is_unknown' as False.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(self._enum.HEAD.is_unknown)
        self.assertFalse(self._enum.TAIL_END.is_unknown)


class TestNetProtoLibProtoEnumWordFromInt(TestCase):
    """
    The NetProto ProtoEnumWord from_int() tests.
    """

    @override
    def setUp(self) -> None:
        class WordEnum(ProtoEnumWord):
            KNOWN = 0x0800

        self._enum = WordEnum

    def test__net_proto__lib__proto_enum__word__from_int_known(self) -> None:
        """
        Ensure 'from_int()' returns the known member for its declared value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(self._enum.from_int(0x0800), self._enum.KNOWN)

    def test__net_proto__lib__proto_enum__word__from_int_unknown(self) -> None:
        """
        Ensure 'from_int()' registers and returns an 'UNKNOWN_{value}' member.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        member = self._enum.from_int(0xABCD)

        self.assertEqual(member.value, 0xABCD)
        self.assertTrue(member.is_unknown)
        self.assertEqual(member.name, f"UNKNOWN_{0xABCD}")

    def test__net_proto__lib__proto_enum__word__from_int_unknown_idempotent(
        self,
    ) -> None:
        """
        Ensure repeated 'from_int()' on the same unknown value returns the same member.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = self._enum.from_int(0x1000)
        second = self._enum.from_int(0x1000)

        self.assertIs(first, second)


class TestNetProtoLibProtoEnumWordFromBytes(TestCase):
    """
    The NetProto ProtoEnumWord from_bytes() tests.
    """

    @override
    def setUp(self) -> None:
        class WordEnum(ProtoEnumWord):
            A = 0x0102
            B = 0xFFEE

        self._enum = WordEnum

    def test__net_proto__lib__proto_enum__word__from_bytes_known(self) -> None:
        """
        Ensure 'from_bytes()' returns the known member for an exact two-byte input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(self._enum.from_bytes(b"\x01\x02"), self._enum.A)
        self.assertIs(self._enum.from_bytes(b"\xff\xee"), self._enum.B)

    def test__net_proto__lib__proto_enum__word__from_bytes_truncates(self) -> None:
        """
        Ensure 'from_bytes()' only consumes the first two bytes of the buffer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(self._enum.from_bytes(b"\x01\x02\xff\xff"), self._enum.A)

    def test__net_proto__lib__proto_enum__word__from_bytes_unknown(self) -> None:
        """
        Ensure 'from_bytes()' registers and returns an unknown for a novel value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        member = self._enum.from_bytes(b"\xde\xad")

        self.assertEqual(member.value, 0xDEAD)
        self.assertTrue(member.is_unknown)

    def test__net_proto__lib__proto_enum__word__from_bytes_short(self) -> None:
        """
        Ensure 'from_bytes()' accepts a single-byte input and treats it as 0x00XX.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        member = self._enum.from_bytes(b"\x05")

        self.assertEqual(member.value, 0x05)

    def test__net_proto__lib__proto_enum__word__from_bytes_empty(self) -> None:
        """
        Ensure 'from_bytes()' treats an empty buffer as the integer value 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        member = self._enum.from_bytes(b"")

        self.assertEqual(member.value, 0)
        self.assertTrue(member.is_unknown)
