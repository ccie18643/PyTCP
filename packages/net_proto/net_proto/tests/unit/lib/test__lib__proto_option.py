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
This module contains tests for the NetProto ProtoOption/ProtoOptions base classes.

net_proto/tests/unit/lib/test__lib__proto_option.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError, dataclass
from typing import Self, override
from unittest import TestCase

from net_proto.lib.buffer import Buffer
from net_proto.lib.proto_enum import ProtoEnumByte
from net_proto.lib.proto_option import (
    ProtoOption,
    ProtoOptions,
    ProtoOptionType,
)
from net_proto.lib.proto_struct import ProtoStruct


class _FixtureOptionType(ProtoOptionType):
    """Fixture enum used to exercise ProtoOption subclasses."""

    A = 1
    B = 2
    C = 3


@dataclass(frozen=True, kw_only=True, slots=True)
class _FixtureOption(ProtoOption):
    """Minimal concrete ProtoOption used as a fixture."""

    @override
    def __post_init__(self) -> None:
        assert self.len >= 1, f"'len' must be at least 1. Got: {self.len}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        return memoryview(bytes(self.type) + self.len.to_bytes(1, "big"))

    @classmethod
    @override
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        return cls(
            type=_FixtureOptionType.from_bytes(bytes(buffer[:1])),
            len=int(buffer[1]),
        )


class _FixtureOptions(ProtoOptions):
    """Minimal concrete ProtoOptions container used as a fixture."""

    @classmethod
    @override
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        options: list[ProtoOption] = []
        offset = 0
        while offset < len(buffer):
            option = _FixtureOption.from_buffer(buffer[offset:])
            options.append(option)
            offset += len(option)
        return cls(*options)


class _OtherFixtureOptions(ProtoOptions):
    """Second container class used to exercise cross-type inequality."""

    @classmethod
    @override
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        return cls()


class TestNetProtoLibProtoOptionType(TestCase):
    """
    The NetProto ProtoOptionType tests.
    """

    def test__net_proto__lib__proto_option__option_type_subclasses_byte_enum(
        self,
    ) -> None:
        """
        Ensure 'ProtoOptionType' inherits the byte-sized proto enum behavior.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(issubclass(ProtoOptionType, ProtoEnumByte))

    def test__net_proto__lib__proto_option__option_type_serializes_to_byte(
        self,
    ) -> None:
        """
        Ensure a ProtoOptionType subclass member serializes to a single byte.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(bytes(_FixtureOptionType.A), b"\x01")
        self.assertEqual(bytes(_FixtureOptionType.B), b"\x02")


class TestNetProtoLibProtoOptionAbstract(TestCase):
    """
    The NetProto ProtoOption abstract-class contract tests.
    """

    def test__net_proto__lib__proto_option__is_proto_struct(self) -> None:
        """
        Ensure 'ProtoOption' subclasses 'ProtoStruct'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(issubclass(ProtoOption, ProtoStruct))

    def test__net_proto__lib__proto_option__cannot_instantiate_base(self) -> None:
        """
        Ensure 'ProtoOption' cannot be instantiated directly because it still
        carries abstract methods from 'ProtoStruct'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            ProtoOption(type=_FixtureOptionType.A, len=1)  # type: ignore[abstract]


class TestNetProtoLibProtoOptionConcrete(TestCase):
    """
    The NetProto ProtoOption concrete-subclass behavior tests.
    """

    @override
    def setUp(self) -> None:
        self._option = _FixtureOption(type=_FixtureOptionType.A, len=2)

    def test__net_proto__lib__proto_option__fields(self) -> None:
        """
        Ensure the subclass exposes the 'type' and 'len' fields.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(self._option.type, _FixtureOptionType.A)
        self.assertEqual(self._option.len, 2)

    def test__net_proto__lib__proto_option__len_returns_len_field(self) -> None:
        """
        Ensure 'len()' returns the value of the 'len' field, not structure size.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(len(self._option), 2)
        self.assertEqual(len(_FixtureOption(type=_FixtureOptionType.A, len=10)), 10)

    def test__net_proto__lib__proto_option__is_frozen(self) -> None:
        """
        Ensure ProtoOption fields cannot be mutated after construction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(FrozenInstanceError):
            self._option.len = 99  # type: ignore[misc]

    def test__net_proto__lib__proto_option__post_init_runs(self) -> None:
        """
        Ensure the concrete '__post_init__()' hook runs during construction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            _FixtureOption(type=_FixtureOptionType.A, len=0)

    def test__net_proto__lib__proto_option__buffer_protocol(self) -> None:
        """
        Ensure the concrete subclass serializes via 'memoryview()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(bytes(memoryview(self._option)), b"\x01\x02")

    def test__net_proto__lib__proto_option__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(x))' reconstructs an equal option instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        reconstructed = _FixtureOption.from_buffer(bytes(memoryview(self._option)))

        self.assertEqual(reconstructed, self._option)

    def test__net_proto__lib__proto_option__equality(self) -> None:
        """
        Ensure options compare equal when their fields match.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _FixtureOption(type=_FixtureOptionType.A, len=2)
        b = _FixtureOption(type=_FixtureOptionType.A, len=2)
        c = _FixtureOption(type=_FixtureOptionType.B, len=2)
        d = _FixtureOption(type=_FixtureOptionType.A, len=3)

        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertNotEqual(a, d)


class TestNetProtoLibProtoOptionsAbstract(TestCase):
    """
    The NetProto ProtoOptions abstract-class contract tests.
    """

    def test__net_proto__lib__proto_options__cannot_instantiate_without_from_buffer(
        self,
    ) -> None:
        """
        Ensure ProtoOptions cannot be instantiated without 'from_buffer()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            ProtoOptions()  # type: ignore[abstract]


class TestNetProtoLibProtoOptionsEmpty(TestCase):
    """
    The NetProto ProtoOptions empty-container tests.
    """

    @override
    def setUp(self) -> None:
        self._options = _FixtureOptions()

    def test__net_proto__lib__proto_options__empty_len(self) -> None:
        """
        Ensure an empty ProtoOptions reports zero length.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(len(self._options), 0)

    def test__net_proto__lib__proto_options__empty_bool(self) -> None:
        """
        Ensure an empty ProtoOptions is falsy.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(bool(self._options))

    def test__net_proto__lib__proto_options__empty_str(self) -> None:
        """
        Ensure an empty ProtoOptions renders as an empty string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(str(self._options), "")

    def test__net_proto__lib__proto_options__empty_repr(self) -> None:
        """
        Ensure an empty ProtoOptions renders with an empty list in its repr.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(repr(self._options), "_FixtureOptions(options=[])")

    def test__net_proto__lib__proto_options__empty_buffer_protocol(self) -> None:
        """
        Ensure an empty ProtoOptions has an empty memoryview representation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(bytes(memoryview(self._options)), b"")

    def test__net_proto__lib__proto_options__empty_iter(self) -> None:
        """
        Ensure iterating an empty ProtoOptions yields nothing.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(list(self._options), [])


class TestNetProtoLibProtoOptionsPopulated(TestCase):
    """
    The NetProto ProtoOptions populated-container tests.
    """

    @override
    def setUp(self) -> None:
        self._option_a = _FixtureOption(type=_FixtureOptionType.A, len=2)
        self._option_b = _FixtureOption(type=_FixtureOptionType.B, len=3)
        self._option_c = _FixtureOption(type=_FixtureOptionType.C, len=4)
        self._options = _FixtureOptions(self._option_a, self._option_b, self._option_c)

    def test__net_proto__lib__proto_options__len_sums_option_lengths(self) -> None:
        """
        Ensure 'len()' on a ProtoOptions sums the lengths of contained options.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(len(self._options), 2 + 3 + 4)

    def test__net_proto__lib__proto_options__bool_true_when_populated(self) -> None:
        """
        Ensure a populated ProtoOptions is truthy.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(bool(self._options))

    def test__net_proto__lib__proto_options__str_joins_option_strings(self) -> None:
        """
        Ensure '__str__()' joins each option's string form with ", ".

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._options),
            ", ".join(str(option) for option in (self._option_a, self._option_b, self._option_c)),
        )

    def test__net_proto__lib__proto_options__repr_lists_options(self) -> None:
        """
        Ensure '__repr__()' mentions the class name and the options list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._options),
            f"_FixtureOptions(options={[self._option_a, self._option_b, self._option_c]!r})",
        )

    def test__net_proto__lib__proto_options__buffer_concatenates_option_buffers(
        self,
    ) -> None:
        """
        Ensure '__buffer__()' concatenates the serialized forms of each option.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(memoryview(self._options)),
            b"\x01\x02" + b"\x02\x03" + b"\x03\x04",
        )

    def test__net_proto__lib__proto_options__iter_yields_options_in_order(
        self,
    ) -> None:
        """
        Ensure iterating a ProtoOptions yields options in insertion order.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            list(self._options),
            [self._option_a, self._option_b, self._option_c],
        )

    def test__net_proto__lib__proto_options__getitem(self) -> None:
        """
        Ensure '__getitem__()' returns options by index.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(self._options[0], self._option_a)
        self.assertIs(self._options[1], self._option_b)
        self.assertIs(self._options[-1], self._option_c)

    def test__net_proto__lib__proto_options__getitem_out_of_range(self) -> None:
        """
        Ensure '__getitem__()' raises IndexError for out-of-range indices.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IndexError):
            _ = self._options[99]

    def test__net_proto__lib__proto_options__index(self) -> None:
        """
        Ensure 'index()' returns the matching option's position.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._options.index(self._option_b), 1)

    def test__net_proto__lib__proto_options__index_missing(self) -> None:
        """
        Ensure 'index()' raises ValueError when the option is absent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            self._options.index(_FixtureOption(type=_FixtureOptionType.A, len=99))

    def test__net_proto__lib__proto_options__contains(self) -> None:
        """
        Ensure '__contains__()' uses value-based membership lookup.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIn(_FixtureOption(type=_FixtureOptionType.A, len=2), self._options)
        self.assertNotIn(_FixtureOption(type=_FixtureOptionType.A, len=99), self._options)


class TestNetProtoLibProtoOptionsEquality(TestCase):
    """
    The NetProto ProtoOptions equality tests.
    """

    def test__net_proto__lib__proto_options__eq__same_contents(self) -> None:
        """
        Ensure two same-typed ProtoOptions with identical contents compare equal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _FixtureOptions(_FixtureOption(type=_FixtureOptionType.A, len=2))
        b = _FixtureOptions(_FixtureOption(type=_FixtureOptionType.A, len=2))

        self.assertEqual(a, b)

    def test__net_proto__lib__proto_options__eq__different_contents(self) -> None:
        """
        Ensure two same-typed ProtoOptions with different contents are unequal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _FixtureOptions(_FixtureOption(type=_FixtureOptionType.A, len=2))
        b = _FixtureOptions(_FixtureOption(type=_FixtureOptionType.B, len=2))

        self.assertNotEqual(a, b)

    def test__net_proto__lib__proto_options__eq__different_class(self) -> None:
        """
        Ensure ProtoOptions subclasses with the same option list are not equal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _FixtureOptions()
        b = _OtherFixtureOptions()

        self.assertNotEqual(a, b)

    def test__net_proto__lib__proto_options__eq__foreign_type(self) -> None:
        """
        Ensure ProtoOptions is not equal to a raw list of options.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        option = _FixtureOption(type=_FixtureOptionType.A, len=2)
        container = _FixtureOptions(option)

        self.assertNotEqual(container, [option])


class TestNetProtoLibProtoOptionsFromBuffer(TestCase):
    """
    The NetProto ProtoOptions from_buffer tests.
    """

    def test__net_proto__lib__proto_options__from_buffer_parses_all(self) -> None:
        """
        Ensure a concrete 'from_buffer()' reconstructs the options list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        buffer = b"\x01\x02" + b"\x02\x03"

        parsed = _FixtureOptions.from_buffer(buffer)

        self.assertEqual(
            list(parsed),
            [
                _FixtureOption(type=_FixtureOptionType.A, len=2),
                _FixtureOption(type=_FixtureOptionType.B, len=3),
            ],
        )

    def test__net_proto__lib__proto_options__from_buffer_empty(self) -> None:
        """
        Ensure 'from_buffer(b"")' returns an empty container.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        parsed = _FixtureOptions.from_buffer(b"")

        self.assertEqual(len(parsed), 0)
        self.assertFalse(bool(parsed))


class TestNetProtoLibProtoOptionsAbstractBody(TestCase):
    """
    The NetProto ProtoOptions abstract 'from_buffer' stub body tests.
    """

    def test__net_proto__lib__proto_options__from_buffer_stub_raises(self) -> None:
        """
        Ensure the abstract 'from_buffer()' stub body raises 'NotImplementedError'
        when reached via 'super()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class _SuperOptions(ProtoOptions):
            @classmethod
            @override
            def from_buffer(cls, buffer: Buffer, /) -> Self:
                return super().from_buffer(buffer)

        with self.assertRaises(NotImplementedError):
            _SuperOptions.from_buffer(b"")
