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
This module contains tests for the NetProto ProtoStruct base class.

net_proto/tests/unit/lib/test__lib__proto_struct.py

ver 3.0.10
"""

from dataclasses import FrozenInstanceError, dataclass, fields, is_dataclass
from typing import Self, override
from unittest import TestCase

from net_addr import Buffer
from net_proto.lib.proto_struct import ProtoStruct


@dataclass(frozen=True, kw_only=True, slots=True)
class _ConcreteStruct(ProtoStruct):
    """
    Minimal concrete ProtoStruct fixture with a single byte-sized field.
    """

    value: int

    @override
    def __post_init__(self) -> None:
        assert 0 <= self.value <= 0xFF, f"'value' must be a byte. Got: {self.value}"

    @override
    def __len__(self) -> int:
        return 1

    @override
    def __buffer__(self, _: int) -> memoryview:
        return memoryview(self.value.to_bytes(1, "big"))

    @classmethod
    @override
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        return cls(value=int.from_bytes(buffer[:1], "big"))


class TestNetProtoLibProtoStructAbstract(TestCase):
    """
    The NetProto ProtoStruct abstract-class contract tests.
    """

    def test__net_proto__lib__proto_struct__is_dataclass(self) -> None:
        """
        Ensure ProtoStruct is configured as a dataclass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(is_dataclass(ProtoStruct))

    def test__net_proto__lib__proto_struct__cannot_instantiate_abstract(self) -> None:
        """
        Ensure 'ProtoStruct' cannot be instantiated directly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            ProtoStruct()  # type: ignore[abstract]

    def test__net_proto__lib__proto_struct__partial_subclass_cannot_instantiate(
        self,
    ) -> None:
        """
        Ensure a dataclass subclass missing abstract methods cannot be instantiated.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        @dataclass(frozen=True, kw_only=True, slots=True)
        class Partial(ProtoStruct):
            tag: int = 0

            @override
            def __post_init__(self) -> None:
                return None

            @override
            def __len__(self) -> int:
                return 0

        with self.assertRaises(TypeError):
            Partial()  # type: ignore[abstract]

    def test__net_proto__lib__proto_struct__concrete_subclass_can_instantiate(
        self,
    ) -> None:
        """
        Ensure a fully concrete subclass can be instantiated.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = _ConcreteStruct(value=0x7F)

        self.assertEqual(instance.value, 0x7F)
        self.assertEqual(len(instance), 1)

    def test__net_proto__lib__proto_struct__post_init_runs(self) -> None:
        """
        Ensure '__post_init__()' fires during construction and can raise.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            _ConcreteStruct(value=0x1FF)

        with self.assertRaises(AssertionError):
            _ConcreteStruct(value=-1)


class TestNetProtoLibProtoStructDataclassConfig(TestCase):
    """
    The NetProto ProtoStruct dataclass configuration tests.
    """

    def test__net_proto__lib__proto_struct__subclass_is_frozen(self) -> None:
        """
        Ensure subclass instances cannot be mutated after construction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = _ConcreteStruct(value=1)

        with self.assertRaises(FrozenInstanceError):
            instance.value = 2  # type: ignore[misc]

    def test__net_proto__lib__proto_struct__subclass_is_kw_only(self) -> None:
        """
        Ensure subclass init rejects positional arguments.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            _ConcreteStruct(1)  # type: ignore[call-arg]

    def test__net_proto__lib__proto_struct__subclass_has_slots(self) -> None:
        """
        Ensure the subclass uses '__slots__' and has no '__dict__'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(hasattr(_ConcreteStruct, "__slots__"))
        instance = _ConcreteStruct(value=1)
        self.assertFalse(hasattr(instance, "__dict__"))

    def test__net_proto__lib__proto_struct__equality_is_value_based(self) -> None:
        """
        Ensure dataclass equality compares field values, not identity.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _ConcreteStruct(value=42)
        b = _ConcreteStruct(value=42)
        c = _ConcreteStruct(value=99)

        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test__net_proto__lib__proto_struct__fields_introspectable(self) -> None:
        """
        Ensure 'dataclasses.fields()' exposes the declared fields of a subclass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        names = [f.name for f in fields(_ConcreteStruct)]

        self.assertEqual(names, ["value"])


class TestNetProtoLibProtoStructBufferProtocol(TestCase):
    """
    The NetProto ProtoStruct buffer-protocol and from_buffer tests.
    """

    def test__net_proto__lib__proto_struct__len(self) -> None:
        """
        Ensure '__len__()' on a concrete subclass returns the field-defined size.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(len(_ConcreteStruct(value=0)), 1)

    def test__net_proto__lib__proto_struct__buffer_protocol(self) -> None:
        """
        Ensure '__buffer__()' yields the binary representation via 'memoryview()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = _ConcreteStruct(value=0x2A)

        self.assertEqual(bytes(memoryview(instance)), b"\x2a")

    def test__net_proto__lib__proto_struct__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(x))' reconstructs an equal ProtoStruct instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original = _ConcreteStruct(value=0x99)

        reconstructed = _ConcreteStruct.from_buffer(bytes(memoryview(original)))

        self.assertEqual(reconstructed, original)

    def test__net_proto__lib__proto_struct__from_buffer_consumes_prefix(
        self,
    ) -> None:
        """
        Ensure 'from_buffer()' reads only the first byte of a wider input buffer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        reconstructed = _ConcreteStruct.from_buffer(b"\x77\x11\x22\x33")

        self.assertEqual(reconstructed.value, 0x77)


class TestNetProtoLibProtoStructAbstractBodies(TestCase):
    """
    The NetProto ProtoStruct abstract stub bodies raise 'NotImplementedError'.
    """

    def test__net_proto__lib__proto_struct__abstract_bodies_raise(self) -> None:
        """
        Ensure the abstract stub bodies raise 'NotImplementedError' when
        invoked directly on a concrete instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = _ConcreteStruct(value=0)

        with self.assertRaises(NotImplementedError):
            ProtoStruct.__post_init__(instance)
        with self.assertRaises(NotImplementedError):
            ProtoStruct.__len__(instance)
        with self.assertRaises(NotImplementedError):
            ProtoStruct.__buffer__(instance, 0)
        with self.assertRaises(NotImplementedError):
            ProtoStruct.from_buffer(b"")
