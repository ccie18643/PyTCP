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
This module contains tests for the NetProto Proto abstract base class.

net_proto/tests/unit/lib/test__lib__proto.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto.lib.proto import Proto


class _SimpleProto(Proto):
    """
    Minimal concrete Proto used as a test fixture.
    """

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __len__(self) -> int:
        return len(self._payload)

    def __str__(self) -> str:
        return f"SimpleProto({self._payload!r})"

    def __repr__(self) -> str:
        return f"SimpleProto({self._payload!r})"

    def __buffer__(self, _: int) -> memoryview:
        return memoryview(self._payload)


class _OtherProto(Proto):
    """
    Concrete Proto subclass used to test cross-type equality.
    """

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __len__(self) -> int:
        return len(self._payload)

    def __str__(self) -> str:
        return f"SimpleProto({self._payload!r})"

    def __repr__(self) -> str:
        return f"SimpleProto({self._payload!r})"

    def __buffer__(self, _: int) -> memoryview:
        return memoryview(self._payload)


class TestNetProtoLibProtoAbstract(TestCase):
    """
    The NetProto Proto abstract-class contract tests.
    """

    def test__net_proto__lib__proto__cannot_instantiate_abstract(self) -> None:
        """
        Ensure 'Proto' cannot be instantiated directly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            Proto()  # type: ignore[abstract]

    def test__net_proto__lib__proto__partial_subclass_cannot_instantiate(self) -> None:
        """
        Ensure a subclass missing abstract methods cannot be instantiated.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class Partial(Proto):
            def __len__(self) -> int:
                return 0

            def __str__(self) -> str:
                return ""

        with self.assertRaises(TypeError):
            Partial()  # type: ignore[abstract]

    def test__net_proto__lib__proto__concrete_subclass_can_instantiate(self) -> None:
        """
        Ensure a subclass implementing all abstract methods can be instantiated.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = _SimpleProto(b"\x01\x02")

        self.assertEqual(len(instance), 2)
        self.assertEqual(str(instance), "SimpleProto(b'\\x01\\x02')")
        self.assertEqual(repr(instance), "SimpleProto(b'\\x01\\x02')")

    def test__net_proto__lib__proto__buffer_protocol(self) -> None:
        """
        Ensure implementing '__buffer__()' exposes the payload via 'memoryview()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = _SimpleProto(b"\xaa\xbb\xcc")

        self.assertEqual(bytes(memoryview(instance)), b"\xaa\xbb\xcc")

    def test__net_proto__lib__proto__abstract_bodies_raise(self) -> None:
        """
        Ensure abstract method bodies raise 'NotImplementedError' when invoked
        via 'super()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class _SuperProto(Proto):
            def __len__(self) -> int:
                return super().__len__()  # type: ignore[safe-super]

            def __str__(self) -> str:
                return super().__str__()  # type: ignore[safe-super]

            def __repr__(self) -> str:
                return super().__repr__()  # type: ignore[safe-super]

            def __buffer__(self, flags: int) -> memoryview:
                return super().__buffer__(flags)  # type: ignore[safe-super]

        instance = _SuperProto()

        with self.assertRaises(NotImplementedError):
            len(instance)
        with self.assertRaises(NotImplementedError):
            str(instance)
        with self.assertRaises(NotImplementedError):
            repr(instance)
        with self.assertRaises(NotImplementedError):
            memoryview(instance)


class TestNetProtoLibProtoEquality(TestCase):
    """
    The NetProto Proto equality tests.
    """

    def test__net_proto__lib__proto__eq__self_identity(self) -> None:
        """
        Ensure 'Proto.__eq__()' returns True for the same instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = _SimpleProto(b"\x01")

        self.assertEqual(instance, instance)

    def test__net_proto__lib__proto__eq__same_type_same_repr(self) -> None:
        """
        Ensure two Proto instances with matching type and repr compare equal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _SimpleProto(b"\x01\x02")
        b = _SimpleProto(b"\x01\x02")

        self.assertEqual(a, b)
        self.assertEqual(b, a)

    def test__net_proto__lib__proto__eq__same_type_different_repr(self) -> None:
        """
        Ensure two Proto instances with matching type but different repr compare unequal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _SimpleProto(b"\x01\x02")
        b = _SimpleProto(b"\xff\xfe")

        self.assertNotEqual(a, b)

    def test__net_proto__lib__proto__eq__foreign_type(self) -> None:
        """
        Ensure 'Proto.__eq__()' returns False when compared to non-Proto values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = _SimpleProto(b"\x01")

        self.assertNotEqual(instance, "SimpleProto(b'\\x01')")
        self.assertNotEqual(instance, 123)
        self.assertNotEqual(instance, None)

    def test__net_proto__lib__proto__eq__unrelated_proto_subclass(self) -> None:
        """
        Ensure a foreign Proto subclass is not considered equal even when their
        repr values happen to match.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _SimpleProto(b"\x01")
        b = _OtherProto(b"\x01")

        self.assertEqual(repr(a), repr(b))
        self.assertNotEqual(a, b)
        self.assertNotEqual(b, a)


class TestNetProtoLibProtoHash(TestCase):
    """
    The NetProto Proto hashing tests.
    """

    def test__net_proto__lib__proto__hash__matches_for_equal_instances(self) -> None:
        """
        Ensure equal Proto instances hash to the same value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _SimpleProto(b"\x01\x02\x03")
        b = _SimpleProto(b"\x01\x02\x03")

        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))

    def test__net_proto__lib__proto__hash__differs_for_different_repr(self) -> None:
        """
        Ensure Proto instances with different repr typically hash differently.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _SimpleProto(b"\x01")
        b = _SimpleProto(b"\x02")

        self.assertNotEqual(hash(a), hash(b))

    def test__net_proto__lib__proto__hash__equals_hash_of_repr(self) -> None:
        """
        Ensure 'hash()' on a Proto matches 'hash(repr(x))'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = _SimpleProto(b"\xde\xad\xbe\xef")

        self.assertEqual(hash(instance), hash(repr(instance)))

    def test__net_proto__lib__proto__usable_in_set(self) -> None:
        """
        Ensure equal Proto instances collapse into a single set element.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _SimpleProto(b"\x01\x02")
        b = _SimpleProto(b"\x01\x02")
        c = _SimpleProto(b"\xff")

        self.assertEqual(len({a, b}), 1)
        self.assertEqual(len({a, b, c}), 2)

    def test__net_proto__lib__proto__usable_as_dict_key(self) -> None:
        """
        Ensure equal Proto instances refer to the same dict entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = _SimpleProto(b"\x01\x02")
        b = _SimpleProto(b"\x01\x02")

        mapping = {a: "value"}

        self.assertEqual(mapping[b], "value")
