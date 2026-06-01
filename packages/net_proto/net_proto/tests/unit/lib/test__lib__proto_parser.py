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
This module contains tests for the NetProto ProtoParser base class.

net_proto/tests/unit/lib/test__lib__proto_parser.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto.lib.buffer import Buffer
from net_proto.lib.proto import Proto
from net_proto.lib.proto_parser import ProtoParser


class _ConcreteParser(ProtoParser):
    """
    Minimal concrete ProtoParser used as a test fixture.
    """

    def __init__(self, frame: Buffer) -> None:
        self._frame = frame
        self.integrity_called = False
        self.parse_called = False
        self.sanity_called = False
        self._validate_integrity()
        self._parse()
        self._validate_sanity()

    def _validate_integrity(self) -> None:
        self.integrity_called = True

    def _parse(self) -> None:
        self.parse_called = True

    def _validate_sanity(self) -> None:
        self.sanity_called = True

    def __len__(self) -> int:
        return len(self._frame)

    def __str__(self) -> str:
        return f"ConcreteParser({bytes(self._frame)!r})"

    def __repr__(self) -> str:
        return f"ConcreteParser({bytes(self._frame)!r})"

    def __buffer__(self, _: int) -> memoryview:
        return memoryview(self._frame)


class TestNetProtoLibProtoParserAbstract(TestCase):
    """
    The NetProto ProtoParser abstract-class contract tests.
    """

    def test__net_proto__lib__proto_parser__subclasses_proto(self) -> None:
        """
        Ensure 'ProtoParser' subclasses 'Proto'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(issubclass(ProtoParser, Proto))

    def test__net_proto__lib__proto_parser__cannot_instantiate_abstract(self) -> None:
        """
        Ensure 'ProtoParser' cannot be instantiated directly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            ProtoParser()  # type: ignore[abstract]

    def test__net_proto__lib__proto_parser__partial_subclass_cannot_instantiate(
        self,
    ) -> None:
        """
        Ensure a subclass missing abstract validation/parse methods cannot
        be instantiated.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class Partial(ProtoParser):
            def _validate_integrity(self) -> None:
                return None

            def __len__(self) -> int:
                return 0

            def __str__(self) -> str:
                return ""

            def __repr__(self) -> str:
                return ""

            def __buffer__(self, _: int) -> memoryview:
                return memoryview(b"")

        with self.assertRaises(TypeError):
            Partial()  # type: ignore[abstract]

    def test__net_proto__lib__proto_parser__concrete_subclass_can_instantiate(
        self,
    ) -> None:
        """
        Ensure a concrete parser subclass can be instantiated and its lifecycle
        hooks fire in order.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        parser = _ConcreteParser(b"\x01\x02\x03")

        self.assertTrue(parser.integrity_called)
        self.assertTrue(parser.parse_called)
        self.assertTrue(parser.sanity_called)


@parameterized_class(
    [
        {
            "_description": "Parser frame stored as bytes.",
            "_frame": b"\x01\x02\x03\x04",
            "_results": {"bytes": b"\x01\x02\x03\x04"},
        },
        {
            "_description": "Parser frame stored as bytearray.",
            "_frame": bytearray(b"\xaa\xbb"),
            "_results": {"bytes": b"\xaa\xbb"},
        },
        {
            "_description": "Parser frame stored as memoryview.",
            "_frame": memoryview(b"\xff\x00\xff\x00"),
            "_results": {"bytes": b"\xff\x00\xff\x00"},
        },
        {
            "_description": "Parser frame stored as empty bytes.",
            "_frame": b"",
            "_results": {"bytes": b""},
        },
    ]
)
class TestNetProtoLibProtoParserFrame(TestCase):
    """
    The NetProto ProtoParser 'frame' property tests.
    """

    _description: str
    _frame: Buffer
    _results: dict[str, Any]

    def setUp(self) -> None:
        self._parser = _ConcreteParser(self._frame)

    def test__net_proto__lib__proto_parser__frame_returns_memoryview(self) -> None:
        """
        Ensure the 'frame' property always returns a memoryview.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._parser.frame,
            memoryview,
            msg=f"{self._description}: frame must be a memoryview.",
        )

    def test__net_proto__lib__proto_parser__frame_preserves_contents(self) -> None:
        """
        Ensure the 'frame' property exposes the original bytes untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._parser.frame),
            self._results["bytes"],
            msg=f"{self._description}: frame contents must match the input bytes.",
        )


class TestNetProtoLibProtoParserFrameView(TestCase):
    """
    The NetProto ProtoParser frame-view invariants.
    """

    def test__net_proto__lib__proto_parser__frame_view_of_bytearray(self) -> None:
        """
        Ensure the 'frame' property returns a view over the underlying
        bytearray buffer when the frame is mutable.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = bytearray(b"\x00\x00\x00")
        parser = _ConcreteParser(source)
        source[0] = 0xFF

        self.assertEqual(bytes(parser.frame), b"\xff\x00\x00")

    def test__net_proto__lib__proto_parser__frame_is_fresh_memoryview_each_call(
        self,
    ) -> None:
        """
        Ensure each 'frame' access returns a fresh memoryview instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        parser = _ConcreteParser(b"\x01\x02")

        first = parser.frame
        second = parser.frame

        self.assertIsInstance(first, memoryview)
        self.assertIsInstance(second, memoryview)
        self.assertEqual(bytes(first), bytes(second))


class TestNetProtoLibProtoParserAbstractBodies(TestCase):
    """
    The NetProto ProtoParser abstract stub bodies raise 'NotImplementedError'.
    """

    def test__net_proto__lib__proto_parser__abstract_bodies_raise(self) -> None:
        """
        Ensure the abstract stub bodies raise 'NotImplementedError' when
        reached via 'super()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class _SuperParser(ProtoParser):
            def _validate_integrity(self) -> None:
                super()._validate_integrity()  # type: ignore[safe-super]

            def _parse(self) -> None:
                super()._parse()  # type: ignore[safe-super]

            def _validate_sanity(self) -> None:
                super()._validate_sanity()  # type: ignore[safe-super]

            def __len__(self) -> int:
                return 0

            def __str__(self) -> str:
                return ""

            def __repr__(self) -> str:
                return ""

            def __buffer__(self, _: int) -> memoryview:
                return memoryview(b"")

        parser = _SuperParser()

        with self.assertRaises(NotImplementedError):
            parser._validate_integrity()
        with self.assertRaises(NotImplementedError):
            parser._parse()
        with self.assertRaises(NotImplementedError):
            parser._validate_sanity()
