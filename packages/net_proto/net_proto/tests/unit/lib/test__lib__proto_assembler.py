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
This module contains tests for the NetProto ProtoAssembler base class.

net_proto/tests/unit/lib/test__lib__proto_assembler.py

ver 3.0.10
"""

import itertools
from typing import override
from unittest import TestCase

from net_addr import Buffer
from net_proto.lib.proto import Proto
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker


class _ConcreteAssembler(ProtoAssembler):
    """
    Minimal concrete ProtoAssembler used as a test fixture.
    """

    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._tracker = Tracker(prefix="TX")

    @override
    def __len__(self) -> int:
        return len(self._payload)

    @override
    def __str__(self) -> str:
        return f"ConcreteAssembler({self._payload!r})"

    @override
    def __repr__(self) -> str:
        return f"ConcreteAssembler({self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        return memoryview(self._payload)

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        buffers.append(self._payload)


class _TrackerReset(TestCase):
    """
    Base class resetting the Tracker class-level counters around each test.
    """

    @override
    def setUp(self) -> None:
        self._saved_rx_counter = Tracker._rx_counter
        self._saved_tx_counter = Tracker._tx_counter
        Tracker._rx_counter = itertools.count()
        Tracker._tx_counter = itertools.count()

    @override
    def tearDown(self) -> None:
        Tracker._rx_counter = self._saved_rx_counter
        Tracker._tx_counter = self._saved_tx_counter


class TestNetProtoLibProtoAssemblerAbstract(_TrackerReset):
    """
    The NetProto ProtoAssembler abstract-class contract tests.
    """

    def test__net_proto__lib__proto_assembler__subclasses_proto(self) -> None:
        """
        Ensure 'ProtoAssembler' subclasses 'Proto'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(issubclass(ProtoAssembler, Proto))

    def test__net_proto__lib__proto_assembler__cannot_instantiate_abstract(
        self,
    ) -> None:
        """
        Ensure 'ProtoAssembler' cannot be instantiated directly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            ProtoAssembler()  # type: ignore[abstract]

    def test__net_proto__lib__proto_assembler__partial_subclass_cannot_instantiate(
        self,
    ) -> None:
        """
        Ensure a subclass missing 'assemble()' cannot be instantiated.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class Partial(ProtoAssembler):
            @override
            def __len__(self) -> int:
                return 0

            @override
            def __str__(self) -> str:
                return ""

            @override
            def __repr__(self) -> str:
                return ""

            @override
            def __buffer__(self, _: int) -> memoryview:
                return memoryview(b"")

        with self.assertRaises(TypeError):
            Partial()  # type: ignore[abstract]

    def test__net_proto__lib__proto_assembler__concrete_subclass_can_instantiate(
        self,
    ) -> None:
        """
        Ensure a subclass implementing all abstract methods can be instantiated.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = _ConcreteAssembler(b"\x01\x02")

        self.assertEqual(len(assembler), 2)
        self.assertEqual(bytes(memoryview(assembler)), b"\x01\x02")


class TestNetProtoLibProtoAssemblerTracker(_TrackerReset):
    """
    The NetProto ProtoAssembler tracker property tests.
    """

    def test__net_proto__lib__proto_assembler__tracker_returns_internal(
        self,
    ) -> None:
        """
        Ensure the 'tracker' property returns the backing '_tracker' attribute.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = _ConcreteAssembler(b"\x00")

        self.assertIs(assembler.tracker, assembler._tracker)

    def test__net_proto__lib__proto_assembler__tracker_is_tx_tracker(self) -> None:
        """
        Ensure the tracker carries a TX-tagged serial for an assembler.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = _ConcreteAssembler(b"\x00")

        self.assertIsInstance(assembler.tracker, Tracker)
        self.assertIn("TX", str(assembler.tracker))


class TestNetProtoLibProtoAssemblerAssemble(_TrackerReset):
    """
    The NetProto ProtoAssembler assemble method tests.
    """

    def test__net_proto__lib__proto_assembler__assemble_appends_payload(
        self,
    ) -> None:
        """
        Ensure 'assemble()' appends payload fragments to the supplied buffer list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = _ConcreteAssembler(b"\x11\x22")
        buffers: list[Buffer] = []

        assembler.assemble(buffers)

        self.assertEqual(len(buffers), 1)
        self.assertEqual(bytes(buffers[0]), b"\x11\x22")

    def test__net_proto__lib__proto_assembler__assemble_requires_positional_arg(
        self,
    ) -> None:
        """
        Ensure the 'assemble()' method only accepts its buffers list positionally.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = _ConcreteAssembler(b"\x00")

        with self.assertRaises(TypeError):
            assembler.assemble(buffers=[])  # type: ignore[call-arg]

    def test__net_proto__lib__proto_assembler__assemble_extends_existing_list(
        self,
    ) -> None:
        """
        Ensure 'assemble()' preserves existing entries in the buffers list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assembler = _ConcreteAssembler(b"\x33")
        buffers: list[Buffer] = [b"header"]

        assembler.assemble(buffers)

        self.assertEqual(len(buffers), 2)
        self.assertEqual(bytes(buffers[0]), b"header")
        self.assertEqual(bytes(buffers[1]), b"\x33")


class TestNetProtoLibProtoAssemblerAbstractBody(_TrackerReset):
    """
    The NetProto ProtoAssembler abstract stub body raises 'NotImplementedError'.
    """

    def test__net_proto__lib__proto_assembler__assemble_stub_raises(self) -> None:
        """
        Ensure the abstract 'assemble()' stub body raises 'NotImplementedError'
        when reached via 'super()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class _SuperAssembler(ProtoAssembler):
            def __init__(self) -> None:
                self._tracker = Tracker(prefix="TX")

            @override
            def __len__(self) -> int:
                return 0

            @override
            def __str__(self) -> str:
                return ""

            @override
            def __repr__(self) -> str:
                return ""

            @override
            def __buffer__(self, _: int) -> memoryview:
                return memoryview(b"")

            @override
            def assemble(self, buffers: list[Buffer], /) -> None:
                super().assemble(buffers)  # type: ignore[safe-super]

        assembler = _SuperAssembler()

        with self.assertRaises(NotImplementedError):
            assembler.assemble([])
