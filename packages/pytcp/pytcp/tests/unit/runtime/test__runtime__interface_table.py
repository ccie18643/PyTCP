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
This module contains unit tests for the 'InterfaceTable' registry —
the lock-guarded, dict-compatible map of 'ifindex -> PacketHandler'
the daemon mutates at runtime as interfaces are added / removed.

pytcp/tests/unit/runtime/test__runtime__interface_table.py

ver 3.0.8
"""

import threading
from typing import cast
from unittest import TestCase
from unittest.mock import MagicMock

from pytcp.runtime.interface_table import InterfaceTable
from pytcp.runtime.packet_handler import PacketHandlerL2


def _make_handler() -> PacketHandlerL2:
    """
    Build a spec'd stand-in packet handler for table-storage tests.
    """

    mock_handler = MagicMock(spec=PacketHandlerL2)
    mock_handler._ifindex = 0
    # 'InterfaceTable.add' stamps the allocated index via the public
    # 'set_ifindex' mutator; mirror its effect on the spec'd mock so the
    # '_ifindex' side effect the storage tests assert on is observable.
    mock_handler.set_ifindex.side_effect = lambda ifindex: setattr(mock_handler, "_ifindex", ifindex)
    return cast(PacketHandlerL2, mock_handler)


class TestInterfaceTableAllocation(TestCase):
    """
    The 'InterfaceTable.add' ifindex-allocation tests.
    """

    def test__interface_table__add_first_takes_first_ifindex(self) -> None:
        """
        Ensure the first 'add' into an empty table returns the
        configured first ifindex (default 1) and registers the handler
        under it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        handler = _make_handler()

        ifindex = table.add(handler)

        self.assertEqual(ifindex, 1, msg="First add must take the default first ifindex (1).")
        self.assertIs(table[ifindex], handler, msg="The handler must be registered under the allocated ifindex.")

    def test__interface_table__add_allocates_max_plus_one_monotonic(self) -> None:
        """
        Ensure 'add' allocates max(existing) + 1 and never reuses a
        freed index — a popped ifindex is not handed out again.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        first = table.add(_make_handler())
        second = table.add(_make_handler())

        self.assertEqual((first, second), (1, 2), msg="Sequential adds must allocate 1 then 2.")

        table.pop(first)
        third = table.add(_make_handler())

        self.assertEqual(third, 3, msg="After popping ifindex 1, the next add must take max(2)+1 = 3, not reuse 1.")

    def test__interface_table__add_sets_handler_ifindex(self) -> None:
        """
        Ensure 'add' records the allocated ifindex back onto the
        handler's '_ifindex' attribute so the handler knows which
        interface it is.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        handler = _make_handler()

        ifindex = table.add(handler)

        self.assertEqual(handler._ifindex, ifindex, msg="add must stamp the allocated ifindex onto the handler.")

    def test__interface_table__custom_first_ifindex(self) -> None:
        """
        Ensure a table constructed with a custom 'first_ifindex'
        allocates from that base.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable(first_ifindex=10)

        self.assertEqual(table.add(_make_handler()), 10, msg="First add must honour the custom first_ifindex.")


class TestInterfaceTableBasic(TestCase):
    """
    The 'InterfaceTable' dict-compatible operation tests.
    """

    def test__interface_table__setitem_getitem_roundtrip(self) -> None:
        """
        Ensure a handler placed under an explicit ifindex is returned
        by '__getitem__' and 'get'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        handler = _make_handler()

        table[2] = handler

        self.assertIs(table[2], handler, msg="__getitem__ must return the handler placed under the ifindex.")
        self.assertIs(table.get(2), handler, msg="get must return the handler placed under the ifindex.")

    def test__interface_table__get_missing_returns_default(self) -> None:
        """
        Ensure 'get' on an unknown ifindex returns the supplied default
        ('None' when omitted), never raising.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()

        self.assertIsNone(table.get(99), msg="get on an unknown ifindex must return None by default.")

    def test__interface_table__pop_removes_and_returns(self) -> None:
        """
        Ensure 'pop' removes the entry and returns it; a second pop
        returns the default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        handler = _make_handler()
        ifindex = table.add(handler)

        self.assertIs(table.pop(ifindex), handler, msg="pop must return the removed handler.")
        self.assertIsNone(table.pop(ifindex), msg="a second pop must return the default (entry gone).")

    def test__interface_table__contains_and_len(self) -> None:
        """
        Ensure '__contains__' and '__len__' reflect the registered set,
        and '__bool__' (via __len__) reports emptiness.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        self.assertFalse(table, msg="An empty table must be falsy.")

        ifindex = table.add(_make_handler())

        self.assertIn(ifindex, table, msg="a registered ifindex must be 'in' the table.")
        self.assertEqual(len(table), 1, msg="len must count registered interfaces.")
        self.assertTrue(table, msg="A non-empty table must be truthy.")

    def test__interface_table__iter_yields_ifindexes(self) -> None:
        """
        Ensure iteration yields the registered ifindexes so 'max(table)'
        / 'set(table)' / 'dict(table)' work the way the lifecycle code
        relies on.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        table.add(_make_handler())
        table.add(_make_handler())

        self.assertEqual(set(table), {1, 2}, msg="iteration must yield the registered ifindexes.")
        self.assertEqual(max(table), 2, msg="max(table) must return the highest registered ifindex.")

    def test__interface_table__values_snapshot_safe_under_mutation(self) -> None:
        """
        Ensure 'values' returns a snapshot list so iterating it while
        the table is concurrently mutated cannot raise
        'RuntimeError: dictionary changed size during iteration'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        for _ in range(8):
            table.add(_make_handler())

        for index, _ in enumerate(table.values()):
            if index == 0:
                table[999] = _make_handler()

    def test__interface_table__dict_roundtrip(self) -> None:
        """
        Ensure the table supports the 'dict(table)' Mapping protocol
        (keys + __getitem__) used by the test harness to snapshot and
        restore the registry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        handler = _make_handler()
        ifindex = table.add(handler)

        self.assertEqual(dict(table), {ifindex: handler}, msg="dict(table) must reproduce the registered mapping.")

    def test__interface_table__clear_and_update(self) -> None:
        """
        Ensure 'clear' empties the table and 'update' bulk-installs a
        mapping (the harness snapshot/restore primitives).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        table.add(_make_handler())

        table.clear()
        self.assertEqual(len(table), 0, msg="clear must empty the table.")

        restored = {5: _make_handler()}
        table.update(restored)
        self.assertEqual(len(table), 1, msg="update must bulk-install the mapping.")
        self.assertIn(5, table, msg="update must install entries under their keys.")


class TestInterfaceTableConcurrency(TestCase):
    """
    The 'InterfaceTable' thread-safety tests — concurrent add must
    allocate a unique ifindex per interface even under contention.
    """

    def test__interface_table__concurrent_add_allocates_unique_ifindexes(self) -> None:
        """
        Ensure many threads each adding a distinct handler receive
        distinct ifindexes and the table ends with one entry per add —
        the lock makes 'read max + 1, store' atomic so two racing adds
        cannot collide on the same index (the daemon-critical property
        a bare dict's GIL-atomicity does not guarantee on free-threaded
        builds).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = InterfaceTable()
        handlers = [_make_handler() for _ in range(64)]
        allocated: list[int] = []
        allocated_lock = threading.Lock()
        errors: list[BaseException] = []

        def add_one(handler: PacketHandlerL2) -> None:
            try:
                ifindex = table.add(handler)
                with allocated_lock:
                    allocated.append(ifindex)
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)

        threads = [threading.Thread(target=add_one, args=(handler,)) for handler in handlers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [], msg=f"Concurrent add must not raise; got: {errors!r}")
        self.assertEqual(len(set(allocated)), len(handlers), msg="Every concurrent add must get a unique ifindex.")
        self.assertEqual(len(table), len(handlers), msg="Every added handler must be registered.")
