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
This module contains unit tests for the 'SocketTable' registry.

pytcp/tests/unit/runtime/socket/test__runtime__socket__socket_table.py

ver 3.0.8
"""

import threading
from types import SimpleNamespace
from typing import cast
from unittest import TestCase
from unittest.mock import create_autospec

from pytcp.runtime.socket import socket
from pytcp.runtime.socket.socket_id import SocketId
from pytcp.runtime.socket.socket_table import SocketTable


def _make_socket_id(token: str) -> SocketId:
    """
    Build a distinct opaque 'SocketId' fixture for the table tests.
    """

    return cast(SocketId, token)


def _make_socket(socket_id: SocketId | None = None) -> socket:
    """
    Build a spec'd stand-in socket for table-storage tests.

    When 'socket_id' is supplied it is stamped onto the mock's
    'socket_id' attribute so the 'register' / 'unregister' cohort
    API (which keys off 'sock.socket_id') can be exercised.
    """

    sock = create_autospec(socket, spec_set=True, instance=True)
    if socket_id is not None:
        sock.socket_id = socket_id
    return cast(socket, sock)


def _make_bound_socket(socket_id: SocketId, *, egress_ifindex: int | None) -> socket:
    """
    Build a stand-in socket carrying a 'socket_id' and the
    SO_BINDTODEVICE-resolved 'egress_ifindex' (None when unbound) for the
    ingress-demux tests. A 'SimpleNamespace' stand-in is used because
    'egress_ifindex' is an instance-only attribute an autospec cannot
    stamp under 'spec_set'.
    """

    return cast(socket, SimpleNamespace(socket_id=socket_id, egress_ifindex=egress_ifindex))


class TestSocketTableBasic(TestCase):
    """
    The 'SocketTable' dict-compatible operation tests.
    """

    def test__socket_table__register_and_get_roundtrip(self) -> None:
        """
        Ensure a registered socket is returned by 'get' under its id.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("a")
        sock = _make_socket()

        table[sid] = sock

        self.assertIs(
            table.get(sid),
            sock,
            msg="get must return the socket registered under the id.",
        )

    def test__socket_table__get_missing_returns_default(self) -> None:
        """
        Ensure 'get' on an unknown id returns the supplied default
        ('None' when omitted), never raising.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()

        self.assertIsNone(
            table.get(_make_socket_id("missing")),
            msg="get on an unknown id must return None by default.",
        )

    def test__socket_table__pop_removes_and_returns(self) -> None:
        """
        Ensure 'pop' removes the entry and returns it; a second pop
        returns the default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("a")
        sock = _make_socket()
        table[sid] = sock

        self.assertIs(
            table.pop(sid, None),
            sock,
            msg="pop must return the removed socket.",
        )
        self.assertIsNone(
            table.pop(sid, None),
            msg="a second pop must return the default (entry gone).",
        )

    def test__socket_table__contains_and_len(self) -> None:
        """
        Ensure '__contains__' and '__len__' reflect the registered set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("a")
        table[sid] = _make_socket()

        self.assertIn(sid, table, msg="a registered id must be 'in' the table.")
        self.assertEqual(len(table), 1, msg="len must count registered sockets.")

    def test__socket_table__values_returns_snapshot_safe_under_mutation(self) -> None:
        """
        Ensure 'values' returns a snapshot list so iterating it while
        the table is concurrently mutated cannot raise
        'RuntimeError: dictionary changed size during iteration'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        for i in range(8):
            table[_make_socket_id(str(i))] = _make_socket()

        # Mutating the table while iterating the returned snapshot
        # must not raise — the snapshot is detached from the live dict.
        for index, _ in enumerate(table.values()):
            if index == 0:
                table[_make_socket_id("added-during-iteration")] = _make_socket()

    def test__socket_table__dict_roundtrip(self) -> None:
        """
        Ensure the table supports the 'dict(table)' Mapping protocol
        (keys + __getitem__) used by the test harness to snapshot and
        restore the registry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("a")
        sock = _make_socket()
        table[sid] = sock

        snapshot = dict(table)

        self.assertEqual(
            snapshot,
            {sid: sock},
            msg="dict(table) must reproduce the registered mapping.",
        )

    def test__socket_table__clear_and_update(self) -> None:
        """
        Ensure 'clear' empties the table and 'update' bulk-installs a
        mapping (the harness snapshot/restore primitives).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        table[_make_socket_id("a")] = _make_socket()

        table.clear()
        self.assertEqual(len(table), 0, msg="clear must empty the table.")

        restored = {_make_socket_id("b"): _make_socket()}
        table.update(restored)
        self.assertEqual(len(table), 1, msg="update must bulk-install the mapping.")


class TestSocketTableReusePortCohort(TestCase):
    """
    The 'SocketTable' SO_REUSEPORT cohort tests — multiple sockets
    registered under one listening 'SocketId' form a cohort that
    'get' load-balances across with round-robin selection.
    """

    def test__socket_table__register_two_under_one_id_forms_cohort(self) -> None:
        """
        Ensure two distinct sockets registered under the same id both
        remain reachable — neither overwrites the other, as a bare
        dict assignment would.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("listener")
        sock_a = _make_socket(sid)
        sock_b = _make_socket(sid)

        table.register(sock_a)
        table.register(sock_b)

        delivered = {table.get(sid), table.get(sid)}
        self.assertEqual(
            delivered,
            {sock_a, sock_b},
            msg="both cohort members must be reachable via get.",
        )

    def test__socket_table__get_round_robins_across_cohort(self) -> None:
        """
        Ensure successive 'get' calls on a multi-member cohort rotate
        through the members in registration order, then wrap — the
        load-balancing pin for the REUSEPORT demux.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("listener")
        sock_a = _make_socket(sid)
        sock_b = _make_socket(sid)
        sock_c = _make_socket(sid)
        table.register(sock_a)
        table.register(sock_b)
        table.register(sock_c)

        picks = [table.get(sid) for _ in range(4)]

        self.assertEqual(
            picks,
            [sock_a, sock_b, sock_c, sock_a],
            msg="get must round-robin the cohort in registration order and wrap.",
        )

    def test__socket_table__register_is_identity_idempotent(self) -> None:
        """
        Ensure registering the same socket object twice does not add a
        duplicate cohort entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("listener")
        sock = _make_socket(sid)

        table.register(sock)
        table.register(sock)

        self.assertEqual(
            table.values(),
            [sock],
            msg="re-registering the same socket must not duplicate it.",
        )

    def test__socket_table__unregister_removes_one_cohort_member(self) -> None:
        """
        Ensure 'unregister' removes only the given socket from a
        cohort; the surviving member is then the sole 'get' result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("listener")
        sock_a = _make_socket(sid)
        sock_b = _make_socket(sid)
        table.register(sock_a)
        table.register(sock_b)

        table.unregister(sock_a)

        self.assertEqual(
            {table.get(sid), table.get(sid)},
            {sock_b},
            msg="after unregistering one member, get must only return the survivor.",
        )

    def test__socket_table__unregister_last_member_drops_id(self) -> None:
        """
        Ensure unregistering the final cohort member removes the id
        from the table entirely.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("listener")
        sock = _make_socket(sid)
        table.register(sock)

        table.unregister(sock)

        self.assertNotIn(
            sid,
            table,
            msg="an emptied cohort must drop its id from the table.",
        )
        self.assertIsNone(
            table.get(sid),
            msg="get on the dropped id must return None.",
        )

    def test__socket_table__unregister_unknown_socket_is_noop(self) -> None:
        """
        Ensure 'unregister' of a socket that was never registered is a
        silent no-op (no raise), matching the tolerant 'pop' default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("listener")

        # Must not raise.
        table.unregister(_make_socket(sid))

    def test__socket_table__single_member_cohort_get_is_stable(self) -> None:
        """
        Ensure a single-member cohort always returns that member from
        'get' (the common non-REUSEPORT case — no rotation).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("conn")
        sock = _make_socket(sid)
        table.register(sock)

        self.assertEqual(
            [table.get(sid) for _ in range(3)],
            [sock, sock, sock],
            msg="a single-member cohort must return its member on every get.",
        )

    def test__socket_table__values_flatten_cohort_members(self) -> None:
        """
        Ensure 'values' returns every cohort member across all ids, so
        bind-conflict and ephemeral-port scans see all open sockets.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("listener")
        sock_a = _make_socket(sid)
        sock_b = _make_socket(sid)
        table.register(sock_a)
        table.register(sock_b)

        self.assertCountEqual(
            table.values(),
            [sock_a, sock_b],
            msg="values must flatten every cohort member.",
        )


class TestSocketTableConcurrency(TestCase):
    """
    The 'SocketTable' thread-safety tests — concurrent register /
    unregister / lookup must neither raise nor corrupt the registry.
    """

    def test__socket_table__concurrent_register_unregister_consistent(self) -> None:
        """
        Ensure concurrent register / unregister / get from many
        threads never raises and leaves the table in a consistent
        state (every id either present-with-its-socket or absent).
        The bare 'dict' is GIL-atomic per-op but the wrapper makes
        the registry safe under free-threaded builds where compound
        access is not.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        ids = [_make_socket_id(str(i)) for i in range(64)]
        socks = {sid: _make_socket() for sid in ids}
        errors: list[BaseException] = []

        def churn(sid: SocketId) -> None:
            try:
                for _ in range(200):
                    table[sid] = socks[sid]
                    table.get(sid)
                    _ = list(table.values())
                    table.pop(sid, None)
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)

        threads = [threading.Thread(target=churn, args=(sid,)) for sid in ids]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(
            errors,
            [],
            msg=f"Concurrent table access must not raise; got: {errors!r}",
        )
        # Every surviving entry must map an id to its own socket.
        for sid, sock in table.items():
            self.assertIs(
                sock,
                socks[sid],
                msg="A surviving entry must map its id to the registered socket.",
            )


class TestSocketTableIngressDemux(TestCase):
    """
    The 'SocketTable.get_for_ingress' SO_BINDTODEVICE RX-demux tests.
    """

    def test__socket_table__ingress_delivers_to_device_bound_member(self) -> None:
        """
        Ensure a datagram arriving on an interface is delivered to the
        cohort member pinned to that interface via SO_BINDTODEVICE, not a
        sibling pinned to a different interface — the multi-homed
        port-sharing case (two DHCP clients on 0.0.0.0:68).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("dhcp")
        sock_if1 = _make_bound_socket(sid, egress_ifindex=1)
        sock_if2 = _make_bound_socket(sid, egress_ifindex=2)
        table.register(sock_if1)
        table.register(sock_if2)

        self.assertIs(
            table.get_for_ingress(sid, ifindex=1),
            sock_if1,
            msg="A datagram on interface 1 must reach the socket bound to interface 1.",
        )
        self.assertIs(
            table.get_for_ingress(sid, ifindex=2),
            sock_if2,
            msg="A datagram on interface 2 must reach the socket bound to interface 2.",
        )

    def test__socket_table__ingress_no_eligible_member_returns_default(self) -> None:
        """
        Ensure a datagram arriving on an interface with no cohort member
        bound to it (and no unbound member) returns the default rather than
        cross-delivering to a member bound to a different interface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("dhcp")
        table.register(_make_bound_socket(sid, egress_ifindex=1))

        self.assertIsNone(
            table.get_for_ingress(sid, ifindex=2, default=None),
            msg="A datagram on an interface with no device-matching member must not cross-deliver.",
        )

    def test__socket_table__ingress_unbound_member_receives_from_any_interface(self) -> None:
        """
        Ensure an unbound (no SO_BINDTODEVICE) cohort member is eligible to
        receive a datagram arriving on any interface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sid = _make_socket_id("any")
        unbound = _make_bound_socket(sid, egress_ifindex=None)
        table.register(unbound)

        self.assertIs(
            table.get_for_ingress(sid, ifindex=7),
            unbound,
            msg="An unbound socket must receive datagrams from any interface.",
        )

    def test__socket_table__ingress_missing_cohort_returns_default(self) -> None:
        """
        Ensure an ingress lookup for an unregistered socket_id returns the
        supplied default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = SocketTable()
        sentinel = _make_bound_socket(_make_socket_id("x"), egress_ifindex=None)

        self.assertIs(
            table.get_for_ingress(_make_socket_id("missing"), ifindex=1, default=sentinel),
            sentinel,
            msg="A missing cohort must return the default.",
        )
