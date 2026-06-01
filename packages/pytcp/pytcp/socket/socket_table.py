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
This module contains the lock-guarded registry of open stack sockets.

pytcp/socket/socket_table.py

ver 3.0.8
"""

import threading
from collections.abc import Iterator, Mapping

from pytcp.socket import socket
from pytcp.socket.socket_id import SocketId


class SocketTable:
    """
    The stack-wide registry of open sockets keyed by 'SocketId'.

    A lock-guarded registry whose every operation is serialized by a
    single lock. The registry is read by the RX-side packet handlers
    (delivery lookups) while app threads register / unregister
    sockets at bind / connect / close time; compound access (and
    free-threaded / no-GIL builds) need the explicit lock.

    SO_REUSEPORT support makes each 'SocketId' map to a *cohort* — a
    list of sockets — rather than a single socket. In the common
    (non-REUSEPORT) case a cohort holds exactly one member, but a
    listening 'SocketId' (remote unspecified, port 0) may carry
    several when multiple sockets bound the same 4-tuple with
    'SO_REUSEPORT'. 'get' load-balances delivery across a
    multi-member cohort with round-robin selection (a deliberate
    Phase-1 simplification of Linux's 4-tuple-hash demux — see
    'docs/refactor/socket_parity_followup.md'); a single-member
    cohort always returns its sole member, so established-connection
    lookups stay deterministic.

    'register' / 'unregister' are the SO_REUSEPORT-aware production
    API (append-to / remove-from cohort). The dict-style shims
    ('__setitem__' / '__delitem__' / 'pop' / '__getitem__' /
    'update') retain their historical single-socket semantics so the
    test harness's snapshot / restore primitives keep working
    unchanged; '__setitem__' / 'update' replace a cohort with a
    single member, and '__getitem__' / 'pop' surface the cohort's
    first / last member. 'dict(table)' is therefore single-socket per
    id (lossy for a live REUSEPORT cohort, which no harness snapshots).

    Iteration accessors ('values' / 'keys' / 'items' / '__iter__')
    return detached snapshots taken under the lock, so an RX or
    control thread can iterate the open-socket set while another
    thread mutates it without risking
    'RuntimeError: dictionary changed size during iteration'.
    'values' / 'items' flatten every cohort member, so they may
    return more entries than 'len(table)' (the number of registered
    ids) when a REUSEPORT cohort is present.
    """

    def __init__(self) -> None:
        """
        Initialize an empty registry and its guarding lock.
        """

        self._lock = threading.Lock()
        self._sockets: dict[SocketId, list[socket]] = {}
        # Per-cohort round-robin cursor, populated lazily for
        # multi-member (REUSEPORT) cohorts only.
        self._rr_cursor: dict[SocketId, int] = {}

    def register(self, sock: socket) -> None:
        """
        Append 'sock' to the cohort for its current 'socket_id'.

        Identity-idempotent: re-registering the same object is a
        no-op. This is the SO_REUSEPORT-aware insert — two sockets
        sharing a listening 'SocketId' both land in the cohort
        instead of the second clobbering the first.
        """

        with self._lock:
            cohort = self._sockets.setdefault(sock.socket_id, [])
            if not any(existing is sock for existing in cohort):
                cohort.append(sock)

    def unregister(self, sock: socket) -> None:
        """
        Remove 'sock' (by identity) from the cohort for its current
        'socket_id'. Dropping the final member removes the id and its
        round-robin cursor. Unregistering an absent socket is a
        silent no-op (matches the tolerant 'pop' default).
        """

        with self._lock:
            cohort = self._sockets.get(sock.socket_id)
            if cohort is None:
                return
            cohort[:] = [existing for existing in cohort if existing is not sock]
            if not cohort:
                del self._sockets[sock.socket_id]
                self._rr_cursor.pop(sock.socket_id, None)

    def get(self, socket_id: SocketId, default: socket | None = None) -> socket | None:
        """
        Return one socket from the cohort under 'socket_id', or
        'default' when no cohort is registered.

        A single-member cohort always returns its sole member. A
        multi-member (SO_REUSEPORT) cohort round-robins across its
        members on successive calls so inbound connections /
        datagrams load-balance across the cohort.
        """

        with self._lock:
            cohort = self._sockets.get(socket_id)
            if not cohort:
                return default
            if len(cohort) == 1:
                return cohort[0]
            index = self._rr_cursor.get(socket_id, 0)
            self._rr_cursor[socket_id] = (index + 1) % len(cohort)
            return cohort[index % len(cohort)]

    def pop(self, socket_id: SocketId, default: socket | None = None) -> socket | None:
        """
        Remove the entire cohort under 'socket_id' and return its last
        member (single-socket compat shim), or 'default' when absent.
        """

        with self._lock:
            cohort = self._sockets.pop(socket_id, None)
            self._rr_cursor.pop(socket_id, None)
            return cohort[-1] if cohort else default

    def __getitem__(self, socket_id: SocketId) -> socket:
        """
        Return the first cohort member under 'socket_id' (or raise).
        """

        with self._lock:
            return self._sockets[socket_id][0]

    def __setitem__(self, socket_id: SocketId, sock: socket) -> None:
        """
        Register 'sock' under 'socket_id' as a single-member cohort,
        replacing any prior cohort (single-socket compat shim).
        """

        with self._lock:
            self._sockets[socket_id] = [sock]
            self._rr_cursor.pop(socket_id, None)

    def __delitem__(self, socket_id: SocketId) -> None:
        """
        Remove the entire cohort under 'socket_id' (or raise).
        """

        with self._lock:
            del self._sockets[socket_id]
            self._rr_cursor.pop(socket_id, None)

    def __contains__(self, socket_id: SocketId) -> bool:
        """
        Return whether any socket is registered under 'socket_id'.
        """

        with self._lock:
            return socket_id in self._sockets

    def __len__(self) -> int:
        """
        Return the number of registered ids (not cohort members).
        """

        with self._lock:
            return len(self._sockets)

    def __iter__(self) -> Iterator[SocketId]:
        """
        Return an iterator over a snapshot of the registered ids.
        """

        with self._lock:
            return iter(list(self._sockets))

    def keys(self) -> list[SocketId]:
        """
        Return a snapshot list of the registered ids.
        """

        with self._lock:
            return list(self._sockets.keys())

    def values(self) -> list[socket]:
        """
        Return a snapshot list of every registered socket, flattening
        all cohorts.
        """

        with self._lock:
            return [sock for cohort in self._sockets.values() for sock in cohort]

    def items(self) -> list[tuple[SocketId, socket]]:
        """
        Return a snapshot list of (id, socket) pairs, one per cohort
        member.
        """

        with self._lock:
            return [(socket_id, sock) for socket_id, cohort in self._sockets.items() for sock in cohort]

    def clear(self) -> None:
        """
        Remove every registered socket.
        """

        with self._lock:
            self._sockets.clear()
            self._rr_cursor.clear()

    def update(self, other: Mapping[SocketId, socket]) -> None:
        """
        Bulk-install the mappings from 'other' as single-member
        cohorts (single-socket compat shim for the harness restore).
        """

        with self._lock:
            for socket_id, sock in other.items():
                self._sockets[socket_id] = [sock]
                self._rr_cursor.pop(socket_id, None)
