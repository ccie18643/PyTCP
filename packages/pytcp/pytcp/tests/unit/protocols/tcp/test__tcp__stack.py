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
This module contains unit tests for the TCP-specific stack-level
state container in 'pytcp/protocols/tcp/tcp__stack.py'.

pytcp/tests/unit/protocols/tcp/test__tcp__stack.py

ver 3.0.8
"""

from types import TracebackType
from typing import Self, override
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp.protocols.tcp.tcp__stack import TcpStack

_PEER_A = Ip4Address("203.0.113.1")


class _TrackingLock:
    """
    A 'threading.Lock' stand-in that records the maximum
    context-manager hold depth so a test can prove an accessor
    acquired the lock for the duration of its critical section.
    """

    def __init__(self) -> None:
        """
        Initialize the hold-depth counters.
        """

        self.depth = 0
        self.max_depth = 0

    def __enter__(self) -> Self:
        """
        Enter the guarded section, bumping the hold depth.
        """

        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """
        Leave the guarded section, dropping the hold depth.
        """

        self.depth -= 1


class _LockAssertingDict(dict[Ip4Address | Ip6Address, bytes]):
    """
    A dict that records whether a tracking lock was held at the
    moment of each mutating operation, so a test can prove the
    cookie-cache write happened inside the critical section.
    """

    def __init__(self, probe: _TrackingLock) -> None:
        """
        Bind the dict to the tracking lock it should observe.
        """

        super().__init__()
        self._probe = probe
        self.held_on_setitem = True
        self.held_on_delitem = True

    @override
    def __setitem__(self, key: Ip4Address | Ip6Address, value: bytes) -> None:
        """
        Record the lock state, then perform the insertion.
        """

        self.held_on_setitem = self.held_on_setitem and self._probe.depth > 0
        super().__setitem__(key, value)

    @override
    def __delitem__(self, key: Ip4Address | Ip6Address) -> None:
        """
        Record the lock state, then perform the deletion.
        """

        self.held_on_delitem = self.held_on_delitem and self._probe.depth > 0
        super().__delitem__(key)


class _LockAssertingSet(set[Ip4Address | Ip6Address]):
    """
    A set that records whether a tracking lock was held at the
    moment of each 'add', so a test can prove the negative-cache
    write happened inside the critical section.
    """

    def __init__(self, probe: _TrackingLock) -> None:
        """
        Bind the set to the tracking lock it should observe.
        """

        super().__init__()
        self._probe = probe
        self.held_on_add = True

    @override
    def add(self, element: Ip4Address | Ip6Address) -> None:
        """
        Record the lock state, then perform the insertion.
        """

        self.held_on_add = self.held_on_add and self._probe.depth > 0
        super().add(element)


class TestTcpStack__Accessors(TestCase):
    """
    The lock-guarded Fast-Open accessor surface tests.
    """

    @override
    def setUp(self) -> None:
        """
        Construct a default state instance for every test.
        """

        self._stack = TcpStack()

    def test__tcp_stack__cache_fastopen_cookie_stores_and_reads_back(self) -> None:
        """
        Ensure 'cache_fastopen_cookie' inserts a peer cookie that
        'fastopen_cookie' then returns, so the client-side cache
        round-trips through the guarded accessors.

        Reference: RFC 7413 §3.1 (Fast Open cookie cache).
        """

        self._stack.cache_fastopen_cookie(peer=_PEER_A, cookie=b"abcd", max_size=4)

        self.assertEqual(
            self._stack.fastopen_cookie(_PEER_A),
            b"abcd",
            msg="cache_fastopen_cookie must store a cookie that fastopen_cookie returns.",
        )

    def test__tcp_stack__fastopen_cookie_absent_returns_none(self) -> None:
        """
        Ensure 'fastopen_cookie' returns None for a peer with no
        cached cookie so a first active-open SYN issues an empty
        cookie-request rather than replaying a stale value.

        Reference: RFC 7413 §3.1 (Fast Open cookie cache).
        """

        self.assertIsNone(
            self._stack.fastopen_cookie(_PEER_A),
            msg="fastopen_cookie must return None for an uncached peer.",
        )

    def test__tcp_stack__cache_fastopen_cookie_fifo_evicts_at_max_size(self) -> None:
        """
        Ensure 'cache_fastopen_cookie' evicts the oldest entry
        once the cache exceeds 'max_size', bounding the cookie
        cache to the configured cap.

        Reference: RFC 7413 §3.1 (Fast Open cookie cache eviction).
        """

        peers = [Ip4Address(f"198.51.100.{octet}") for octet in range(1, 5)]
        for peer in peers:
            self._stack.cache_fastopen_cookie(peer=peer, cookie=b"ck", max_size=2)

        self.assertIsNone(
            self._stack.fastopen_cookie(peers[0]),
            msg="The oldest cookie must be FIFO-evicted once the cache exceeds max_size.",
        )
        self.assertEqual(
            self._stack.fastopen_cookie(peers[-1]),
            b"ck",
            msg="The most-recently-cached cookie must survive eviction.",
        )

    def test__tcp_stack__mark_and_query_fastopen_negative(self) -> None:
        """
        Ensure 'mark_fastopen_negative' records a peer that
        'is_fastopen_negative' then reports, so subsequent
        active-open attempts bypass the TFO option for that peer.

        Reference: RFC 7413 §4.1.3.1 (negative-response cache).
        """

        self.assertFalse(
            self._stack.is_fastopen_negative(_PEER_A),
            msg="is_fastopen_negative must be False before the peer is marked.",
        )

        self._stack.mark_fastopen_negative(_PEER_A)

        self.assertTrue(
            self._stack.is_fastopen_negative(_PEER_A),
            msg="is_fastopen_negative must be True after mark_fastopen_negative.",
        )

    def test__tcp_stack__pending_increment_and_decrement(self) -> None:
        """
        Ensure 'incr_fastopen_pending' / 'decr_fastopen_pending'
        move the PendingFastOpenRequests count that
        'fastopen_pending' reports, gating TFO acceptance.

        Reference: RFC 7413 §4.2 (PendingFastOpenRequests).
        """

        self._stack.incr_fastopen_pending()
        self._stack.incr_fastopen_pending()
        self._stack.decr_fastopen_pending()

        self.assertEqual(
            self._stack.fastopen_pending(),
            1,
            msg="fastopen_pending must reflect two increments and one decrement.",
        )

    def test__tcp_stack__decr_fastopen_pending_clamps_at_zero(self) -> None:
        """
        Ensure 'decr_fastopen_pending' never drives the count
        below zero so a spurious decrement cannot wrap the gate
        into permanently admitting TFO.

        Reference: RFC 7413 §4.2 (PendingFastOpenRequests).
        """

        self._stack.decr_fastopen_pending()

        self.assertEqual(
            self._stack.fastopen_pending(),
            0,
            msg="decr_fastopen_pending must clamp the count at zero.",
        )

    def test__tcp_stack__cache_fastopen_cookie_holds_lock_on_write(self) -> None:
        """
        Ensure 'cache_fastopen_cookie' performs its cookie-cache
        mutation while holding the stack lock so a concurrent RX
        or TX thread cannot observe a torn dict under no-GIL
        CPython.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        probe = _TrackingLock()
        recorder = _LockAssertingDict(probe)
        setattr(self._stack, "_lock", probe)
        setattr(self._stack, "fastopen_cookies", recorder)

        self._stack.cache_fastopen_cookie(peer=_PEER_A, cookie=b"abcd", max_size=4)

        self.assertTrue(
            recorder.held_on_setitem,
            msg="cache_fastopen_cookie must hold the lock while writing the cookie cache.",
        )

    def test__tcp_stack__mark_fastopen_negative_holds_lock_on_write(self) -> None:
        """
        Ensure 'mark_fastopen_negative' performs its set insertion
        while holding the stack lock so a concurrent thread cannot
        observe a torn set under no-GIL CPython.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        probe = _TrackingLock()
        recorder = _LockAssertingSet(probe)
        setattr(self._stack, "_lock", probe)
        setattr(self._stack, "fastopen_negative", recorder)

        self._stack.mark_fastopen_negative(_PEER_A)

        self.assertTrue(
            recorder.held_on_add,
            msg="mark_fastopen_negative must hold the lock while writing the negative cache.",
        )

    def test__tcp_stack__pending_mutators_acquire_lock(self) -> None:
        """
        Ensure the PendingFastOpenRequests mutators acquire the
        stack lock so the non-atomic read-modify-write of the
        scalar count cannot lose an update under no-GIL CPython.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        probe = _TrackingLock()
        setattr(self._stack, "_lock", probe)

        self._stack.incr_fastopen_pending()
        self._stack.decr_fastopen_pending()

        self.assertGreaterEqual(
            probe.max_depth,
            1,
            msg="The pending-count mutators must acquire the stack lock.",
        )
        self.assertEqual(
            probe.depth,
            0,
            msg="The pending-count mutators must release the stack lock.",
        )


class TestTcpStack__Defaults(TestCase):
    """
    Per-field default values pinning the post-construction state
    of 'TcpStack'.
    """

    @override
    def setUp(self) -> None:
        """
        Construct a default state instance for every test.
        """

        self._stack = TcpStack()

    def test__tcp_stack__fastopen_cookies_default_empty(self) -> None:
        """
        Ensure 'fastopen_cookies' defaults to an empty dict so a
        freshly-constructed stack has no cached TFO cookies — a
        first active-open SYN to any peer will issue an empty
        cookie-request rather than a stale replay.

        Reference: RFC 7413 §3.1 (Fast Open cookie cache).
        """

        self.assertEqual(
            self._stack.fastopen_cookies,
            {},
            msg="TcpStack.fastopen_cookies must default to {}.",
        )

    def test__tcp_stack__fastopen_negative_default_empty(self) -> None:
        """
        Ensure 'fastopen_negative' defaults to an empty set so a
        freshly-constructed stack does not bypass TFO for any
        peer — every peer gets a TFO-bearing SYN on the first
        active-open attempt.

        Reference: RFC 7413 §4.1.3.1 (negative-response cache).
        """

        self.assertEqual(
            self._stack.fastopen_negative,
            set(),
            msg="TcpStack.fastopen_negative must default to set().",
        )

    def test__tcp_stack__fastopen_pending_count_default_zero(self) -> None:
        """
        Ensure 'fastopen_pending_count' defaults to 0 so a
        freshly-constructed stack admits TFO-accepted SYNs up
        to the 'fastopen_qlen' configured on the listening
        socket without the gate triggering on a phantom prior
        count.

        Reference: RFC 7413 §4.2 (PendingFastOpenRequests).
        """

        self.assertEqual(
            self._stack.fastopen_pending_count,
            0,
            msg="TcpStack.fastopen_pending_count must default to 0.",
        )

    def test__tcp_stack__instances_own_independent_collections(self) -> None:
        """
        Ensure two distinct 'TcpStack' instances own independent
        'fastopen_cookies' and 'fastopen_negative' collections via
        'default_factory'. A test fixture that replaces
        'stack.tcp_stack' with a fresh instance must not share
        mutable state with the prior instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack_a = TcpStack()
        stack_b = TcpStack()

        self.assertIsNot(
            stack_a.fastopen_cookies,
            stack_b.fastopen_cookies,
            msg="Distinct TcpStack instances must own distinct fastopen_cookies dicts.",
        )
        self.assertIsNot(
            stack_a.fastopen_negative,
            stack_b.fastopen_negative,
            msg="Distinct TcpStack instances must own distinct fastopen_negative sets.",
        )
