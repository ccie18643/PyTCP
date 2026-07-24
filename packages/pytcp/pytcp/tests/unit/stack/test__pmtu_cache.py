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
Unit test for the 'stack.pmtu_cache' module-level state introduced
by Phase 3 of the ICMP demux + PMTUD refactor. The cache itself is
just a 'dict' — what this test pins is that the attribute exists,
its annotation matches the design, and its default state is empty.

pytcp/tests/unit/stack/test__pmtu_cache.py

ver 3.0.9
"""

import threading
from typing import override
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp import stack
from pytcp.lib.plpmtud import PmtuSearch


class TestPmtuCache(TestCase):
    """
    The 'stack.pmtu_cache' substrate.
    """

    def test__pmtu_cache__attribute_exists(self) -> None:
        """
        Ensure 'stack.pmtu_cache' is defined at module scope.

        Reference: RFC 1191 §3 (Path MTU Discovery).
        """

        self.assertTrue(
            hasattr(stack, "pmtu_cache"),
            msg="stack.pmtu_cache must be defined at module scope.",
        )

    def test__pmtu_cache__is_dict(self) -> None:
        """
        Ensure 'stack.pmtu_cache' is a plain dict so callers can
        snapshot/clear/restore it via the standard dict idioms used
        elsewhere in the test framework.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            stack.pmtu_cache,
            dict,
            msg="stack.pmtu_cache must be a dict[Ip4Address | Ip6Address, int].",
        )

    def test__pmtu_cache__accepts_ip4_key(self) -> None:
        """
        Ensure an Ip4Address key with an integer MTU value can be
        stored and retrieved without surprises.

        Reference: RFC 1191 §3 (PMTUD per-destination MTU cache).
        """

        ip = Ip4Address("10.0.1.91")
        try:
            stack.pmtu_cache[ip] = 1400
            self.assertEqual(
                stack.pmtu_cache[ip],
                1400,
                msg="stack.pmtu_cache must accept an Ip4Address key with an int MTU value.",
            )
        finally:
            stack.pmtu_cache.pop(ip, None)

    def test__pmtu_cache__accepts_ip6_key(self) -> None:
        """
        Ensure an Ip6Address key with an integer MTU value can be
        stored and retrieved.

        Reference: RFC 8201 §4 (IPv6 PMTUD per-destination MTU cache).
        """

        ip = Ip6Address("2001:db8:0:1::91")
        try:
            stack.pmtu_cache[ip] = 1280
            self.assertEqual(
                stack.pmtu_cache[ip],
                1280,
                msg="stack.pmtu_cache must accept an Ip6Address key with an int MTU value.",
            )
        finally:
            stack.pmtu_cache.pop(ip, None)


class _TrackingLock:
    """
    A lock that counts how many times it was entered (and its current
    hold depth) so a test can assert an operation acquired it.
    """

    def __init__(self) -> None:
        """
        Wrap a real lock and start at zero entries / hold depth.
        """

        self._lock = threading.Lock()
        self.entries = 0
        self.depth = 0

    def __enter__(self) -> "_TrackingLock":
        """
        Acquire the underlying lock and record the entry.
        """

        self._lock.acquire()
        self.entries += 1
        self.depth += 1
        return self

    def __exit__(self, *_: object) -> None:
        """
        Record the shallower hold and release the underlying lock.
        """

        self.depth -= 1
        self._lock.release()


class _LockAssertingDict[K, V](dict[K, V]):
    """
    A dict that records, on every structural mutation, whether the
    tracking lock was held at the moment of the write.
    """

    def __init__(self, lock: _TrackingLock, observed: list[bool], /) -> None:
        """
        Start empty and remember where to record observations.
        """

        super().__init__()
        self._lock = lock
        self._observed = observed

    @override
    def __setitem__(self, key: K, value: V) -> None:
        """
        Record the lock-held state, then insert / replace the key.
        """

        self._observed.append(self._lock.depth > 0)
        super().__setitem__(key, value)


class TestPmtuCacheLocking(TestCase):
    """
    The 'stack' Path-MTU cache thread-safety tests — the 'pmtu_cache'
    and 'pmtu_state' maps are written by the RX (ICMP) thread and the
    application / TX (UDP / TCP) threads and read by 'current_pmtu', so
    every access must hold the shared lock for the maps not to tear on a
    free-threaded build.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the pmtu maps and the lock so the instrumentation each
        test installs is fully restored afterwards.
        """

        self._cache_prior = stack.pmtu_cache
        self._state_prior = stack.pmtu_state
        self._lock_prior = getattr(stack, "_pmtu_lock", None)

    @override
    def tearDown(self) -> None:
        """
        Restore the original pmtu maps and lock.
        """

        setattr(stack, "pmtu_cache", self._cache_prior)
        setattr(stack, "pmtu_state", self._state_prior)
        if self._lock_prior is not None:
            setattr(stack, "_pmtu_lock", self._lock_prior)

    def test__pmtu__current_pmtu_reads_under_lock(self) -> None:
        """
        Ensure 'current_pmtu' reads the Path-MTU maps while holding the
        shared pmtu lock, so a concurrent ICMP / TX write cannot tear the
        map under the reader on a free-threaded build.

        Reference: RFC 8201 §5.2 (a host caches and reads PMTU per destination).
        """

        tracking = _TrackingLock()
        destination = Ip4Address("10.0.1.42")
        setattr(stack, "_pmtu_lock", tracking)
        setattr(stack, "pmtu_cache", {destination: 1400})
        setattr(stack, "pmtu_state", {})

        result = stack.current_pmtu(destination)

        self.assertEqual(
            result,
            1400,
            msg="current_pmtu must return the cached classical next-hop MTU.",
        )
        self.assertGreater(
            tracking.entries,
            0,
            msg="current_pmtu must acquire the shared pmtu lock while reading the maps.",
        )

    def test__pmtu__record_classical_writes_under_lock(self) -> None:
        """
        Ensure recording a classical per-destination next-hop MTU mutates
        the 'pmtu_cache' map while holding the shared pmtu lock.

        Reference: RFC 1191 §3 (Path MTU Discovery per-destination cache).
        """

        tracking = _TrackingLock()
        observed: list[bool] = []
        destination = Ip4Address("10.0.1.43")
        setattr(stack, "_pmtu_lock", tracking)
        setattr(stack, "pmtu_cache", _LockAssertingDict[object, object](tracking, observed))
        setattr(stack, "pmtu_state", {})

        stack.record_classical_pmtu(destination, 1380)

        self.assertEqual(
            stack.pmtu_cache[destination],
            1380,
            msg="record_classical_pmtu must store the next-hop MTU.",
        )
        self.assertTrue(
            observed and all(observed),
            msg="record_classical_pmtu must mutate pmtu_cache while holding the shared pmtu lock.",
        )

    def test__pmtu__record_engine_writes_under_lock(self) -> None:
        """
        Ensure recording a PLPMTUD engine for a destination mutates the
        'pmtu_state' map while holding the shared pmtu lock.

        Reference: RFC 8899 §5.2 (PLPMTUD maintains per-path search state).
        """

        tracking = _TrackingLock()
        observed: list[bool] = []
        destination = Ip4Address("10.0.1.44")
        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=destination, interface_mtu=1500)
        setattr(stack, "_pmtu_lock", tracking)
        setattr(stack, "pmtu_cache", {})
        setattr(stack, "pmtu_state", _LockAssertingDict[object, object](tracking, observed))

        stack.record_pmtu_engine(destination, engine)

        self.assertIs(
            stack.pmtu_state[destination],
            engine,
            msg="record_pmtu_engine must store the engine for the destination.",
        )
        self.assertTrue(
            observed and all(observed),
            msg="record_pmtu_engine must mutate pmtu_state while holding the shared pmtu lock.",
        )
