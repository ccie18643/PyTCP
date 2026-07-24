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
This module contains tests for the ICMP outbound-error rate limiter.

pytcp/tests/unit/protocols/icmp/test__icmp__error_emitter__rate_limiter.py

ver 3.0.9
"""

import threading
from typing import Any
from unittest import TestCase

from pytcp.protocols.icmp.icmp__constants import (
    ICMP__ERROR__BURST,
    ICMP__ERROR__RATE_PPS,
)
from pytcp.protocols.icmp.icmp__error_emitter import (
    IcmpErrorRateLimiter,
)
from pytcp.tests.lib.parameterized import parameterized_class


class _TrackingLock:
    """
    A lock stand-in that records the maximum context-manager hold
    depth reached so a test can prove a critical section was entered
    around an operation and released afterwards.
    """

    def __init__(self) -> None:
        """
        Wrap a real lock and start at zero hold depth.
        """

        self._lock = threading.Lock()
        self.depth = 0
        self.max_depth = 0

    def __enter__(self) -> "_TrackingLock":
        """
        Acquire the underlying lock and record the deeper hold.
        """

        self._lock.acquire()
        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        return self

    def __exit__(self, *_: object) -> None:
        """
        Record the shallower hold and release the underlying lock.
        """

        self.depth -= 1
        self._lock.release()


@parameterized_class(
    [
        {
            "_description": "Construct with explicit rate=4 and burst=5.",
            "_kwargs": {"rate_pps": 4, "burst": 5},
            "_results": {"rate_pps": 4, "burst": 5},
        },
        {
            "_description": "Construct with default rate and burst.",
            "_kwargs": {},
            "_results": {
                "rate_pps": ICMP__ERROR__RATE_PPS,
                "burst": ICMP__ERROR__BURST,
            },
        },
    ]
)
class TestIcmpErrorRateLimiter__Construction(TestCase):
    """
    The 'IcmpErrorRateLimiter' constructor tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp__rate_limiter__rate_pps(self) -> None:
        """
        Ensure 'rate_pps' is exposed as a read-only attribute matching
        the constructor argument (or the canonical default when no
        argument is provided).

        Reference: RFC 1812 §4.3.2.8 (token-bucket rate limit on ICMP errors).
        Reference: RFC 4443 §2.4(f) (analogous requirement for ICMPv6).
        """

        limiter = IcmpErrorRateLimiter(**self._kwargs)

        self.assertEqual(
            limiter.rate_pps,
            self._results["rate_pps"],
            msg=f"Unexpected 'rate_pps' for case: {self._description}",
        )

    def test__icmp__rate_limiter__burst(self) -> None:
        """
        Ensure 'burst' is exposed as a read-only attribute matching the
        constructor argument (or the canonical default when no argument
        is provided).

        Reference: RFC 1812 §4.3.2.8 (burst is the maximum bucket size).
        """

        limiter = IcmpErrorRateLimiter(**self._kwargs)

        self.assertEqual(
            limiter.burst,
            self._results["burst"],
            msg=f"Unexpected 'burst' for case: {self._description}",
        )


class TestIcmpErrorRateLimiter__Asserts(TestCase):
    """
    The 'IcmpErrorRateLimiter' constructor invariant tests.
    """

    def test__icmp__rate_limiter__rate_pps_must_be_positive(self) -> None:
        """
        Ensure 'rate_pps' must be > 0; zero or negative values would
        permit no traffic / nonsensical refill rate.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            IcmpErrorRateLimiter(rate_pps=0, burst=10)

    def test__icmp__rate_limiter__burst_must_be_positive(self) -> None:
        """
        Ensure 'burst' must be > 0; zero would permit nothing through.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            IcmpErrorRateLimiter(rate_pps=10, burst=0)


class TestIcmpErrorRateLimiter__InitialBurst(TestCase):
    """
    The 'IcmpErrorRateLimiter' starts-full bucket tests.
    """

    def test__icmp__rate_limiter__bucket_starts_full(self) -> None:
        """
        Ensure the bucket starts with a full burst quota so the first
        N ≤ burst calls all succeed without delay. This matches token-
        bucket convention and lets a well-behaved peer take its full
        burst budget on cold start.

        Reference: RFC 1812 §4.3.2.8 (burst is the maximum prompt allowance).
        """

        limiter = IcmpErrorRateLimiter(rate_pps=4, burst=5)

        for i in range(5):
            self.assertTrue(
                limiter.try_consume(now=0.0),
                msg=f"Burst-quota call {i + 1}/5 must succeed at t=0.",
            )


class TestIcmpErrorRateLimiter__Exhaustion(TestCase):
    """
    The 'IcmpErrorRateLimiter' burst-exhaustion tests.
    """

    def test__icmp__rate_limiter__sixth_call_at_t0_blocked(self) -> None:
        """
        Ensure that after consuming the full burst quota at t=0, the
        next call at the same instant is rate-limited.

        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP errors).
        """

        limiter = IcmpErrorRateLimiter(rate_pps=4, burst=5)

        for _ in range(5):
            limiter.try_consume(now=0.0)

        self.assertFalse(
            limiter.try_consume(now=0.0),
            msg="Sixth call at t=0 must be rate-limited after burst is exhausted.",
        )


class TestIcmpErrorRateLimiter__Refill(TestCase):
    """
    The 'IcmpErrorRateLimiter' time-based refill tests.
    """

    def test__icmp__rate_limiter__one_token_after_one_period(self) -> None:
        """
        Ensure that after the bucket is exhausted, advancing by one
        refill period (1 / rate_pps seconds) makes exactly one token
        available — but only one.

        Reference: RFC 1812 §4.3.2.8 (constant-rate refill).
        """

        limiter = IcmpErrorRateLimiter(rate_pps=4, burst=5)

        for _ in range(5):
            limiter.try_consume(now=0.0)

        self.assertTrue(
            limiter.try_consume(now=0.25),
            msg="One refill period must yield one available token.",
        )

        self.assertFalse(
            limiter.try_consume(now=0.25),
            msg="Only one token should accrue per refill period.",
        )

    def test__icmp__rate_limiter__refill_caps_at_burst(self) -> None:
        """
        Ensure that an arbitrarily long idle period does not let the
        bucket grow beyond the configured burst size.

        Reference: RFC 1812 §4.3.2.8 (burst is the maximum bucket size).
        """

        limiter = IcmpErrorRateLimiter(rate_pps=4, burst=5)

        for _ in range(5):
            limiter.try_consume(now=0.0)

        for i in range(5):
            self.assertTrue(
                limiter.try_consume(now=100.0),
                msg=f"Capped-burst call {i + 1}/5 must succeed at t=100.",
            )

        self.assertFalse(
            limiter.try_consume(now=100.0),
            msg="Bucket must cap at burst size, not at idle*rate.",
        )


class TestIcmpErrorRateLimiter__SubSecond(TestCase):
    """
    The 'IcmpErrorRateLimiter' sub-second precision tests.
    """

    def test__icmp__rate_limiter__partial_period_no_token(self) -> None:
        """
        Ensure a fractional refill period does not yield a full token
        — half a period earns half a token, which is not enough to
        consume.

        Reference: RFC 1812 §4.3.2.8 (constant-rate refill).
        """

        limiter = IcmpErrorRateLimiter(rate_pps=4, burst=5)

        for _ in range(5):
            limiter.try_consume(now=0.0)

        self.assertFalse(
            limiter.try_consume(now=0.125),
            msg="Half-period idle must not yield a consumable token.",
        )

    def test__icmp__rate_limiter__partial_then_complete(self) -> None:
        """
        Ensure that a partial-period and a follow-up partial-period
        together accrue a full token. Refill is continuous, not
        bucketed by call site.

        Reference: RFC 1812 §4.3.2.8 (constant-rate refill).
        """

        limiter = IcmpErrorRateLimiter(rate_pps=4, burst=5)

        for _ in range(5):
            limiter.try_consume(now=0.0)

        self.assertFalse(
            limiter.try_consume(now=0.125),
            msg="First half-period must not grant a token.",
        )

        self.assertTrue(
            limiter.try_consume(now=0.25),
            msg="Second half-period brings cumulative to one full token.",
        )


class TestIcmpErrorRateLimiter__Locking(TestCase):
    """
    The 'IcmpErrorRateLimiter' token-bucket lock-discipline tests.
    """

    def test__icmp__rate_limiter__try_consume_holds_the_lock(self) -> None:
        """
        Ensure 'try_consume' performs its token-bucket read-modify-write
        while holding the limiter lock, so the stack-wide singleton
        limiter cannot over- or under-count tokens when multiple
        interface RX threads consume concurrently on a free-threaded
        build.

        Reference: RFC 1812 §4.3.2.8 (ICMP error rate limiting).
        """

        limiter = IcmpErrorRateLimiter(rate_pps=4, burst=5)
        tracking = _TrackingLock()
        setattr(limiter, "_lock", tracking)

        limiter.try_consume(now=0.0)

        self.assertGreaterEqual(
            tracking.max_depth,
            1,
            msg="try_consume must acquire the limiter lock around the token-bucket update.",
        )
        self.assertEqual(
            tracking.depth,
            0,
            msg="try_consume must release the limiter lock.",
        )
