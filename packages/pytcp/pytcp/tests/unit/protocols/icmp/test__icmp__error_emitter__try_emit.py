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
This module contains tests for the ICMP outbound-error try_emit composition.

pytcp/tests/unit/protocols/icmp/test__icmp__error_emitter__try_emit.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.icmp.icmp__error_emitter import (
    IcmpErrorBlockReason,
    IcmpErrorContext,
    IcmpErrorRateLimiter,
    try_emit_icmp_error,
)


class TestTryEmitIcmpError__Permits(TestCase):
    """
    The 'try_emit_icmp_error' permit-path tests.
    """

    def test__icmp__try_emit__clean_context_with_token_permits(self) -> None:
        """
        Ensure a clean context with an available token returns None
        (emission permitted) and consumes one token from the bucket.

        Reference: RFC 1122 §3.2.2 (host MUST-NOT-emit gates; permit when none fire).
        Reference: RFC 1812 §4.3.2.8 (token-bucket rate limit).
        """

        rate_limiter = IcmpErrorRateLimiter(rate_pps=4, burst=2)

        verdict = try_emit_icmp_error(
            IcmpErrorContext(),
            rate_limiter=rate_limiter,
            now=0.0,
        )

        self.assertIsNone(
            verdict,
            msg="Clean context with token must permit emission.",
        )

        # One token consumed; only one left.
        verdict_second = try_emit_icmp_error(
            IcmpErrorContext(),
            rate_limiter=rate_limiter,
            now=0.0,
        )
        self.assertIsNone(
            verdict_second,
            msg="Second call within burst must still permit.",
        )

        # Bucket exhausted.
        verdict_third = try_emit_icmp_error(
            IcmpErrorContext(),
            rate_limiter=rate_limiter,
            now=0.0,
        )
        self.assertEqual(
            verdict_third,
            IcmpErrorBlockReason.RATE_LIMIT_EXCEEDED,
            msg="Third call must be rate-limited (burst=2 exhausted).",
        )


class TestTryEmitIcmpError__GateBlock(TestCase):
    """
    The 'try_emit_icmp_error' gate-block tests.
    """

    def test__icmp__try_emit__gate_block_returns_gate_reason(self) -> None:
        """
        Ensure that when the gate fires, the returned reason is the
        gate's verdict (not RATE_LIMIT_EXCEEDED).

        Reference: RFC 1122 §3.2.2 (gate verdict precedes rate-limit check).
        """

        rate_limiter = IcmpErrorRateLimiter(rate_pps=4, burst=5)

        verdict = try_emit_icmp_error(
            IcmpErrorContext(inbound_was_icmp_error=True),
            rate_limiter=rate_limiter,
            now=0.0,
        )

        self.assertEqual(
            verdict,
            IcmpErrorBlockReason.INBOUND_WAS_ICMP_ERROR,
            msg="Gate-blocked emission must return the gate reason.",
        )

    def test__icmp__try_emit__gate_block_does_not_consume_token(self) -> None:
        """
        Ensure that a gate-blocked emission does NOT consume a token.
        The bucket must remain available for legitimate subsequent
        emissions.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rate_limiter = IcmpErrorRateLimiter(rate_pps=4, burst=1)

        # Gate-block: should not consume the single token.
        try_emit_icmp_error(
            IcmpErrorContext(inbound_was_icmp_error=True),
            rate_limiter=rate_limiter,
            now=0.0,
        )

        # Clean context: should still have one token available.
        verdict = try_emit_icmp_error(
            IcmpErrorContext(),
            rate_limiter=rate_limiter,
            now=0.0,
        )

        self.assertIsNone(
            verdict,
            msg="Clean call after gate-block must find the token still available.",
        )


class TestTryEmitIcmpError__RateLimit(TestCase):
    """
    The 'try_emit_icmp_error' rate-limit-block tests.
    """

    def test__icmp__try_emit__exhausted_bucket_returns_rate_limit(self) -> None:
        """
        Ensure that when the gate permits but the bucket is empty,
        the verdict is RATE_LIMIT_EXCEEDED.

        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP errors).
        Reference: RFC 4443 §2.4(f) (analogous for ICMPv6).
        """

        rate_limiter = IcmpErrorRateLimiter(rate_pps=4, burst=1)

        # Drain the single token.
        try_emit_icmp_error(
            IcmpErrorContext(),
            rate_limiter=rate_limiter,
            now=0.0,
        )

        # Next call: gate clean but no token.
        verdict = try_emit_icmp_error(
            IcmpErrorContext(),
            rate_limiter=rate_limiter,
            now=0.0,
        )

        self.assertEqual(
            verdict,
            IcmpErrorBlockReason.RATE_LIMIT_EXCEEDED,
            msg="Exhausted bucket must yield RATE_LIMIT_EXCEEDED.",
        )

    def test__icmp__try_emit__refill_after_exhaustion_permits(self) -> None:
        """
        Ensure that after the bucket refills, try_emit permits again.

        Reference: RFC 1812 §4.3.2.8 (constant-rate refill).
        """

        rate_limiter = IcmpErrorRateLimiter(rate_pps=4, burst=1)
        try_emit_icmp_error(IcmpErrorContext(), rate_limiter=rate_limiter, now=0.0)

        verdict = try_emit_icmp_error(
            IcmpErrorContext(),
            rate_limiter=rate_limiter,
            now=0.25,
        )

        self.assertIsNone(
            verdict,
            msg="One refill period after exhaustion must permit again.",
        )
