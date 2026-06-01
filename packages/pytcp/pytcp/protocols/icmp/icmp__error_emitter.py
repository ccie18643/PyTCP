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
This module contains the ICMP outbound-error eligibility gates and rate
limiter shared between the IPv4 and IPv6 packet handlers.

pytcp/protocols/icmp/icmp__error_emitter.py

ver 3.0.8
"""

import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import override

from pytcp.protocols.icmp import icmp__constants


class IcmpErrorBlockReason(IntEnum):
    """
    Reasons an outbound ICMP error MUST be suppressed.
    """

    INBOUND_WAS_ICMP_ERROR = 1
    INBOUND_DST_IS_BROADCAST = 2
    INBOUND_DST_IS_MULTICAST = 3
    INBOUND_SRC_INVALID = 4
    INBOUND_NON_INITIAL_FRAGMENT = 5
    RATE_LIMIT_EXCEEDED = 6

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case IcmpErrorBlockReason.INBOUND_WAS_ICMP_ERROR:
                return "inbound-was-icmp-error"
            case IcmpErrorBlockReason.INBOUND_DST_IS_BROADCAST:
                return "inbound-dst-broadcast"
            case IcmpErrorBlockReason.INBOUND_DST_IS_MULTICAST:
                return "inbound-dst-multicast"
            case IcmpErrorBlockReason.INBOUND_SRC_INVALID:
                return "inbound-src-invalid"
            case IcmpErrorBlockReason.INBOUND_NON_INITIAL_FRAGMENT:
                return "inbound-non-initial-fragment"
            case IcmpErrorBlockReason.RATE_LIMIT_EXCEEDED:
                return "rate-limit-exceeded"


@dataclass(frozen=True, kw_only=True, slots=True)
class IcmpErrorContext:
    """
    Inbound-packet context that gates whether an outbound ICMP error
    is permitted under the host requirements.
    """

    inbound_was_icmp_error: bool = False
    inbound_dst_is_broadcast: bool = False
    inbound_dst_is_multicast: bool = False
    inbound_src_invalid: bool = False
    inbound_non_initial_fragment: bool = False
    is_pmtud_response: bool = False
    is_param_problem_code_2: bool = False


def should_emit_icmp_error(ctx: IcmpErrorContext, /) -> IcmpErrorBlockReason | None:
    """
    Return None if emission is permitted; otherwise the blocking reason.
    """

    if ctx.inbound_was_icmp_error:
        return IcmpErrorBlockReason.INBOUND_WAS_ICMP_ERROR

    if ctx.inbound_dst_is_broadcast:
        return IcmpErrorBlockReason.INBOUND_DST_IS_BROADCAST

    if ctx.inbound_dst_is_multicast and not (ctx.is_pmtud_response or ctx.is_param_problem_code_2):
        return IcmpErrorBlockReason.INBOUND_DST_IS_MULTICAST

    if ctx.inbound_src_invalid:
        return IcmpErrorBlockReason.INBOUND_SRC_INVALID

    if ctx.inbound_non_initial_fragment:
        return IcmpErrorBlockReason.INBOUND_NON_INITIAL_FRAGMENT

    return None


class IcmpErrorRateLimiter:
    """
    Token-bucket rate limiter for outbound ICMP errors.
    """

    _rate_pps: int
    _burst: int
    _tokens: float
    _last_refill: float | None
    _lock: threading.Lock

    def __init__(
        self,
        *,
        rate_pps: int | None = None,
        burst: int | None = None,
    ) -> None:
        """
        Initialize the ICMP error rate limiter. With no explicit
        'rate_pps' / 'burst' kwargs, read the LIVE sysctl-backed
        defaults via qualified module access so operators tuning
        the sysctl BEFORE construction (e.g. via
        'stack.init(sysctls={"icmp.error.rate_pps": ...})') see the
        override take effect on this instance.
        """

        if rate_pps is None:
            rate_pps = icmp__constants.ICMP__ERROR__RATE_PPS
        if burst is None:
            burst = icmp__constants.ICMP__ERROR__BURST

        assert rate_pps > 0, f"The 'rate_pps' field must be positive. Got: {rate_pps!r}"
        assert burst > 0, f"The 'burst' field must be positive. Got: {burst!r}"

        self._rate_pps = rate_pps
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = None
        # The limiters are stack-wide singletons; in multi-interface
        # mode every interface's rx-ring thread consumes from the same
        # bucket, so the token-bucket read-modify-write below must be
        # atomic — under free-threaded CPython a bare RMW over/under-
        # counts tokens.
        self._lock = threading.Lock()

    @property
    def rate_pps(self) -> int:
        """
        Get the configured token-refill rate, in packets per second.
        """

        return self._rate_pps

    @property
    def burst(self) -> int:
        """
        Get the configured maximum burst size, in tokens.
        """

        return self._burst

    def try_consume(self, *, now: float) -> bool:
        """
        Consume one token; return True if granted, False if rate-limited.
        """

        with self._lock:
            if self._last_refill is None:
                self._last_refill = now

            elapsed = max(0.0, now - self._last_refill)
            self._tokens = min(float(self._burst), self._tokens + elapsed * self._rate_pps)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True

            return False


def try_emit_icmp_error(
    ctx: IcmpErrorContext,
    /,
    *,
    rate_limiter: IcmpErrorRateLimiter,
    now: float,
) -> IcmpErrorBlockReason | None:
    """
    Compose the host-requirements gate and the rate limiter into a
    single emit/drop decision.

    Returns None if emission is permitted; the block reason otherwise.
    A gate-block does NOT consume a rate-limiter token.
    """

    if (reason := should_emit_icmp_error(ctx)) is not None:
        return reason

    if not rate_limiter.try_consume(now=now):
        return IcmpErrorBlockReason.RATE_LIMIT_EXCEEDED

    return None
