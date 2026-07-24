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
This module contains the RFC 6298 RTO (retransmission timeout) estimator.

RFC 6298 §2 specifies how to compute and adjust the retransmission timeout
based on round-trip-time (RTT) measurements:

    First sample R (§2.2):
        SRTT     = R
        RTTVAR   = R / 2
        RTO      = SRTT + max(G, K * RTTVAR)              where K=4

    Subsequent sample R' (§2.3):
        RTTVAR   = (1 - β) * RTTVAR + β * |SRTT - R'|     where β = 1/4
        SRTT     = (1 - α) * SRTT + α * R'                where α = 1/8
        RTO      = SRTT + max(G, K * RTTVAR)

    Bounds:
        RTO SHOULD be rounded up to 1 second if smaller (§2.4)
        RTO MAY have an upper bound provided it is at least 60 seconds (§2.5)

    On retransmit timeout (§5.5):
        RTO = RTO * 2 ('back off the timer')
        Capped at the upper bound

This helper exposes the formulas as pure functions on an immutable
'RtoState' triple. The TcpSession integration (the eventual fix
commit) consumes one fresh sample per RTT, applies Karn's algorithm
to skip samples from retransmitted segments (§3), and uses the
'rto_ms' field as the live retransmit-timer interval.

pytcp/protocols/tcp/tcp__rto.py

ver 3.0.9
"""

from dataclasses import dataclass

# RFC 6298 §2.1 / RFC 8961: initial RTO before any RTT sample.
# Both RFCs converge on 1 second.
INITIAL_RTO_MS: int = 1000

# RFC 6298 §2.4 lower bound: SHOULD be rounded up to 1 second.
MIN_RTO_MS: int = 1000

# RFC 6298 §2.5 upper bound: MAY be placed on RTO provided it is
# at least 60 seconds. PyTCP picks the lowest legal value.
MAX_RTO_MS: int = 60_000

# RFC 6298 §2.2 'G' clock granularity. PyTCP's timer subsystem
# advances in 1 ms ticks, so G is 1 ms (the RFC says "should be
# small ... 100 ms or less" which our value comfortably satisfies).
CLOCK_GRANULARITY_MS: int = 1

# RFC 6298 §2.2 'K' multiplier for RTTVAR in the RTO computation.
K: int = 4

# RFC 6298 §2.3 'α' weight for the SRTT EWMA.
# SRTT' = (1 - α) * SRTT + α * R'  with α = 1/8.
# Stored as numerator/denominator so integer arithmetic is exact:
# SRTT' = ((ALPHA_DEN - ALPHA_NUM) * SRTT + ALPHA_NUM * R') // ALPHA_DEN.
ALPHA_NUM: int = 1
ALPHA_DEN: int = 8

# RFC 6298 §2.3 'β' weight for the RTTVAR EWMA.
# RTTVAR' = (1 - β) * RTTVAR + β * |SRTT - R'|  with β = 1/4.
BETA_NUM: int = 1
BETA_DEN: int = 4


@dataclass(frozen=True, slots=True)
class RtoState:
    """
    The RFC 6298 §2 RTO estimator state.

    'srtt_ms' and 'rttvar_ms' are 'None' on a fresh session before
    the first RTT sample arrives (the RFC says they are
    "uninitialized"). After the first sample they are non-negative
    integers in milliseconds. 'rto_ms' is always defined; it starts
    at 'INITIAL_RTO_MS' and is updated alongside SRTT / RTTVAR with
    every fresh sample, or doubled (capped at 'MAX_RTO_MS') on each
    retransmit timeout via 'back_off'.
    """

    srtt_ms: int | None
    rttvar_ms: int | None
    rto_ms: int


def initial_state() -> RtoState:
    """
    Construct the RTO state for a fresh session, before any RTT
    sample has been observed: SRTT and RTTVAR are 'None'
    (uninitialized per RFC 6298 §2), RTO defaults to
    'INITIAL_RTO_MS' (RFC 6298 §2.1).
    """

    return RtoState(srtt_ms=None, rttvar_ms=None, rto_ms=INITIAL_RTO_MS)


def update(state: RtoState, sample_ms: int) -> RtoState:
    """
    Fold an RTT sample 'sample_ms' into the RTO state per RFC 6298.

    First-sample case (SRTT is None, RFC 6298 §2.2):
        SRTT   = sample_ms
        RTTVAR = sample_ms // 2
        RTO    = SRTT + max(G, K * RTTVAR), clamped to [MIN, MAX]

    Subsequent-sample case (SRTT is not None, RFC 6298 §2.3):
        RTTVAR = (1 - β) * RTTVAR + β * |SRTT - sample_ms|
        SRTT   = (1 - α) * SRTT + α * sample_ms
        RTO    = SRTT + max(G, K * RTTVAR), clamped to [MIN, MAX]

    The caller is responsible for Karn's algorithm (RFC 6298 §3):
    samples derived from retransmitted segments MUST NOT be passed
    to this function.
    """

    if state.srtt_ms is None:
        # RFC 6298 §2.2 first-sample case.
        srtt = sample_ms
        rttvar = sample_ms // 2
    else:
        # RFC 6298 §2.3 subsequent-sample EWMA. SRTT and RTTVAR are
        # set together so 'rttvar_ms is not None' whenever SRTT is
        # not None; the assert is for mypy.
        assert state.rttvar_ms is not None
        rttvar = ((BETA_DEN - BETA_NUM) * state.rttvar_ms + BETA_NUM * abs(state.srtt_ms - sample_ms)) // BETA_DEN
        srtt = ((ALPHA_DEN - ALPHA_NUM) * state.srtt_ms + ALPHA_NUM * sample_ms) // ALPHA_DEN
    rto = srtt + max(CLOCK_GRANULARITY_MS, K * rttvar)
    return RtoState(srtt_ms=srtt, rttvar_ms=rttvar, rto_ms=clamp_rto(rto))


def back_off(state: RtoState) -> RtoState:
    """
    Apply the RFC 6298 §5.5 binary backoff on retransmit timeout:
        RTO = min(RTO * 2, MAX_RTO_MS)
    SRTT and RTTVAR are unchanged (Karn's algorithm: the estimator
    cannot be safely updated with a sample from a retransmitted
    segment, so the smoothed values remain stale until a fresh
    non-retransmitted sample arrives).
    """

    return RtoState(
        srtt_ms=state.srtt_ms,
        rttvar_ms=state.rttvar_ms,
        rto_ms=min(state.rto_ms * 2, MAX_RTO_MS),
    )


def clamp_rto(rto_ms: int) -> int:
    """
    Clamp an RTO value to the [MIN_RTO_MS, MAX_RTO_MS] bounds per
    RFC 6298 §2.4 / §2.5. Exposed for tests and direct callers
    that want to clamp a hand-computed RTO without going through
    'update' / 'back_off'.
    """

    return max(MIN_RTO_MS, min(rto_ms, MAX_RTO_MS))
