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
This module contains the RFC 6528 §3 Initial Sequence Number generator.

RFC 6528 §3 specifies a hash-based ISN to defend against blind sequence-
number prediction attacks (RFC 1948 / Bellovin 1996):

    ISN = M + F(localip, localport, remoteip, remoteport, secretkey)

where:
  - M is a 32-bit value driven by a monotonically increasing clock
    (typically one tick every 4 microseconds, wrapping the 32-bit
    space every ~4.77 hours).
  - F is a cryptographic pseudorandom function (PRF) seeded with a
    per-host secret. PyTCP uses SHA-256 truncated to 32 bits.
  - secretkey is a per-host high-entropy random value, typically
    16 bytes from 'secrets.token_bytes(16)'.

This replaces the naive 'random.randint(0, 0xFFFFFFFF)' ISS choice.
The naive choice is hard for a blind off-path attacker to predict
in absolute terms but offers no protection against an attacker who
can learn one ISS for the host-pair: subsequent ISS values for the
same pair are independently random and don't help, but the attacker
can already inject into ANY connection on that pair with a single
guess, since there's no binding to the 4-tuple. The hash form binds
ISS to the 4-tuple so an attacker who learns one ISN learns nothing
about ISNs for other peers, and the time-driven M component prevents
replay of stale ISNs against fresh connections.

RFC 9293 §3.4.3 Quiet Time:

    "When a TCP user issues an OPEN call, before any segments are
     issued, the TCP must wait at least 2*MSL ... for any prior
     incarnation's segments to drain."

    "Hosts that prefer to avoid waiting and are willing to risk
     possible confusion of old and new packets at a given
     destination MAY choose not to wait for the 'quiet time'."

PyTCP exercises the MAY-skip option: the literal MSL Quiet Time
wait on stack startup is omitted because the RFC 6528 hashed ISS
provides the equivalent collision-resistance guarantee. Same-4-
tuple ISS values at clocks differing by an MSL differ by
'MSL / ISS_CLOCK_RATE_US' ticks (= 7_500_000 for PyTCP's
TCP__TIME_WAIT__DELAY_MS = 30 s), so a delayed segment from a prior
incarnation cannot collide with a fresh ISN. Pinned by
'test__compute_iss__same_4tuple_post_msl_yields_different_iss'.

pytcp/protocols/tcp/tcp__iss.py

ver 3.0.10
"""

import hashlib

from net_addr import Ip4Address, Ip6Address

# RFC 6528 §3 'M' clock rate. The standard cadence is one tick every
# 4 microseconds, which makes M wrap the 32-bit space every
# (2**32 * 4) / 1e6 / 3600 ~= 4.77 hours. Faster rates leak less
# information about the clock; slower rates risk M wrap collisions
# during typical TIME-WAIT windows.
ISS_CLOCK_RATE_US: int = 4


def compute_iss(
    local_address: Ip4Address | Ip6Address,
    local_port: int,
    remote_address: Ip4Address | Ip6Address,
    remote_port: int,
    secret: bytes,
    *,
    clock_us: int = 0,
) -> int:
    """
    Compute the RFC 6528 §3 Initial Sequence Number.

    The result is deterministic for a fixed (4-tuple, secret,
    clock_us) and depends on every input: changing any address,
    port, secret byte, or the clock yields a different ISN.
    The output is a 32-bit unsigned integer.

    'clock_us' is the current monotonic clock in microseconds.
    Pass 0 for tests that want a fixed time-zero baseline; in
    production, pass 'time.monotonic_ns() // 1000' so the M
    component advances naturally.
    """

    # F = SHA-256(secret || local_addr || local_port || remote_addr ||
    # remote_port) truncated to 32 bits. Address bytes come from each
    # net_addr class's '__bytes__' (4 bytes for IPv4, 16 for IPv6);
    # ports are encoded big-endian on 2 bytes. The secret prefix is
    # the keying material per RFC 6528 §3 - distinct per host so an
    # attacker who reverse-engineers the algorithm still cannot
    # compute a victim's ISNs without knowing the secret.
    digest = hashlib.sha256(
        secret
        + bytes(local_address)
        + local_port.to_bytes(2, "big")
        + bytes(remote_address)
        + remote_port.to_bytes(2, "big")
    ).digest()
    f = int.from_bytes(digest[:4], "big")
    # M = clock_us / ISS_CLOCK_RATE_US (mod 2**32). The
    # monotonically advancing component prevents replay of stale
    # ISNs against fresh connections.
    m = (clock_us // ISS_CLOCK_RATE_US) & 0xFFFF_FFFF
    return (m + f) & 0xFFFF_FFFF
