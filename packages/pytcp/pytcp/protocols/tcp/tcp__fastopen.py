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
This module contains the RFC 7413 Fast Open cookie generation
and validation helpers for the server-side TFO path.

pytcp/protocols/tcp/tcp__fastopen.py

ver 3.0.9
"""

import hmac

from net_addr import Ip4Address, Ip6Address
from pytcp import stack

# RFC 7413 §2 cookie length: PyTCP issues 8-byte cookies, the
# typical size used by Linux and BSD. The RFC allows 4..16
# bytes; 8 is the security-vs-overhead sweet spot.
TCP__FASTOPEN__COOKIE_LEN = 8


def generate_cookie(*, peer_address: Ip4Address | Ip6Address, secret: bytes) -> bytes:
    """
    Generate an opaque RFC 7413 §4.1 Fast Open cookie bound to
    the peer's IP address. The cookie is HMAC-SHA256 of the
    peer's address bytes keyed by the server-side secret,
    truncated to 'TCP__FASTOPEN__COOKIE_LEN' bytes. Truncation
    matches Linux and BSD practice and reduces wire overhead
    while keeping the cookie unforgeable without the secret.

    The cookie binds to the peer's IP only (not port); RFC
    7413 §4.1 leaves the exact derivation implementation-
    specific, but binding to peer-IP allows clients to use
    different ephemeral ports while preserving cookie cache
    hits on the server side.
    """

    assert secret, "The 'secret' argument must be a non-empty bytes value."

    digest = hmac.new(secret, bytes(peer_address), "sha256").digest()
    return digest[:TCP__FASTOPEN__COOKIE_LEN]


def validate_cookie(*, peer_address: Ip4Address | Ip6Address, secret: bytes, cookie: bytes) -> bool:
    """
    Validate a peer-presented Fast Open cookie. Returns True
    iff the cookie matches the value 'generate_cookie' would
    return for this peer with the current secret. Uses
    'hmac.compare_digest' for constant-time comparison so
    timing-side-channel attacks against the secret are
    bounded.
    """

    expected = generate_cookie(peer_address=peer_address, secret=secret)
    return hmac.compare_digest(expected, cookie)


def cache_cookie(*, peer_address: Ip4Address | Ip6Address, cookie: bytes) -> None:
    """
    Insert (or refresh) 'peer_address -> cookie' in the
    'stack.tcp_stack.fastopen_cookies' cache, applying RFC 7413
    §3.1 / §4.1.3 FIFO eviction when the cache would exceed
    'stack.TCP__FASTOPEN_CACHE_MAX_SIZE'. Refreshing an
    existing entry moves it to the most-recently-used end
    (Python 'dict' preserves insertion order; pop+reinsert
    moves the entry to the tail) so a peer that keeps
    reconnecting does not get spuriously evicted by
    activity from other peers.

    Eviction is FIFO over insertion order: the oldest
    entry is removed first. While 'dict' iteration order
    matches insertion order for this purpose, callers
    relying on stable eviction semantics across Python
    versions should treat the order as part of the
    documented contract.
    """

    stack.tcp_stack.cache_fastopen_cookie(
        peer=peer_address,
        cookie=cookie,
        max_size=stack.TCP__FASTOPEN_CACHE_MAX_SIZE,
    )
