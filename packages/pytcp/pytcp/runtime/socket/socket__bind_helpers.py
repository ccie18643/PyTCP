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
This module contains helper functions for IP-related operations.

pytcp/runtime/socket/socket__bind_helpers.py

ver 3.0.8
"""

import hashlib
import secrets
from typing import cast

from net_addr import (
    Ip4Address,
    Ip6Address,
    IpAddress,
    IpVersion,
)
from pytcp import stack
from pytcp.runtime.socket import AddressFamily, SocketType


def pick_local_ip_address[T: IpAddress](*, remote_ip_address: T) -> T:
    """
    Pick an appropriate source IP address based on the provided destination IP address.
    """

    match remote_ip_address.version:
        case IpVersion.IP6:
            assert isinstance(remote_ip_address, Ip6Address)
            return cast(
                T,
                pick_local_ip6_address(remote_ip6_address=remote_ip_address),
            )

        case IpVersion.IP4:
            assert isinstance(remote_ip_address, Ip4Address)
            return cast(
                T,
                pick_local_ip4_address(remote_ip4_address=remote_ip_address),
            )


def pick_local_ip6_address(
    *,
    remote_ip6_address: Ip6Address,
) -> Ip6Address:
    """
    Pick an appropriate source IPv6 address based on the provided destination IPv6 address.

    Selection policy: prefer the address of a local network the destination belongs to;
    otherwise consult the FIB — if a route covers the destination, use the route's
    preferred source when set, else the first configured host's address;
    otherwise return the unspecified address.
    """

    ip6_hosts = stack.local_ip6_hosts()

    for ip6_host in ip6_hosts:
        if remote_ip6_address in ip6_host.network:
            return ip6_host.address

    # Off-link: the next hop is the FIB's job, not a per-IfAddr
    # gateway. 'hasattr' guards reduced test contexts with no
    # Route plane bound (same pattern as the RA chokepoint).
    ip6_fib = stack.ip6_fib if hasattr(stack, "ip6_fib") else None
    if ip6_fib is not None:
        route = ip6_fib.lookup(
            remote_ip6_address,
            connected=stack.connected_ip6_networks(),
        )
        if route is not None:
            if route.prefsrc is not None:
                return route.prefsrc
            if ip6_hosts:
                return ip6_hosts[0].address

    return Ip6Address()


def pick_local_ip4_address(
    *,
    remote_ip4_address: Ip4Address,
) -> Ip4Address:
    """
    Pick an appropriate source IPv4 address based on the provided destination IPv4 address.

    Selection policy: prefer the address of a local network the destination belongs to;
    otherwise consult the FIB — if a route covers the destination, use the route's
    preferred source when set, else the first configured host's address;
    otherwise return the unspecified address.
    """

    ip4_hosts = stack.local_ip4_hosts()

    for ip4_host in ip4_hosts:
        if remote_ip4_address in ip4_host.network:
            return ip4_host.address

    # Off-link: the next hop is the FIB's job, not a per-IfAddr
    # gateway. 'hasattr' guards reduced test contexts with no
    # Route plane bound (same pattern as the RA chokepoint).
    ip4_fib = stack.ip4_fib if hasattr(stack, "ip4_fib") else None
    if ip4_fib is not None:
        route = ip4_fib.lookup(
            remote_ip4_address,
            connected=stack.connected_ip4_networks(),
        )
        if route is not None:
            if route.prefsrc is not None:
                return route.prefsrc
            if ip4_hosts:
                return ip4_hosts[0].address

    return Ip4Address()


def _ephemeral_port_pool() -> range:
    """
    Return the current ephemeral-port pool — a 'range' constructed
    fresh on every call from the sysctl-backed low/high bounds,
    so a boot-time or runtime override of
    'net.ephemeral_port_range.low' / '.high' takes effect on the
    next pick. Test fixtures patch this helper to control the
    candidate pool in unit tests.
    """

    return range(
        stack.STACK__EPHEMERAL_PORT_RANGE__LOW,
        stack.STACK__EPHEMERAL_PORT_RANGE__HIGH,
    )


def pick_local_port() -> int:
    """
    Pick an ephemeral local port from the
    '[STACK__EPHEMERAL_PORT_RANGE__LOW, STACK__EPHEMERAL_PORT_RANGE__HIGH)'
    interval, excluding any port currently held by an existing
    socket, using a CSPRNG-backed primitive ('secrets.choice') as
    the entropy source.

    Implements the RFC 6056 §3.3.1 "Simple Port Randomization"
    pattern with the §3.1 obfuscation SHOULD honoured: each pick
    is independent of every previous one, and the selection is
    unguessable to an off-path attacker. UDP uses this picker
    directly; TCP's connect()-time picker layers RFC 6056 §3.3.3
    Algorithm 3 (hash-based per-destination) on top via
    'pick_local_port_for'.
    """

    used = {socket.local_port for socket in stack.sockets.values()}
    available = [port for port in _ephemeral_port_pool() if port not in used]

    if not available:
        raise OSError("[Errno 98] Address already in use - [Unable to find free local ephemeral port]")

    return secrets.choice(available)


def pick_local_port_for(
    *,
    local_ip: Ip4Address | Ip6Address,
    remote_ip: Ip4Address | Ip6Address,
    remote_port: int,
) -> int:
    """
    Pick an ephemeral local port using RFC 6056 §3.3.3
    Algorithm 3: a BLAKE2s-keyed hash of (local_ip, remote_ip,
    remote_port) under the stack-wide 'TCP__PORT_SECRET' computes
    a starting offset into the
    '[STACK__EPHEMERAL_PORT_RANGE__LOW, STACK__EPHEMERAL_PORT_RANGE__HIGH)'
    interval; a linear scan from that offset returns the first
    port not currently held by an existing socket.

    Two RFC-relevant properties follow:

    - **§3.3.3 per-destination isolation.** Connecting to two
      different remote endpoints starts the scan at independent
      offsets, so an attacker observing the source port for one
      flow learns nothing about source ports for flows to other
      destinations.
    - **§3.4 secret-keyed.** The per-process
      'TCP__PORT_SECRET' (16 random bytes at module import)
      keys the hash so the offset table cannot be precomputed
      by an off-path attacker.

    Falls back to walking the full range on collision (the
    common case is the first slot being free, since the
    cryptographic hash spreads offsets uniformly).
    """

    digest = hashlib.blake2s(
        bytes(local_ip) + bytes(remote_ip) + remote_port.to_bytes(2, "big"),
        key=stack.TCP__PORT_SECRET,
        digest_size=4,
    ).digest()
    offset = int.from_bytes(digest, "big")

    pool = list(_ephemeral_port_pool())
    used = {socket.local_port for socket in stack.sockets.values()}
    pool_len = len(pool)

    for i in range(pool_len):
        port = pool[(offset + i) % pool_len]
        if port not in used:
            return port

    raise OSError("[Errno 98] Address already in use - [Unable to find free local ephemeral port]")


def is_address_in_use(
    *,
    local_ip_address: Ip6Address | Ip4Address,
    local_port: int,
    address_family: AddressFamily,
    socket_type: SocketType,
    dual_stack: bool = False,
    reuseport: bool = False,
    bound_ifindex: int | None = None,
) -> bool:
    """
    Check if the (family, type, IP, port) combination is already in use.

    Within the same family the canonical BSD overlap rules apply
    (unspecified-address binds shadow specifics on the same port).

    Cross-family conflicts arise for sockets bound to the wildcard
    address with 'IPV6_V6ONLY = 0' (Linux dual-stack mode):

      * An open AF_INET6 listener on '::' with 'V6ONLY = 0' reserves
        BOTH IPv4 and IPv6 namespaces on its port; a subsequent
        AF_INET bind on the same port is rejected with EADDRINUSE
        (matches Linux).
      * Symmetrically, a new AF_INET6 bind to '::' with 'V6ONLY = 0'
        ('dual_stack=True' here) conflicts with any pre-existing
        AF_INET listener on the same port.

    'V6ONLY = 1' sockets keep IPv4 and IPv6 in separate namespaces
    (the Python / Linux default). A 'V6ONLY = 0' listener bound to a
    specific (non-wildcard) IPv6 address does not cross-block — the
    dual-stack reservation only triggers when bound to '::'.

    'reuseport=True' (the binding socket carries SO_REUSEPORT) makes an
    otherwise-conflicting overlap permissible — but only when the
    overlapping open socket ALSO carries SO_REUSEPORT. This is Linux's
    all-or-nothing group rule (net/core/sock_reuseport.c): every socket
    bound to the same (ip, port) must opt into SO_REUSEPORT, so an
    overlap with even one non-REUSEPORT socket still reports the
    address in use.
    """

    for opened_socket in stack.sockets.values():
        if opened_socket.type is not socket_type:
            continue
        if opened_socket.local_port != local_port:
            continue

        # Same-family conflict — canonical BSD overlap rules.
        if opened_socket.family is address_family:
            overlaps = (
                opened_socket.local_ip_address.is_unspecified
                or opened_socket.local_ip_address == local_ip_address
                or local_ip_address.is_unspecified
            )
        else:
            # Cross-family conflict — only when one side is the IPv6
            # '::' wildcard with V6ONLY=0 (Linux dual-stack reservation).
            opened_is_dual_stack_ipv6_wildcard = (
                opened_socket.family is AddressFamily.INET6
                and not getattr(opened_socket, "_ipv6_v6only", True)
                and opened_socket.local_ip_address.is_unspecified
            )
            new_is_dual_stack_ipv6_wildcard = (
                address_family is AddressFamily.INET6 and dual_stack and local_ip_address.is_unspecified
            )
            overlaps = (address_family is AddressFamily.INET4 and opened_is_dual_stack_ipv6_wildcard) or (
                new_is_dual_stack_ipv6_wildcard and opened_socket.family is AddressFamily.INET4
            )

        if not overlaps:
            continue

        # SO_BINDTODEVICE: two sockets bound to the same (ip, port) but
        # pinned to DIFFERENT interfaces do not conflict — each only
        # serves traffic on its own device (Linux
        # net/ipv4/inet_connection_sock.c 'inet_bind_conflict' honors
        # 'sk_bound_dev_if'). This lets a per-interface DHCP client bind
        # 0.0.0.0:68 on every NIC of a multi-homed host. A device-bound
        # socket and an unbound one (which spans every interface) still
        # conflict, so the skip requires BOTH sides to be pinned.
        opened_ifindex = getattr(opened_socket, "_egress_ifindex", None)
        if bound_ifindex is not None and opened_ifindex is not None and bound_ifindex != opened_ifindex:
            continue

        # SO_REUSEPORT cohort: an overlap is permitted only when BOTH
        # the binding socket and this open socket opted in. Any overlap
        # with a non-REUSEPORT socket remains a conflict.
        if reuseport and getattr(opened_socket, "_so_reuseport", False):
            continue

        return True

    return False
