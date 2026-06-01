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
This module contains the host-mode routing table (FIB) — the
per-address-family longest-prefix-match next-hop data structure
that replaces the single-gateway-per-IfAddr shortcut. The Linux
equivalents are 'ip route' / RTNETLINK 'RTM_NEWROUTE' and
'net/ipv4/fib_trie.c' / 'net/ipv6/route.c'.

pytcp/runtime/fib.py

ver 3.0.8
"""

import threading
from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum

from net_addr import Ip4Address, Ip4Network, Ip6Address, Ip6Network


class RouteScope(IntEnum):
    """
    Route scope — distance to the destination. Numeric values
    mirror the Linux 'rtnetlink.h' RT_SCOPE_* enumeration so the
    eventual RTNETLINK encoding (Phase 3) is a direct map and
    'ip route' parity is free.
    """

    UNIVERSE = 0  # global — reachable via a gateway
    SITE = 200  # interior IPv6 site (reserved; not behaviourally used)
    LINK = 253  # on-link — destination is directly connected
    HOST = 254  # local — the address is on this host
    NOWHERE = 255  # destination does not exist


class RouteProtocol(IntEnum):
    """
    Route origin — which subsystem installed the route. Numeric
    values mirror the Linux 'rtnetlink.h' RTPROT_* enumeration.
    """

    UNSPEC = 0
    REDIRECT = 1  # Phase 2: installed by an ICMP Redirect
    KERNEL = 2  # connected/direct route derived from an assigned address
    BOOT = 3  # installed from static boot configuration
    STATIC = 4  # installed by the operator (Route API)
    RA = 9  # learned from an IPv6 Router Advertisement
    DHCP = 16  # learned from a DHCP lease


@dataclass(frozen=True, kw_only=True, slots=True)
class Route[
    A: (Ip4Address, Ip6Address),
    N: (Ip4Network, Ip6Network),
]:
    """
    A single routing-table entry.
    """

    destination: N
    gateway: A | None = None
    prefsrc: A | None = None
    metric: int = 0
    scope: RouteScope = RouteScope.UNIVERSE
    protocol: RouteProtocol = RouteProtocol.STATIC
    # Output-interface index — the egress interface for traffic matching
    # this route (Linux 'rtnetlink.h' RTA_OIF). None when egress is
    # unresolved (e.g. an explicit default route whose oif is filled in
    # at synthesis time, or a route installed before multi-interface
    # egress selection). On a multi-homed host this is what binds a
    # destination to the interface that originates traffic toward it.
    oif: int | None = None

    # Phase 2: table id — only the Linux 'main' table (254)
    # exists in host mode; policy routing ('ip rule' / multiple
    # tables) is a router-grade concern.

    def __post_init__(self) -> None:
        """
        Ensure integrity of the Route fields.
        """

        assert self.metric >= 0, f"The 'metric' field must be non-negative. Got: {self.metric!r}"
        assert self.gateway is None or self.gateway.version == self.destination.version, (
            f"The 'gateway' address family must match the 'destination'. "
            f"Got: {self.gateway!r} vs {self.destination!r}"
        )
        assert self.prefsrc is None or self.prefsrc.version == self.destination.version, (
            f"The 'prefsrc' address family must match the 'destination'. "
            f"Got: {self.prefsrc!r} vs {self.destination!r}"
        )


class RouteTable[
    A: (Ip4Address, Ip6Address),
    N: (Ip4Network, Ip6Network),
]:
    """
    A single-address-family host-mode routing table.

    Holds only explicitly-installed routes (default + static).
    Connected (direct, on-link) routes are NOT stored — they are
    a view of the currently-assigned interface addresses and are
    synthesized per-lookup from the 'connected' networks the
    caller supplies. This removes any sync obligation (and the
    stale-route race) between the address plane and the FIB.

    Phase 2: a router-grade build adds an output-interface
    dimension and policy-routing tables; the destination-keyed
    'lookup' entry point is unchanged so the forwarding plane
    consumes it as-is.
    """

    def __init__(self) -> None:
        """
        Initialize an empty routing table.
        """

        self._routes: list[Route[A, N]] = []
        # The FIB is a global structure: the RX / TX / timer threads
        # read it ('lookup') while the Route API mutates it ('add' /
        # 'remove'). The lock makes each mutation atomic and hands every
        # reader a consistent snapshot of the route list, so a concurrent
        # in-place 'append' racing a comprehension rebind cannot drop an
        # update or tear a read on a free-threaded build — the same
        # tiny-locked-surface model as 'SocketTable' / 'InterfaceTable'.
        self._lock = threading.Lock()

    def add(self, *, route: Route[A, N]) -> None:
        """
        Install an explicit route. Linux 'RTM_NEWROUTE' /
        'ip route add' equivalent. Does not de-duplicate; the
        caller (the Route API) owns replace semantics.
        """

        with self._lock:
            self._routes.append(route)

    def remove(self, *, destination: N, gateway: A | None = None) -> int:
        """
        Remove every explicit route whose destination matches
        'destination' and — when 'gateway' is given — whose
        gateway also matches. Linux 'RTM_DELROUTE' /
        'ip route del' equivalent. Returns the number of routes
        removed.
        """

        with self._lock:
            before = len(self._routes)
            self._routes = [
                route
                for route in self._routes
                if not (route.destination == destination and (gateway is None or route.gateway == gateway))
            ]
            return before - len(self._routes)

    def remove_by_oif(self, *, oif: int) -> int:
        """
        Remove every explicit route whose output interface ('oif')
        matches 'oif' — the route-flush half of interface teardown
        (Linux 'RTM_DELLINK' / 'ip route flush dev <ifX>'). Returns the
        number of routes removed. Connected routes are synthesized
        per-lookup (not stored here), so they vanish on their own once
        the interface leaves the registry; this purges only the
        explicitly-installed default / static routes that egress the
        removed interface. Routes with an unset 'oif' never match.
        """

        with self._lock:
            before = len(self._routes)
            self._routes = [route for route in self._routes if route.oif != oif]
            return before - len(self._routes)

    def lookup(self, destination: A, /, *, connected: Iterable[tuple[N, int]]) -> Route[A, N] | None:
        """
        Resolve 'destination' to its next-hop route via
        longest-prefix match over the explicit routes plus the
        connected routes synthesized from 'connected'. Each
        'connected' entry is a '(network, oif)' pair — the directly
        connected network and the index of the interface that owns it
        — so the synthesized connected route carries its egress
        interface (the matched route's '.oif' identifies the egress
        for an on-link destination). Ties are broken by lowest metric,
        then by preferring a direct (no-gateway) route over a gatewayed
        one. Returns None when no candidate covers the destination
        ("no route to host").
        """

        # Snapshot the explicit routes under the lock, then match on the
        # local copy outside it — readers never block each other and the
        # heavy longest-prefix work holds no lock.
        with self._lock:
            candidates: list[Route[A, N]] = list(self._routes)
        for network, oif in connected:
            candidates.append(
                Route(
                    destination=network,
                    gateway=None,
                    prefsrc=None,
                    metric=0,
                    scope=RouteScope.LINK,
                    protocol=RouteProtocol.KERNEL,
                    oif=oif,
                )
            )

        matches = [route for route in candidates if destination in route.destination]
        if not matches:
            return None

        return max(
            matches,
            key=lambda route: (
                route.destination.prefixlen,
                -route.metric,
                route.gateway is None,
            ),
        )

    def snapshot(self) -> tuple[Route[A, N], ...]:
        """
        Return a read-only copy-by-value snapshot of the
        explicitly-installed routes. The 'Route' entries are
        frozen, so the caller cannot mutate table state through
        the returned tuple — matching the Phase-3 north-star
        "introspection is read-only" constraint.
        """

        with self._lock:
            return tuple(self._routes)
