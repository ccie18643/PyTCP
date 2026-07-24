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
This module contains the routing-control API ('RouteApi') — the
kernel/userspace boundary surface for the host-mode routing table.
The verbs ('add_route' / 'remove_route' / 'replace_default' /
'remove_default' / 'list_routes') are family-agnostic, inferring the
family from the route / destination / gateway value type (the Linux
'ip route' model, where the family is the 'rtm_family' field of one
'RTM_NEWROUTE' / 'RTM_DELROUTE' / 'RTM_GETROUTE' verb, not a separate
message). The Linux equivalents are 'ip route' and RTNETLINK.

pytcp/stack/route.py

ver 3.0.8
"""

from typing import cast

from net_addr import Ip4Address, Ip4Network, Ip6Address, Ip6Network
from pytcp.lib.logger import log
from pytcp.runtime.fib import Route, RouteProtocol, RouteScope, RouteTable
from pytcp.runtime.socket import AddressFamily

# The IPv4 / IPv6 default-route destinations (Linux 'default'
# in 'ip route'). Protocol-invariant — these are the
# all-addresses prefixes, not a tunable.
DEFAULT_IP4_NETWORK: Ip4Network = Ip4Network("0.0.0.0/0")
DEFAULT_IP6_NETWORK: Ip6Network = Ip6Network("::/0")


def install_boot_default_routes(
    *,
    ip4_fib: RouteTable[Ip4Address, Ip4Network],
    ip6_fib: RouteTable[Ip6Address, Ip6Network],
    ip4_gateway: Ip4Address | None,
    ip6_gateway: Ip6Address | None,
) -> None:
    """
    Install the static boot-config gateway (if any) as a
    'protocol=BOOT' default route in the FIB. This is the only
    boot-time default-route source; 'Ip{4,6}IfAddr.gateway' is
    no longer written (Phase 3 of
    'docs/refactor/routing_table_host_mode.md' dropped the
    Phase-1 dual-write — the FIB is now the single source of
    truth for the next hop). The DHCP / RA / autoconfig paths
    do NOT go through here; they learn the gateway at runtime
    and install it via 'RouteApi.replace_default_ip{4,6}'. A
    'None' gateway installs no default route (the DHCP /
    autoconfig case).
    """

    if ip4_gateway is not None:
        ip4_fib.add(
            route=Route(
                destination=DEFAULT_IP4_NETWORK,
                gateway=ip4_gateway,
                protocol=RouteProtocol.BOOT,
            )
        )
        __debug__ and log("stack", f"<lg>Route API</>: boot IPv4 default via {ip4_gateway}")

    if ip6_gateway is not None:
        ip6_fib.add(
            route=Route(
                destination=DEFAULT_IP6_NETWORK,
                gateway=ip6_gateway,
                protocol=RouteProtocol.BOOT,
            )
        )
        __debug__ and log("stack", f"<lg>Route API</>: boot IPv6 default via {ip6_gateway}")


class RouteApi:
    """
    Routing-control surface — mirrors Linux RTNETLINK 'RTM_*ROUTE'
    / 'ip route' semantics. The verbs are family-agnostic; the
    family is inferred from the route / destination / gateway value
    type (or, for 'remove_default' / 'list_routes', an explicit
    'family' field), exactly as the netlink family is a message
    field rather than a distinct verb.

    Implementation: a thin dispatch over the two per-address-family
    FIBs ('stack.ip4_fib' / 'stack.ip6_fib').

    Consumer code reads the route table ONLY through this
    surface; it never reaches into 'stack.ip4_fib' /
    'stack.ip6_fib' directly. This is the architectural seam the
    Phase-3 north-star turns into a real IPC channel — the
    wrapper internals swap from a direct in-process table to an
    RTNETLINK-equivalent message bus without any consumer change.
    """

    def __init__(
        self,
        *,
        ip4_fib: RouteTable[Ip4Address, Ip4Network],
        ip6_fib: RouteTable[Ip6Address, Ip6Network],
    ) -> None:
        """
        Bind the API to the stack's IPv4 / IPv6 FIBs. The FIBs
        own the route storage; the API is the only sanctioned
        consumer surface over them.
        """

        self._ip4_fib = ip4_fib
        self._ip6_fib = ip6_fib

    def list_routes(
        self,
        *,
        family: AddressFamily | None = None,
    ) -> tuple[Route[Ip4Address, Ip4Network] | Route[Ip6Address, Ip6Network], ...]:
        """
        Return a read-only copy-by-value snapshot of the routing
        table — Linux 'ip route show' equivalent. With no 'family'
        the snapshot covers both families (IPv4 first, then IPv6);
        pass 'AddressFamily.INET4' / 'INET6' to filter (the Linux
        'ip -4' / 'ip -6' selectors). The returned tuple is
        immutable (Phase-3 north-star "introspection is read-only").
        """

        routes: list[Route[Ip4Address, Ip4Network] | Route[Ip6Address, Ip6Network]] = []
        if family in (None, AddressFamily.INET4):
            routes.extend(self._ip4_fib.snapshot())
            routes.extend(self._connected_routes_ip4())
        if family in (None, AddressFamily.INET6):
            routes.extend(self._ip6_fib.snapshot())
            routes.extend(self._connected_routes_ip6())
        return tuple(routes)

    @staticmethod
    def _connected_routes_ip4() -> list[Route[Ip4Address, Ip4Network]]:
        """
        Synthesize the on-link IPv4 connected routes from each interface's
        assigned addresses — the 'proto kernel scope link' routes Linux
        auto-installs per address (one per (address, interface)), so the
        introspected table shows the on-link subnets the lookup path
        derives from the address list rather than from the FIB.
        """

        import pytcp.stack as _stack

        return [
            Route[Ip4Address, Ip4Network](
                destination=ifaddr.network,
                prefsrc=ifaddr.address,
                scope=RouteScope.LINK,
                protocol=RouteProtocol.KERNEL,
                oif=ifindex,
            )
            for ifindex, handler in _stack.interfaces.items()
            for ifaddr in handler.ip4_ifaddr
        ]

    @staticmethod
    def _connected_routes_ip6() -> list[Route[Ip6Address, Ip6Network]]:
        """
        Synthesize the on-link IPv6 connected routes from each interface's
        assigned addresses (link-local and global) — the IPv6 counterpart
        of '_connected_routes_ip4'.
        """

        import pytcp.stack as _stack

        return [
            Route[Ip6Address, Ip6Network](
                destination=ifaddr.network,
                prefsrc=ifaddr.address,
                scope=RouteScope.LINK,
                protocol=RouteProtocol.KERNEL,
                oif=ifindex,
            )
            for ifindex, handler in _stack.interfaces.items()
            for ifaddr in handler.ip6_ifaddr
        ]

    def add_route(
        self,
        *,
        route: Route[Ip4Address, Ip4Network] | Route[Ip6Address, Ip6Network],
    ) -> None:
        """
        Install an explicit route — Linux 'RTM_NEWROUTE' / 'ip route
        add' equivalent. The family is inferred from the route's
        destination prefix. Does not de-duplicate; the caller owns
        replace semantics (see 'replace_default').
        """

        # The destination prefix type discriminates the family;
        # mypy narrows the generic 'Route[A, N]' from the
        # 'route.destination' isinstance, so no cast is needed.
        if isinstance(route.destination, Ip6Network):
            self._ip6_fib.add(route=route)
            return
        self._ip4_fib.add(route=route)

    def remove_route(
        self,
        *,
        destination: Ip4Network | Ip6Network,
        gateway: Ip4Address | Ip6Address | None = None,
    ) -> int:
        """
        Remove every route to 'destination' (optionally
        gateway-qualified) — Linux 'RTM_DELROUTE' / 'ip route del'
        equivalent. The family is inferred from 'destination'.
        Returns the number of routes removed.
        """

        if isinstance(destination, Ip6Network):
            return self._ip6_fib.remove(destination=destination, gateway=cast("Ip6Address | None", gateway))
        return self._ip4_fib.remove(destination=destination, gateway=cast("Ip4Address | None", gateway))

    def replace_default(
        self,
        *,
        gateway: Ip4Address | Ip6Address,
        protocol: RouteProtocol,
        oif: int | None = None,
    ) -> None:
        """
        Atomically replace the default route for the gateway's
        family: remove any existing default, then install a single
        new one via 'gateway' with the given 'protocol'. Linux 'ip
        route replace default via ...' equivalent. 'oif' is the
        egress interface index the gateway is reachable on (the
        DHCP-leasing / RA-receiving interface); it is stamped onto
        the installed route so 'ip route'-style introspection can
        render the default's 'dev'. 'None' leaves it unset (the
        external-consumer / unknown-interface case).

        Remove-then-add (not the add-before-remove ordering of
        'AddressApi.replace'): two same-prefix default routes would
        create a lookup tiebreak ambiguity, whereas two interface
        addresses do not. The call is synchronous from the
        control-plane caller's view, so the transient no-default
        window is not observable to a concurrent lookup in practice.
        """

        if isinstance(gateway, Ip6Address):
            self._ip6_fib.remove(destination=DEFAULT_IP6_NETWORK)
            self._ip6_fib.add(
                route=Route(
                    destination=DEFAULT_IP6_NETWORK,
                    gateway=gateway,
                    protocol=protocol,
                    oif=oif,
                )
            )
            __debug__ and log("stack", f"<lg>Route API</>: IPv6 default via {gateway} ({protocol!r})")
            return
        self._ip4_fib.remove(destination=DEFAULT_IP4_NETWORK)
        self._ip4_fib.add(
            route=Route(
                destination=DEFAULT_IP4_NETWORK,
                gateway=gateway,
                protocol=protocol,
                oif=oif,
            )
        )
        __debug__ and log("stack", f"<lg>Route API</>: IPv4 default via {gateway} ({protocol!r})")

    def remove_default(self, *, family: AddressFamily) -> int:
        """
        Remove the default route of 'family', if any — the DHCP /
        static lease-loss (IPv4) and RA router-lifetime-expiry
        (IPv6) paths. Returns the number of routes removed (0 or,
        normally, 1). Linux 'ip route del default'.
        """

        if family is AddressFamily.INET6:
            return self._ip6_fib.remove(destination=DEFAULT_IP6_NETWORK)
        return self._ip4_fib.remove(destination=DEFAULT_IP4_NETWORK)
