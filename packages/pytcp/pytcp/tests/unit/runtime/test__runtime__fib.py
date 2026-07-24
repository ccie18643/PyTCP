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
This module contains tests for the host-mode routing table (FIB).

pytcp/tests/unit/runtime/test__runtime__fib.py

ver 3.0.8
"""

import dataclasses
import threading
from typing import override
from unittest import TestCase

from net_addr import Ip4Address, Ip4Network, Ip6Address, Ip6Network
from pytcp.runtime.fib import (
    Route,
    RouteProtocol,
    RouteScope,
    RouteTable,
)
from pytcp.tests.lib.parameterized import parameterized_class

# IPv4 fixture topology used by the lookup matrix:
#   default 0.0.0.0/0      via 10.0.1.1   (protocol BOOT)
#   static  10.9.0.0/16    via 10.0.1.254 (protocol STATIC)
#   connected 10.0.1.0/24  (derived from an assigned address; no gateway)
_DEFAULT4_NET = Ip4Network("0.0.0.0/0")
_CONNECTED4_NET = Ip4Network("10.0.1.0/24")
_STATIC4_NET = Ip4Network("10.9.0.0/16")
_GW_DEFAULT4 = Ip4Address("10.0.1.1")
_GW_STATIC4 = Ip4Address("10.0.1.254")

_DEFAULT4_ROUTE = Route(
    destination=_DEFAULT4_NET,
    gateway=_GW_DEFAULT4,
    protocol=RouteProtocol.BOOT,
)
_STATIC4_ROUTE = Route(
    destination=_STATIC4_NET,
    gateway=_GW_STATIC4,
    protocol=RouteProtocol.STATIC,
)

# The canonical synthesized connected route the table derives for
# '_CONNECTED4_NET' — scope LINK, no gateway, protocol KERNEL,
# default metric, no prefsrc. Deterministic synthesis means a
# whole-object equality assertion is sound.
# The owning interface index the connected network is tagged with;
# 'lookup' stamps it onto the synthesized connected route's 'oif'.
_CONNECTED4_OIF = 1
_CONNECTED4_ROUTE = Route(
    destination=_CONNECTED4_NET,
    gateway=None,
    prefsrc=None,
    metric=0,
    scope=RouteScope.LINK,
    protocol=RouteProtocol.KERNEL,
    oif=_CONNECTED4_OIF,
)


@parameterized_class(
    [
        {
            "_description": "On-link destination resolves to the derived "
            "connected route, not the default route (longest-prefix wins).",
            "_table_routes": [_DEFAULT4_ROUTE, _STATIC4_ROUTE],
            "_connected": [(_CONNECTED4_NET, _CONNECTED4_OIF)],
            "_query": Ip4Address("10.0.1.50"),
            "_expected": _CONNECTED4_ROUTE,
        },
        {
            "_description": "Destination inside a static /16 resolves to the " "static route, beating the /0 default.",
            "_table_routes": [_DEFAULT4_ROUTE, _STATIC4_ROUTE],
            "_connected": [(_CONNECTED4_NET, _CONNECTED4_OIF)],
            "_query": Ip4Address("10.9.1.1"),
            "_expected": _STATIC4_ROUTE,
        },
        {
            "_description": "Destination matching only the default route " "resolves to the default route.",
            "_table_routes": [_DEFAULT4_ROUTE, _STATIC4_ROUTE],
            "_connected": [(_CONNECTED4_NET, _CONNECTED4_OIF)],
            "_query": Ip4Address("8.8.8.8"),
            "_expected": _DEFAULT4_ROUTE,
        },
        {
            "_description": "Default route alone matches any destination when " "no connected route exists.",
            "_table_routes": [_DEFAULT4_ROUTE],
            "_connected": [],
            "_query": Ip4Address("203.0.113.7"),
            "_expected": _DEFAULT4_ROUTE,
        },
        {
            "_description": "No route and no connected network yields no " "match (no route to host).",
            "_table_routes": [],
            "_connected": [],
            "_query": Ip4Address("8.8.8.8"),
            "_expected": None,
        },
        {
            "_description": "Connected route alone matches an in-subnet " "destination with no gateway.",
            "_table_routes": [],
            "_connected": [(_CONNECTED4_NET, _CONNECTED4_OIF)],
            "_query": Ip4Address("10.0.1.9"),
            "_expected": _CONNECTED4_ROUTE,
        },
        {
            "_description": "Connected route alone does not match an " "out-of-subnet destination.",
            "_table_routes": [],
            "_connected": [(_CONNECTED4_NET, _CONNECTED4_OIF)],
            "_query": Ip4Address("10.0.2.9"),
            "_expected": None,
        },
    ]
)
class TestRouteTableLookupIp4(TestCase):
    """
    The host-mode FIB IPv4 longest-prefix lookup tests.
    """

    _description: str
    _table_routes: list[Route[Ip4Address, Ip4Network]]
    _connected: list[tuple[Ip4Network, int]]
    _query: Ip4Address
    _expected: Route[Ip4Address, Ip4Network] | None

    @override
    def setUp(self) -> None:
        """
        Build a fresh IPv4 'RouteTable' populated with the case's
        explicit routes.
        """

        self._table: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        for route in self._table_routes:
            self._table.add(route=route)

    def test__runtime__fib__lookup(self) -> None:
        """
        Ensure 'RouteTable.lookup' returns the longest-prefix
        route among the explicit and derived-connected
        candidates, or None when no candidate covers the
        destination.

        Reference: RFC 1122 §3.3.1 (next-hop selection / longest-prefix match).
        """

        result = self._table.lookup(self._query, connected=self._connected)

        self.assertEqual(
            result,
            self._expected,
            msg=f"Unexpected route for case: {self._description}",
        )


class TestRouteTableLookupTiebreaks(TestCase):
    """
    The host-mode FIB lookup tiebreak tests.
    """

    def test__runtime__fib__lookup__metric_tiebreak(self) -> None:
        """
        Ensure that among equal-prefix routes the lower metric
        wins.

        Reference: RFC 1122 §3.3.1 (next-hop selection / metric preference).
        """

        table: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        high = Route(
            destination=Ip4Network("0.0.0.0/0"),
            gateway=Ip4Address("10.0.1.2"),
            metric=100,
        )
        low = Route(
            destination=Ip4Network("0.0.0.0/0"),
            gateway=Ip4Address("10.0.1.1"),
            metric=10,
        )
        table.add(route=high)
        table.add(route=low)

        result = table.lookup(Ip4Address("8.8.8.8"), connected=[])

        self.assertEqual(
            result,
            low,
            msg="Lower-metric route must win on an equal-prefix tie.",
        )

    def test__runtime__fib__lookup__connected_beats_gatewayed(self) -> None:
        """
        Ensure that at an equal prefix the derived connected
        (on-link, no-gateway) route is preferred over an
        explicit gatewayed route.

        Reference: RFC 1122 §3.3.1 (next-hop selection / direct over indirect).
        """

        table: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        gatewayed = Route(
            destination=Ip4Network("10.0.1.0/24"),
            gateway=Ip4Address("10.0.1.254"),
        )
        table.add(route=gatewayed)

        result = table.lookup(
            Ip4Address("10.0.1.50"),
            connected=[(Ip4Network("10.0.1.0/24"), 1)],
        )

        self.assertIsNone(
            None if result is None else result.gateway,
            msg="Connected on-link route (gateway None) must win the equal-prefix tie.",
        )
        self.assertEqual(
            None if result is None else result.scope,
            RouteScope.LINK,
            msg="The winning equal-prefix route must be the connected (scope LINK) one.",
        )


class TestRouteTableLookupIp6(TestCase):
    """
    The host-mode FIB IPv6 lookup tests.
    """

    def test__runtime__fib__lookup__ip6_on_link_beats_default(self) -> None:
        """
        Ensure an in-subnet IPv6 destination resolves to the
        derived connected route rather than the ::/0 default,
        including when the default's gateway is link-local.

        Reference: RFC 1122 §3.3.1 (next-hop selection / longest-prefix match).
        """

        table: RouteTable[Ip6Address, Ip6Network] = RouteTable()
        table.add(
            route=Route(
                destination=Ip6Network("::/0"),
                gateway=Ip6Address("fe80::1"),
                protocol=RouteProtocol.RA,
            )
        )

        on_link = table.lookup(
            Ip6Address("2001:db8:0:1::50"),
            connected=[(Ip6Network("2001:db8:0:1::/64"), 1)],
        )
        off_link = table.lookup(
            Ip6Address("2606:4700:4700::1111"),
            connected=[(Ip6Network("2001:db8:0:1::/64"), 1)],
        )

        self.assertEqual(
            None if on_link is None else on_link.destination,
            Ip6Network("2001:db8:0:1::/64"),
            msg="In-subnet IPv6 destination must resolve to the connected route.",
        )
        self.assertEqual(
            None if off_link is None else off_link.gateway,
            Ip6Address("fe80::1"),
            msg="Off-link IPv6 destination must resolve via the default route's link-local gateway.",
        )


class TestRouteTableMutation(TestCase):
    """
    The host-mode FIB add / remove / snapshot tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh IPv4 'RouteTable'.
        """

        self._table: RouteTable[Ip4Address, Ip4Network] = RouteTable()

    def test__runtime__fib__snapshot_is_copy_by_value(self) -> None:
        """
        Ensure 'RouteTable.snapshot' returns an immutable tuple
        whose contents do not change when the table is mutated
        afterwards.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._table.add(route=_DEFAULT4_ROUTE)
        snap_before = self._table.snapshot()
        self._table.add(route=_STATIC4_ROUTE)

        self.assertIsInstance(
            snap_before,
            tuple,
            msg="snapshot must return a tuple (copy-by-value, immutable).",
        )
        self.assertEqual(
            snap_before,
            (_DEFAULT4_ROUTE,),
            msg="A snapshot taken before a later add must not observe the add.",
        )
        self.assertEqual(
            len(self._table.snapshot()),
            2,
            msg="A fresh snapshot must observe every added route.",
        )

    def test__runtime__fib__remove_by_destination_only(self) -> None:
        """
        Ensure 'remove' with no gateway deletes every route to
        the destination and returns the removed count.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._table.add(route=Route(destination=_DEFAULT4_NET, gateway=Ip4Address("10.0.1.1")))
        self._table.add(route=Route(destination=_DEFAULT4_NET, gateway=Ip4Address("10.0.1.2")))

        removed = self._table.remove(destination=_DEFAULT4_NET)

        self.assertEqual(
            removed,
            2,
            msg="remove(destination=...) must delete all routes to that destination.",
        )
        self.assertEqual(
            self._table.snapshot(),
            (),
            msg="The table must be empty after removing the only destination's routes.",
        )

    def test__runtime__fib__remove_by_destination_and_gateway(self) -> None:
        """
        Ensure 'remove' with a gateway deletes only the route
        matching both destination and gateway.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        keep = Route(destination=_DEFAULT4_NET, gateway=Ip4Address("10.0.1.2"))
        self._table.add(route=Route(destination=_DEFAULT4_NET, gateway=Ip4Address("10.0.1.1")))
        self._table.add(route=keep)

        removed = self._table.remove(
            destination=_DEFAULT4_NET,
            gateway=Ip4Address("10.0.1.1"),
        )

        self.assertEqual(
            removed,
            1,
            msg="remove(destination=, gateway=) must delete exactly the matching route.",
        )
        self.assertEqual(
            self._table.snapshot(),
            (keep,),
            msg="The non-matching route must survive a gateway-qualified remove.",
        )

    def test__runtime__fib__remove_no_match_returns_zero(self) -> None:
        """
        Ensure 'remove' returns zero and leaves the table
        untouched when nothing matches.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._table.add(route=_DEFAULT4_ROUTE)

        removed = self._table.remove(destination=Ip4Network("10.9.0.0/16"))

        self.assertEqual(
            removed,
            0,
            msg="remove must return 0 when no route matches.",
        )
        self.assertEqual(
            self._table.snapshot(),
            (_DEFAULT4_ROUTE,),
            msg="A no-match remove must leave the table untouched.",
        )

    def test__runtime__fib__remove_by_oif_purges_matching(self) -> None:
        """
        Ensure 'remove_by_oif' deletes every explicit route whose
        output interface matches and returns the removed count — the
        route-flush half of interface teardown (RTM_DELLINK).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        keep = Route(destination=_STATIC4_NET, gateway=_GW_STATIC4, oif=2)
        self._table.add(route=Route(destination=_DEFAULT4_NET, gateway=_GW_DEFAULT4, oif=1))
        self._table.add(route=Route(destination=Ip4Network("10.8.0.0/16"), gateway=_GW_DEFAULT4, oif=1))
        self._table.add(route=keep)

        removed = self._table.remove_by_oif(oif=1)

        self.assertEqual(
            removed,
            2,
            msg="remove_by_oif must delete every route egressing the given interface.",
        )
        self.assertEqual(
            self._table.snapshot(),
            (keep,),
            msg="A route egressing a different interface must survive remove_by_oif.",
        )

    def test__runtime__fib__remove_by_oif_no_match_returns_zero(self) -> None:
        """
        Ensure 'remove_by_oif' returns zero and leaves the table
        untouched when no explicit route egresses the interface —
        including routes whose 'oif' is unset (gatewayed default).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._table.add(route=_DEFAULT4_ROUTE)

        removed = self._table.remove_by_oif(oif=7)

        self.assertEqual(
            removed,
            0,
            msg="remove_by_oif must return 0 when no route egresses the interface.",
        )
        self.assertEqual(
            self._table.snapshot(),
            (_DEFAULT4_ROUTE,),
            msg="A no-match remove_by_oif must leave the table untouched.",
        )


class TestRouteInvariants(TestCase):
    """
    The Route dataclass invariant tests.
    """

    def test__runtime__fib__route__valid_construction(self) -> None:
        """
        Ensure a well-formed Route exposes its fields and applies
        the documented defaults.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        route = Route(
            destination=Ip4Network("10.0.1.0/24"),
            gateway=Ip4Address("10.0.1.1"),
        )

        self.assertEqual(
            route.destination,
            Ip4Network("10.0.1.0/24"),
            msg="Route must expose the 'destination' field.",
        )
        self.assertEqual(
            route.metric,
            0,
            msg="Route 'metric' must default to 0.",
        )
        self.assertIs(
            route.scope,
            RouteScope.UNIVERSE,
            msg="Route 'scope' must default to UNIVERSE (global).",
        )
        self.assertIs(
            route.protocol,
            RouteProtocol.STATIC,
            msg="Route 'protocol' must default to STATIC.",
        )

    def test__runtime__fib__route__oif_defaults_none_and_round_trips(self) -> None:
        """
        Ensure the Route 'oif' (output interface index) field defaults
        to None and round-trips an explicit ifindex — the per-route
        egress-interface dimension a multi-homed host selects on.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        default_route = Route(destination=Ip4Network("0.0.0.0/0"))
        self.assertIsNone(
            default_route.oif,
            msg="Route 'oif' must default to None (egress unresolved).",
        )

        tagged_route = Route(destination=Ip4Network("10.0.1.0/24"), oif=2)
        self.assertEqual(
            tagged_route.oif,
            2,
            msg="Route must expose the explicit 'oif' egress-interface index.",
        )

    def test__runtime__fib__route__is_frozen(self) -> None:
        """
        Ensure Route is an immutable (frozen) value object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        route = Route(destination=Ip4Network("0.0.0.0/0"))

        with self.assertRaises(dataclasses.FrozenInstanceError):
            route.metric = 5  # type: ignore[misc]

    def test__runtime__fib__route__negative_metric_rejected(self) -> None:
        """
        Ensure a negative metric is rejected at construction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Route(destination=Ip4Network("0.0.0.0/0"), metric=-1)

    def test__runtime__fib__route__gateway_version_mismatch_rejected(self) -> None:
        """
        Ensure a gateway whose address family differs from the
        destination is rejected at construction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=Ip6Address("fe80::1"),
            )

    def test__runtime__fib__route__prefsrc_version_mismatch_rejected(self) -> None:
        """
        Ensure a preferred source whose address family differs
        from the destination is rejected at construction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Route(
                destination=Ip6Network("::/0"),
                prefsrc=Ip4Address("10.0.1.1"),
            )


class TestRouteEnums(TestCase):
    """
    The RouteScope / RouteProtocol Linux-parity tests.
    """

    def test__runtime__fib__route_scope_linux_values(self) -> None:
        """
        Ensure RouteScope members carry the Linux rtnetlink.h
        RT_SCOPE_* numeric values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for member, value in (
            (RouteScope.UNIVERSE, 0),
            (RouteScope.SITE, 200),
            (RouteScope.LINK, 253),
            (RouteScope.HOST, 254),
            (RouteScope.NOWHERE, 255),
        ):
            with self.subTest(member=member):
                self.assertEqual(
                    int(member),
                    value,
                    msg=f"{member!r} must mirror the Linux RT_SCOPE_* value.",
                )

    def test__runtime__fib__route_protocol_linux_values(self) -> None:
        """
        Ensure RouteProtocol members carry the Linux rtnetlink.h
        RTPROT_* numeric values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for member, value in (
            (RouteProtocol.UNSPEC, 0),
            (RouteProtocol.REDIRECT, 1),
            (RouteProtocol.KERNEL, 2),
            (RouteProtocol.BOOT, 3),
            (RouteProtocol.STATIC, 4),
            (RouteProtocol.RA, 9),
            (RouteProtocol.DHCP, 16),
        ):
            with self.subTest(member=member):
                self.assertEqual(
                    int(member),
                    value,
                    msg=f"{member!r} must mirror the Linux RTPROT_* value.",
                )


class TestRouteTableConcurrency(TestCase):
    """
    The 'RouteTable' thread-safety tests — the FIB is a global structure
    read by the RX / TX / timer threads ('lookup') while the Route API
    mutates it ('add' / 'remove'), so its lock must make concurrent
    mutation safe (no lost route, no torn read) on a free-threaded build
    where a bare list's in-place 'append' racing a comprehension rebind
    would otherwise drop updates.
    """

    def test__runtime__fib__concurrent_add_loses_no_route(self) -> None:
        """
        Ensure many threads each adding a distinct route end with every
        route registered — the lock serializes 'append' so a concurrent
        mutation cannot drop an add, the daemon-critical property a bare
        list does not guarantee on a free-threaded build.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        routes = [Route(destination=Ip4Network(f"10.{i}.0.0/16"), oif=i + 1) for i in range(64)]
        errors: list[BaseException] = []

        def add_one(route: Route[Ip4Address, Ip4Network]) -> None:
            try:
                table.add(route=route)
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)

        threads = [threading.Thread(target=add_one, args=(route,)) for route in routes]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [], msg=f"Concurrent add must not raise; got: {errors!r}")
        self.assertEqual(
            set(table.snapshot()),
            set(routes),
            msg="Every concurrently-added route must survive (none lost to a racing mutation).",
        )

    def test__runtime__fib__concurrent_lookup_during_mutation_does_not_raise(self) -> None:
        """
        Ensure a 'lookup' running while the table is concurrently
        mutated never raises — the lock hands the reader a consistent
        snapshot of the route list rather than letting it iterate a list
        being resized.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        errors: list[BaseException] = []
        stop = threading.Event()

        def churn() -> None:
            i = 0
            while not stop.is_set():
                try:
                    table.add(route=Route(destination=Ip4Network(f"10.{i % 256}.0.0/16"), oif=1))
                    table.remove_by_oif(oif=1)
                    i += 1
                except BaseException as exc:  # pylint: disable=broad-exception-caught
                    errors.append(exc)
                    return

        def reader() -> None:
            for _ in range(2000):
                try:
                    table.lookup(Ip4Address("10.1.2.3"), connected=())
                except BaseException as exc:  # pylint: disable=broad-exception-caught
                    errors.append(exc)
                    return

        churner = threading.Thread(target=churn)
        readers = [threading.Thread(target=reader) for _ in range(4)]
        churner.start()
        for thread in readers:
            thread.start()
        for thread in readers:
            thread.join()
        stop.set()
        churner.join()

        self.assertEqual(errors, [], msg=f"Concurrent lookup during mutation must not raise; got: {errors!r}")
