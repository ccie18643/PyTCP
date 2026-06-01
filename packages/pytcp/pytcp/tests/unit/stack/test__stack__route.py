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
This module contains tests for the read-only Route API and the
Phase-1 boot default-route dual-write helper.

pytcp/tests/unit/stack/test__stack__route.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase

from net_addr import Ip4Address, Ip4Network, Ip6Address, Ip6Network
from pytcp.runtime.fib import Route, RouteProtocol, RouteTable
from pytcp.socket import AddressFamily
from pytcp.stack.route import RouteApi, install_boot_default_routes


class TestRouteApiRead(TestCase):
    """
    The read-only Route API introspection tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a RouteApi over fresh empty IPv4 / IPv6 FIBs.
        """

        self._ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        self._ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
        self._route_api = RouteApi(ip4_fib=self._ip4_fib, ip6_fib=self._ip6_fib)

    def test__stack__route__list_reflects_fib_contents(self) -> None:
        """
        Ensure 'list_routes' / 'list_routes' return the
        current FIB contents.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        r4 = Route(destination=Ip4Network("0.0.0.0/0"), gateway=Ip4Address("10.0.1.1"))
        r6 = Route(destination=Ip6Network("::/0"), gateway=Ip6Address("fe80::1"))
        self._ip4_fib.add(route=r4)
        self._ip6_fib.add(route=r6)

        self.assertEqual(
            self._route_api.list_routes(family=AddressFamily.INET4),
            (r4,),
            msg="list_routes must reflect the IPv4 FIB contents.",
        )
        self.assertEqual(
            self._route_api.list_routes(family=AddressFamily.INET6),
            (r6,),
            msg="list_routes must reflect the IPv6 FIB contents.",
        )

    def test__stack__route__list_is_copy_by_value(self) -> None:
        """
        Ensure the returned snapshot is an immutable tuple that
        does not observe a later FIB mutation (Phase-3 read-only
        introspection constraint).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snap_before = self._route_api.list_routes(family=AddressFamily.INET4)
        self._ip4_fib.add(route=Route(destination=Ip4Network("0.0.0.0/0")))

        self.assertIsInstance(
            snap_before,
            tuple,
            msg="list_routes must return an immutable tuple.",
        )
        self.assertEqual(
            snap_before,
            (),
            msg="A snapshot taken before a later add must not observe the add.",
        )
        self.assertEqual(
            len(self._route_api.list_routes(family=AddressFamily.INET4)),
            1,
            msg="A fresh snapshot must observe every added route.",
        )

    def test__stack__route__empty_fibs_yield_empty_tuples(self) -> None:
        """
        Ensure both list methods yield an empty tuple when the
        backing FIB is empty.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._route_api.list_routes(family=AddressFamily.INET4),
            (),
            msg="list_routes on an empty FIB must be ().",
        )
        self.assertEqual(
            self._route_api.list_routes(family=AddressFamily.INET6),
            (),
            msg="list_routes on an empty FIB must be ().",
        )


class TestInstallBootDefaultRoutes(TestCase):
    """
    The boot default-route install helper tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build fresh empty IPv4 / IPv6 FIBs for each case.
        """

        self._ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        self._ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()

    def test__stack__route__boot_ipv4_gateway_installs_default(self) -> None:
        """
        Ensure a static boot IPv4 gateway installs exactly one
        0.0.0.0/0 BOOT-protocol default route.

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        install_boot_default_routes(
            ip4_fib=self._ip4_fib,
            ip6_fib=self._ip6_fib,
            ip4_gateway=Ip4Address("10.0.1.1"),
            ip6_gateway=None,
        )

        self.assertEqual(
            self._ip4_fib.snapshot(),
            (
                Route(
                    destination=Ip4Network("0.0.0.0/0"),
                    gateway=Ip4Address("10.0.1.1"),
                    protocol=RouteProtocol.BOOT,
                ),
            ),
            msg="A boot IPv4 gateway must install one BOOT default route.",
        )
        self.assertEqual(
            self._ip6_fib.snapshot(),
            (),
            msg="No IPv6 gateway must leave the IPv6 FIB empty.",
        )

    def test__stack__route__boot_ipv6_gateway_installs_default(self) -> None:
        """
        Ensure a static boot IPv6 (link-local) gateway installs
        exactly one ::/0 BOOT-protocol default route.

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        install_boot_default_routes(
            ip4_fib=self._ip4_fib,
            ip6_fib=self._ip6_fib,
            ip4_gateway=None,
            ip6_gateway=Ip6Address("fe80::1"),
        )

        self.assertEqual(
            self._ip6_fib.snapshot(),
            (
                Route(
                    destination=Ip6Network("::/0"),
                    gateway=Ip6Address("fe80::1"),
                    protocol=RouteProtocol.BOOT,
                ),
            ),
            msg="A boot IPv6 gateway must install one BOOT default route.",
        )

    def test__stack__route__no_gateway_installs_nothing(self) -> None:
        """
        Ensure that with no gateway nothing is installed (the
        DHCP / autoconfig path — the gateway is learned and
        installed at runtime via the Route API instead).

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        install_boot_default_routes(
            ip4_fib=self._ip4_fib,
            ip6_fib=self._ip6_fib,
            ip4_gateway=None,
            ip6_gateway=None,
        )

        self.assertEqual(
            (self._ip4_fib.snapshot(), self._ip6_fib.snapshot()),
            ((), ()),
            msg="No gateway must install no default routes.",
        )

    def test__stack__route__dual_stack_installs_both(self) -> None:
        """
        Ensure a dual-stack static boot config installs one IPv4
        and one IPv6 BOOT default route.

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        install_boot_default_routes(
            ip4_fib=self._ip4_fib,
            ip6_fib=self._ip6_fib,
            ip4_gateway=Ip4Address("10.0.1.1"),
            ip6_gateway=Ip6Address("fe80::1"),
        )

        self.assertEqual(
            len(self._ip4_fib.snapshot()),
            1,
            msg="Dual-stack boot must install one IPv4 default route.",
        )
        self.assertEqual(
            len(self._ip6_fib.snapshot()),
            1,
            msg="Dual-stack boot must install one IPv6 default route.",
        )


class TestRouteApiMutation(TestCase):
    """
    The Phase-3 Route API mutation surface tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a RouteApi over fresh empty IPv4 / IPv6 FIBs.
        """

        self._ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        self._ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
        self._route_api = RouteApi(ip4_fib=self._ip4_fib, ip6_fib=self._ip6_fib)

    def test__stack__route__add_route_installs_into_fib(self) -> None:
        """
        Ensure 'add_route' / 'add_route' install the
        route into the backing FIB.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        r4 = Route(destination=Ip4Network("10.9.0.0/16"), gateway=Ip4Address("10.0.1.254"))
        r6 = Route(destination=Ip6Network("2001:db8:9::/48"), gateway=Ip6Address("fe80::9"))
        self._route_api.add_route(route=r4)
        self._route_api.add_route(route=r6)

        self.assertEqual(
            (self._ip4_fib.snapshot(), self._ip6_fib.snapshot()),
            ((r4,), (r6,)),
            msg="add_ip{4,6}_route must install the route into the FIB.",
        )

    def test__stack__route__remove_route_returns_count__ip4(self) -> None:
        """
        Ensure 'remove_route' deletes matching IPv4 routes and
        returns the removed count.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        net = Ip4Network("10.9.0.0/16")
        self._route_api.add_route(route=Route(destination=net, gateway=Ip4Address("10.0.1.1")))
        self._route_api.add_route(route=Route(destination=net, gateway=Ip4Address("10.0.1.2")))

        removed = self._route_api.remove_route(
            destination=net,
            gateway=Ip4Address("10.0.1.1"),
        )

        self.assertEqual(
            removed,
            1,
            msg="remove_route must return the number of routes removed.",
        )
        self.assertEqual(
            len(self._route_api.list_routes(family=AddressFamily.INET4)),
            1,
            msg="Only the gateway-matched route must be removed.",
        )

    def test__stack__route__remove_route_returns_count__ip6(self) -> None:
        """
        Ensure 'remove_route' deletes the matching IPv6
        route and returns the removed count.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        net = Ip6Network("2001:db8:9::/48")
        self._route_api.add_route(route=Route(destination=net, gateway=Ip6Address("fe80::9")))

        removed = self._route_api.remove_route(destination=net)

        self.assertEqual(
            removed,
            1,
            msg="remove_route must return the number of routes removed.",
        )
        self.assertEqual(
            self._route_api.list_routes(family=AddressFamily.INET6),
            (),
            msg="The IPv6 route must be gone after remove_route.",
        )

    def test__stack__route__replace_default_ipv4_swaps_atomically(self) -> None:
        """
        Ensure 'replace_default' removes any existing default
        route and installs exactly one new default route via the
        given gateway and protocol.

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        self._route_api.add_route(
            route=Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=Ip4Address("10.0.1.1"),
                protocol=RouteProtocol.BOOT,
            )
        )

        self._route_api.replace_default(
            gateway=Ip4Address("10.0.1.254"),
            protocol=RouteProtocol.DHCP,
        )

        self.assertEqual(
            self._route_api.list_routes(family=AddressFamily.INET4),
            (
                Route(
                    destination=Ip4Network("0.0.0.0/0"),
                    gateway=Ip4Address("10.0.1.254"),
                    protocol=RouteProtocol.DHCP,
                ),
            ),
            msg="replace_default must leave exactly the new default route.",
        )

    def test__stack__route__replace_default_ipv6_swaps_atomically(self) -> None:
        """
        Ensure 'replace_default' removes any existing ::/0
        route and installs exactly one new default route via the
        given (link-local) gateway and protocol.

        Reference: RFC 4861 §6.3.4 (default router selection).
        """

        self._route_api.add_route(
            route=Route(
                destination=Ip6Network("::/0"),
                gateway=Ip6Address("fe80::1"),
                protocol=RouteProtocol.BOOT,
            )
        )

        self._route_api.replace_default(
            gateway=Ip6Address("fe80::abcd"),
            protocol=RouteProtocol.RA,
        )

        self.assertEqual(
            self._route_api.list_routes(family=AddressFamily.INET6),
            (
                Route(
                    destination=Ip6Network("::/0"),
                    gateway=Ip6Address("fe80::abcd"),
                    protocol=RouteProtocol.RA,
                ),
            ),
            msg="replace_default must leave exactly the new default route.",
        )

    def test__stack__route__remove_default_clears_default_route(self) -> None:
        """
        Ensure 'remove_default' / 'remove_default' delete
        the default route and leave non-default routes intact
        (the DHCP / RA lease-loss path).

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        static = Route(
            destination=Ip4Network("10.9.0.0/16"),
            gateway=Ip4Address("10.0.1.254"),
            protocol=RouteProtocol.STATIC,
        )
        self._route_api.add_route(route=static)
        self._route_api.replace_default(
            gateway=Ip4Address("10.0.1.1"),
            protocol=RouteProtocol.DHCP,
        )
        self._route_api.replace_default(
            gateway=Ip6Address("fe80::1"),
            protocol=RouteProtocol.RA,
        )

        self._route_api.remove_default(family=AddressFamily.INET4)
        self._route_api.remove_default(family=AddressFamily.INET6)

        self.assertEqual(
            self._route_api.list_routes(family=AddressFamily.INET4),
            (static,),
            msg="remove_default must delete only the default route.",
        )
        self.assertEqual(
            self._route_api.list_routes(family=AddressFamily.INET6),
            (),
            msg="remove_default must delete the IPv6 default route.",
        )

    def test__stack__route__replace_default_preserves_non_default_routes(self) -> None:
        """
        Ensure 'replace_default' touches only the default
        route and leaves static non-default routes intact.

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        static = Route(
            destination=Ip4Network("10.9.0.0/16"),
            gateway=Ip4Address("10.0.1.254"),
            protocol=RouteProtocol.STATIC,
        )
        self._route_api.add_route(route=static)
        self._route_api.add_route(
            route=Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=Ip4Address("10.0.1.1"),
                protocol=RouteProtocol.BOOT,
            )
        )

        self._route_api.replace_default(
            gateway=Ip4Address("10.0.1.9"),
            protocol=RouteProtocol.DHCP,
        )

        self.assertIn(
            static,
            self._route_api.list_routes(family=AddressFamily.INET4),
            msg="A non-default static route must survive replace_default.",
        )
        self.assertEqual(
            len(self._route_api.list_routes(family=AddressFamily.INET4)),
            2,
            msg="replace_default must leave the static route + exactly one default.",
        )


class TestRouteControlTypesPublicSurface(TestCase):
    """
    The Route-control value types' Phase-3 public-surface tests.
    """

    def test__stack__route__control_types_reexported_from_stack(self) -> None:
        """
        Ensure the Route-control value types a consumer needs to use
        the Route API (Route, RouteProtocol, RouteScope) are importable
        from the sanctioned 'pytcp.stack' surface and are the same
        objects as the runtime definitions, so a consumer never has to
        reach into the implementation-detail 'pytcp.runtime.fib'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import pytcp.stack as stack_pkg
        from pytcp.runtime.fib import RouteScope as RuntimeRouteScope

        self.assertIs(
            stack_pkg.Route,
            Route,
            msg="pytcp.stack.Route must be the runtime Route type.",
        )
        self.assertIs(
            stack_pkg.RouteProtocol,
            RouteProtocol,
            msg="pytcp.stack.RouteProtocol must be the runtime RouteProtocol enum.",
        )
        self.assertIs(
            stack_pkg.RouteScope,
            RuntimeRouteScope,
            msg="pytcp.stack.RouteScope must be the runtime RouteScope enum.",
        )
