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
This module contains tests for the NetAddr package Click type adapters.

net_addr/tests/unit/test__click_types.py

ver 3.0.9
"""

from typing import assert_type, override
from unittest import TestCase

from click import BadParameter

from net_addr.click_types import (
    ClickTypeIfAddr,
    ClickTypeIp4Address,
    ClickTypeIp4IfAddr,
    ClickTypeIp4Network,
    ClickTypeIp6Address,
    ClickTypeIp6IfAddr,
    ClickTypeIp6Network,
    ClickTypeIpAddress,
    ClickTypeIpNetwork,
    ClickTypeMacAddress,
)
from net_addr.ip4_address import Ip4Address
from net_addr.ip4_ifaddr import Ip4IfAddr
from net_addr.ip4_network import Ip4Network
from net_addr.ip6_address import Ip6Address
from net_addr.ip6_ifaddr import Ip6IfAddr
from net_addr.ip6_network import Ip6Network
from net_addr.mac_address import MacAddress


class TestClickTypeMacAddress(TestCase):
    """
    The ClickTypeMacAddress Click parameter type tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeMacAddress()

    def test__click_types__mac_address__name(self) -> None:
        """
        Ensure the type name advertises the expected MAC-address format.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "xx:xx:xx:xx:xx:xx")

    def test__click_types__mac_address__valid(self) -> None:
        """
        Ensure a well-formed MAC address is parsed into a 'MacAddress'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("02:03:04:aa:bb:cc", None, None)

        self.assertIsInstance(result, MacAddress)
        self.assertEqual(str(result), "02:03:04:aa:bb:cc")

    def test__click_types__mac_address__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid MAC address raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("not-a-mac", None, None)

        self.assertIn("Invalid MAC address argument 'not-a-mac'", str(ctx.exception))


class TestClickTypeIpAddress(TestCase):
    """
    The ClickTypeIpAddress (IPv6 or IPv4) tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeIpAddress()

    def test__click_types__ip_address__name(self) -> None:
        """
        Ensure the type name advertises both IPv6 and IPv4 formats.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "x:x:x:x::x or x.x.x.x")

    def test__click_types__ip_address__valid_ip6(self) -> None:
        """
        Ensure a valid IPv6 address is parsed into an 'Ip6Address'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("2001:db8::1", None, None)

        self.assertIsInstance(result, Ip6Address)
        self.assertEqual(str(result), "2001:db8::1")

    def test__click_types__ip_address__valid_ip4_fallback(self) -> None:
        """
        Ensure a valid IPv4 address is parsed after the IPv6 attempt fails.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("192.0.2.1", None, None)

        self.assertIsInstance(result, Ip4Address)
        self.assertEqual(str(result), "192.0.2.1")

    def test__click_types__ip_address__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid IP address raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("not-an-address", None, None)

        self.assertIn("Invalid IP address argument 'not-an-address'", str(ctx.exception))


class TestClickTypeIp6Address(TestCase):
    """
    The ClickTypeIp6Address (IPv6 only) tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeIp6Address()

    def test__click_types__ip6_address__name(self) -> None:
        """
        Ensure the type name advertises the IPv6-only format.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "x:x:x:x::x")

    def test__click_types__ip6_address__valid(self) -> None:
        """
        Ensure a valid IPv6 address is parsed into an 'Ip6Address'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("fe80::1", None, None)

        self.assertIsInstance(result, Ip6Address)
        self.assertEqual(str(result), "fe80::1")

    def test__click_types__ip6_address__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid IPv6 address raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("192.0.2.1", None, None)

        self.assertIn("Invalid IPv6 address argument '192.0.2.1'", str(ctx.exception))


class TestClickTypeIp4Address(TestCase):
    """
    The ClickTypeIp4Address (IPv4 only) tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeIp4Address()

    def test__click_types__ip4_address__name(self) -> None:
        """
        Ensure the type name advertises the IPv4-only format.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "x.x.x.x")

    def test__click_types__ip4_address__valid(self) -> None:
        """
        Ensure a valid IPv4 address is parsed into an 'Ip4Address'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("10.0.0.1", None, None)

        self.assertIsInstance(result, Ip4Address)
        self.assertEqual(str(result), "10.0.0.1")

    def test__click_types__ip4_address__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid IPv4 address raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("2001:db8::1", None, None)

        self.assertIn("Invalid IPv4 address argument '2001:db8::1'", str(ctx.exception))


class TestClickTypeIpNetwork(TestCase):
    """
    The ClickTypeIpNetwork (IPv6 or IPv4) tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeIpNetwork()

    def test__click_types__ip_network__name(self) -> None:
        """
        Ensure the type name advertises both IPv6 and IPv4 network formats.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "x:x:x:x::x/n or x.x.x.x/n")

    def test__click_types__ip_network__valid_ip6(self) -> None:
        """
        Ensure a valid IPv6 network is parsed into an 'Ip6Network'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("2001:db8::/64", None, None)

        self.assertIsInstance(result, Ip6Network)
        self.assertEqual(str(result), "2001:db8::/64")

    def test__click_types__ip_network__valid_ip4_fallback(self) -> None:
        """
        Ensure a valid IPv4 network is parsed after the IPv6 attempt fails.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("10.0.0.0/8", None, None)

        self.assertIsInstance(result, Ip4Network)
        self.assertEqual(str(result), "10.0.0.0/8")

    def test__click_types__ip_network__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid IP network raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("not-a-network", None, None)

        self.assertIn("Invalid IP network argument 'not-a-network'", str(ctx.exception))


class TestClickTypeIp6Network(TestCase):
    """
    The ClickTypeIp6Network (IPv6 only) tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeIp6Network()

    def test__click_types__ip6_network__name(self) -> None:
        """
        Ensure the type name advertises the IPv6-only network format.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "x:x:x:x::x/n")

    def test__click_types__ip6_network__valid(self) -> None:
        """
        Ensure a valid IPv6 network is parsed into an 'Ip6Network'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("fe80::/64", None, None)

        self.assertIsInstance(result, Ip6Network)
        self.assertEqual(str(result), "fe80::/64")

    def test__click_types__ip6_network__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid IPv6 network raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("10.0.0.0/8", None, None)

        self.assertIn("Invalid IPv6 network argument '10.0.0.0/8'", str(ctx.exception))


class TestClickTypeIp4Network(TestCase):
    """
    The ClickTypeIp4Network (IPv4 only) tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeIp4Network()

    def test__click_types__ip4_network__name(self) -> None:
        """
        Ensure the type name advertises the IPv4-only network format.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "x.x.x.x/n")

    def test__click_types__ip4_network__valid(self) -> None:
        """
        Ensure a valid IPv4 network is parsed into an 'Ip4Network'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("192.0.2.0/24", None, None)

        self.assertIsInstance(result, Ip4Network)
        self.assertEqual(str(result), "192.0.2.0/24")

    def test__click_types__ip4_network__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid IPv4 network raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("2001:db8::/64", None, None)

        self.assertIn("Invalid IPv4 network argument '2001:db8::/64'", str(ctx.exception))


class TestClickTypeIpHost(TestCase):
    """
    The ClickTypeIfAddr (IPv6 or IPv4) tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeIfAddr()

    def test__click_types__ip_host__name(self) -> None:
        """
        Ensure the type name advertises both IPv6 and IPv4 host formats.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "x:x:x:x::x/n or x.x.x.x/n")

    def test__click_types__ip_host__valid_ip6(self) -> None:
        """
        Ensure a valid IPv6 host is parsed into an 'Ip6IfAddr'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("2001:db8::1/64", None, None)

        self.assertIsInstance(result, Ip6IfAddr)
        self.assertEqual(str(result), "2001:db8::1/64")

    def test__click_types__ip_host__valid_ip4_fallback(self) -> None:
        """
        Ensure a valid IPv4 host is parsed after the IPv6 attempt fails.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("192.0.2.1/24", None, None)

        self.assertIsInstance(result, Ip4IfAddr)
        self.assertEqual(str(result), "192.0.2.1/24")

    def test__click_types__ip_host__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid IP host raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("not-a-host", None, None)

        self.assertIn("Invalid IP host argument 'not-a-host'", str(ctx.exception))


class TestClickTypeIp6Host(TestCase):
    """
    The ClickTypeIp6IfAddr (IPv6 only) tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeIp6IfAddr()

    def test__click_types__ip6_host__name(self) -> None:
        """
        Ensure the type name advertises the IPv6-only host format.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "x:x:x:x::x/n")

    def test__click_types__ip6_host__valid(self) -> None:
        """
        Ensure a valid IPv6 host is parsed into an 'Ip6IfAddr'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("2001:db8::1/64", None, None)

        self.assertIsInstance(result, Ip6IfAddr)
        self.assertEqual(str(result), "2001:db8::1/64")

    def test__click_types__ip6_host__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid IPv6 host raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("192.0.2.1/24", None, None)

        self.assertIn("Invalid IPv6 host argument '192.0.2.1/24'", str(ctx.exception))


class TestClickTypeIp4Host(TestCase):
    """
    The ClickTypeIp4IfAddr (IPv4 only) tests.
    """

    @override
    def setUp(self) -> None:
        self._param = ClickTypeIp4IfAddr()

    def test__click_types__ip4_host__name(self) -> None:
        """
        Ensure the type name advertises the IPv4-only host format.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._param.name, "x.x.x.x/n")

    def test__click_types__ip4_host__valid(self) -> None:
        """
        Ensure a valid IPv4 host is parsed into an 'Ip4IfAddr'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._param.convert("192.0.2.1/24", None, None)

        self.assertIsInstance(result, Ip4IfAddr)
        self.assertEqual(str(result), "192.0.2.1/24")

    def test__click_types__ip4_host__invalid_raises_bad_parameter(self) -> None:
        """
        Ensure an invalid IPv4 host raises 'click.BadParameter'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BadParameter) as ctx:
            self._param.convert("2001:db8::1/64", None, None)

        self.assertIn("Invalid IPv4 host argument '2001:db8::1/64'", str(ctx.exception))


class TestClickTypeParameterisation(TestCase):
    """
    The NetAddr Click type generic-binding tests.
    """

    def test__click_types__param_type_binding(self) -> None:
        """
        Ensure each Click type binds ParamType to the concrete
        value type its convert() returns, so the generic is not
        left as an unparameterised Any. The assert_type calls are
        compile-time (mypy) assertions and runtime no-ops.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        assert_type(ClickTypeMacAddress().convert("02:00:00:00:00:01", None, None), MacAddress)
        assert_type(ClickTypeIp4Address().convert("10.0.0.1", None, None), Ip4Address)
        assert_type(ClickTypeIp6Address().convert("2001:db8::1", None, None), Ip6Address)
        assert_type(ClickTypeIp4Network().convert("10.0.0.0/24", None, None), Ip4Network)
        assert_type(ClickTypeIp6Network().convert("2001:db8::/64", None, None), Ip6Network)
        assert_type(ClickTypeIp4IfAddr().convert("10.0.0.1/24", None, None), Ip4IfAddr)
        assert_type(ClickTypeIp6IfAddr().convert("2001:db8::1/64", None, None), Ip6IfAddr)
        assert_type(
            ClickTypeIpAddress().convert("2001:db8::1", None, None),
            Ip6Address | Ip4Address,
        )
        assert_type(
            ClickTypeIpNetwork().convert("2001:db8::/64", None, None),
            Ip6Network | Ip4Network,
        )
        assert_type(
            ClickTypeIfAddr().convert("2001:db8::1/64", None, None),
            Ip6IfAddr | Ip4IfAddr,
        )
