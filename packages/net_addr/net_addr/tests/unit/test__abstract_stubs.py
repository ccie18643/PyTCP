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
This module contains tests that exercise abstract stub bodies in the NetAddr
base classes so the 'NotImplementedError' fallback lines are covered.

net_addr/tests/unit/test__abstract_stubs.py

ver 3.0.10
"""

import inspect
from unittest import TestCase

from net_addr.address import Address
from net_addr.base import Base
from net_addr.errors import NetAddrError
from net_addr.ip4_address import Ip4Address
from net_addr.ip4_ifaddr import Ip4IfAddr
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip4_network import Ip4Network
from net_addr.ip4_wildcard import Ip4Wildcard
from net_addr.ip6_address import Ip6Address
from net_addr.ip6_ifaddr import Ip6IfAddr
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip6_network import Ip6Network
from net_addr.ip6_wildcard import Ip6Wildcard
from net_addr.ip_address import IpAddress
from net_addr.ip_ifaddr import IfAddr
from net_addr.ip_mask import IpMask
from net_addr.ip_network import IpNetwork
from net_addr.ip_version import IpVersion
from net_addr.ip_wildcard import IpWildcard
from net_addr.mac_address import MacAddress


class TestNetAddrBaseAbstractStubs(TestCase):
    """
    The NetAddr 'Base' abstract stub body tests.
    """

    def test__net_addr__base__str_stub_raises(self) -> None:
        """
        Ensure the abstract 'Base.__str__()' stub body raises 'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            Base.__str__(Ip4Address())

    def test__net_addr__base__eq_stub_raises(self) -> None:
        """
        Ensure the abstract 'Base.__eq__()' stub body raises 'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            Base.__eq__(Ip4Address(), Ip4Address())


class TestNetAddrAddressAbstractStubs(TestCase):
    """
    The NetAddr 'Address' abstract stub body tests.
    """

    def test__net_addr__address__buffer_stub_raises(self) -> None:
        """
        Ensure the abstract 'Address.__buffer__()' stub body raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            Address.__buffer__(Ip4Address(), 0)


class TestNetAddrIpAddressAbstractStubs(TestCase):
    """
    The NetAddr 'IpAddress' abstract property stub body tests.
    """

    def test__net_addr__ip_address__multicast_mac_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.multicast_mac' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.multicast_mac.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__reverse_pointer_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.reverse_pointer' stub
        raises 'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.reverse_pointer.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_loopback_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_loopback' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_loopback.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_global_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_global' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_global.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_private_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_private' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_private.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_link_local_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_link_local' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_link_local.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_multicast_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_multicast' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_multicast.fget(Ip4Address())  # type: ignore[attr-defined]


class TestNetAddrIpMaskAbstractStubs(TestCase):
    """
    The NetAddr 'IpMask' abstract stub body tests.
    """

    def test__net_addr__ip_mask__buffer_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpMask.__buffer__()' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpMask.__buffer__(Ip4Mask(), 0)


class TestNetAddrIpWildcardAbstractStubs(TestCase):
    """
    The NetAddr 'IpWildcard' abstract stub body tests.
    """

    def test__net_addr__ip_wildcard__buffer_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpWildcard.__buffer__()' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpWildcard.__buffer__(Ip4Wildcard(), 0)


class TestNetAddrIpNetworkAbstractStubs(TestCase):
    """
    The NetAddr 'IpNetwork' abstract property stub body tests.
    """

    def test__net_addr__ip_network__last_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpNetwork.last' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpNetwork.last.fget(Ip4Network())  # type: ignore[attr-defined]

    def test__net_addr__ip_network__hostmask_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpNetwork.hostmask' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpNetwork.hostmask.fget(Ip4Network())  # type: ignore[attr-defined]


class TestNetAddrIfAddrAbstractStubs(TestCase):
    """
    The NetAddr 'IfAddr' abstract stub body tests.
    """

    def test__net_addr__if_addr__init_stub_raises(self) -> None:
        """
        Ensure the abstract 'IfAddr.__init__()' stub body raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IfAddr.__init__(Ip4IfAddr("10.0.0.1/24"), "10.0.0.1/24")

    def test__net_addr__if_addr__not_directly_instantiable(self) -> None:
        """
        Ensure the abstract 'IfAddr' base cannot be instantiated
        directly, mirroring the 'Address' and 'IpNetwork' bases
        which both declare an abstract '__init__'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIn(
            "__init__",
            IfAddr.__abstractmethods__,
            msg="IfAddr.__init__ must be abstract so the base is not directly instantiable.",
        )
        with self.assertRaises(TypeError):
            IfAddr()  # type: ignore[abstract, call-arg]


class TestNetAddrIfAddrInitContract(TestCase):
    """
    The NetAddr 'IfAddr.__init__' base-contract tests.
    """

    def test__net_addr__if_addr__init_first_param_positional_only_host(self) -> None:
        """
        Ensure the abstract 'IfAddr.__init__' and the concrete
        Ip4IfAddr / Ip6IfAddr overrides all declare a
        positional-only first parameter named 'host', so the
        base contract stays in lockstep with the subclasses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for cls in (IfAddr, Ip4IfAddr, Ip6IfAddr):
            with self.subTest(cls=cls.__name__):
                params = list(inspect.signature(cls.__init__).parameters.values())
                first = params[1]
                self.assertEqual(
                    first.name,
                    "host",
                    msg=f"{cls.__name__}.__init__ first parameter must be named 'host'.",
                )
                self.assertIs(
                    first.kind,
                    inspect.Parameter.POSITIONAL_ONLY,
                    msg=f"{cls.__name__}.__init__ 'host' must be positional-only.",
                )


class TestNetAddrIpVersion(TestCase):
    """
    The NetAddr 'IpVersion' enum tests.
    """

    def test__net_addr__ip_version__values(self) -> None:
        """
        Ensure the 'IpVersion' enum exposes IP4 and IP6 members.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(IpVersion.IP4.value, 4)
        self.assertEqual(IpVersion.IP6.value, 6)

    def test__net_addr__ip_version__int_conversion(self) -> None:
        """
        Ensure 'int(IpVersion.x)' returns the underlying numeric value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(int(IpVersion.IP4), 4)
        self.assertEqual(int(IpVersion.IP6), 6)


class TestNetAddrSanityErrorDefault(TestCase):
    """
    The NetAddr value-type base '_sanity_error' default tests.
    """

    def test__net_addr__base_classes_default_sanity_error_to_netaddrerror(self) -> None:
        """
        Ensure every value-type base binds a '_sanity_error'
        defaulting to a NetAddrError subclass, so a subclass
        that omits the override still raises a NetAddrError —
        never a bare AttributeError — from '__format__' /
        '__getitem__' / 'subnets'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for base in (Address, IpNetwork, IfAddr):
            with self.subTest(base=base.__name__):
                self.assertTrue(
                    issubclass(base._sanity_error, NetAddrError),
                    msg=f"{base.__name__}._sanity_error must default to a NetAddrError subclass.",
                )


class TestNetAddrConcreteTypesFinal(TestCase):
    """
    The NetAddr concrete value-type '@final' contract tests.
    """

    def test__net_addr__concrete_value_types_are_final(self) -> None:
        """
        Ensure every concrete NetAddr value type is '@final'. The
        isinstance-based '__eq__' / '__hash__' contract on the
        value-type bases is symmetric only for leaf classes; a
        subclass would produce asymmetric equality and a
        diverging hash. Marking the leaves '@final' makes the
        leaf-only assumption enforced rather than implicit.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for cls in (
            Ip4Address,
            Ip6Address,
            MacAddress,
            Ip4Network,
            Ip6Network,
            Ip4Mask,
            Ip6Mask,
            Ip4Wildcard,
            Ip6Wildcard,
            Ip4IfAddr,
            Ip6IfAddr,
        ):
            with self.subTest(cls=cls.__name__):
                self.assertIs(
                    getattr(cls, "__final__", False),
                    True,
                    msg=f"{cls.__name__} must be decorated '@final'.",
                )


class TestNetAddrAddressLenConstant(TestCase):
    """
    The NetAddr 'Address._address_len' wire-width tests.
    """

    def test__net_addr__address_len_matches_buffer_width(self) -> None:
        """
        Ensure each concrete address type's '_address_len'
        class constant equals its real serialized width, so the
        allocation-free hot-path reads ('_with_offset',
        '__format__', 'max_prefixlen') stay consistent with
        'len(memoryview(self))'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for instance in (Ip4Address(), Ip6Address(), MacAddress()):
            with self.subTest(cls=type(instance).__name__):
                self.assertEqual(
                    type(instance)._address_len,
                    len(memoryview(instance)),
                    msg=(f"{type(instance).__name__}._address_len must equal " f"the serialized byte width."),
                )


class TestNetAddrIpNetworkInitContract(TestCase):
    """
    The NetAddr 'IpNetwork.__init__' base-contract tests.
    """

    def test__net_addr__ip_network__init_exposes_strict(self) -> None:
        """
        Ensure the abstract 'IpNetwork.__init__' and the concrete
        Ip4Network / Ip6Network overrides all declare a
        keyword-only 'strict' parameter defaulting to False, so
        the base contract stays in lockstep with the subclasses
        and code typed against the base can pass it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for cls in (IpNetwork, Ip4Network, Ip6Network):
            with self.subTest(cls=cls.__name__):
                param = inspect.signature(cls.__init__).parameters.get("strict")
                self.assertIsNotNone(
                    param,
                    msg=f"{cls.__name__}.__init__ must declare a 'strict' parameter.",
                )
                assert param is not None  # narrow for mypy
                self.assertIs(
                    param.kind,
                    inspect.Parameter.KEYWORD_ONLY,
                    msg=f"{cls.__name__}.__init__ 'strict' must be keyword-only.",
                )
                self.assertIs(
                    param.default,
                    False,
                    msg=f"{cls.__name__}.__init__ 'strict' must default to False.",
                )
