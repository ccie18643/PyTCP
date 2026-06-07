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
This module contains tests for the NetAddr package IPv4 network support class.

net_addr/tests/unit/test__ip4_network.py

ver 3.0.8
"""

from collections.abc import Callable
from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip4IfAddr,
    Ip4Mask,
    Ip4MaskFormatError,
    Ip4Network,
    Ip4NetworkFormatError,
    Ip4NetworkSanityError,
    Ip4Wildcard,
    Ip6Address,
    Ip6IfAddr,
    Ip6Network,
    IpNetwork,
    IpNetworkSanityError,
    IpVersion,
)


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 network: 0.0.0.0/0 (None)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0/0",
                "__repr__": "Ip4Network('0.0.0.0/0')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address(),
                "mask": Ip4Mask(),
                "last": Ip4Address("255.255.255.255"),
                "broadcast": Ip4Address("255.255.255.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 0.0.0.0/0 (str)",
            "_args": [
                "0.0.0.0/0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0/0",
                "__repr__": "Ip4Network('0.0.0.0/0')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address(),
                "mask": Ip4Mask(),
                "last": Ip4Address("255.255.255.255"),
                "broadcast": Ip4Address("255.255.255.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.0/24 (str CIDR)",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.0/24 (str address mask)",
            "_args": [
                "192.168.1.100 255.255.255.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.0/24 (Ip4Address, Ip4Mask)",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Mask("255.255.255.0")),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.0/24 (Ip4Network)",
            "_args": [
                Ip4Network("192.168.1.100/24"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 10.0.0.0/8 (str)",
            "_args": [
                "10.20.30.40/8",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "10.0.0.0/8",
                "__repr__": "Ip4Network('10.0.0.0/8')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("10.0.0.0"),
                "mask": Ip4Mask("255.0.0.0"),
                "last": Ip4Address("10.255.255.255"),
                "broadcast": Ip4Address("10.255.255.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 172.16.16.0/20 (str)",
            "_args": [
                "172.16.21.40/20",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.16.16.0/20",
                "__repr__": "Ip4Network('172.16.16.0/20')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("172.16.16.0"),
                "mask": Ip4Mask("255.255.240.0"),
                "last": Ip4Address("172.16.31.255"),
                "broadcast": Ip4Address("172.16.31.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 172.16.10.70/31 (str)",
            "_args": [
                "172.16.10.70/31",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.16.10.70/31",
                "__repr__": "Ip4Network('172.16.10.70/31')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("172.16.10.70"),
                "mask": Ip4Mask("255.255.255.254"),
                "last": Ip4Address("172.16.10.71"),
                "broadcast": Ip4Address("172.16.10.71"),
            },
        },
        {
            "_description": "Test the IPv4 network: 127.0.0.1/32 (str)",
            "_args": [
                "127.0.0.1/32",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "127.0.0.1/32",
                "__repr__": "Ip4Network('127.0.0.1/32')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("127.0.0.1"),
                "mask": Ip4Mask("255.255.255.255"),
                "last": Ip4Address("127.0.0.1"),
                "broadcast": Ip4Address("127.0.0.1"),
            },
        },
    ]
)
class TestNetAddrIp4Network(TestCase):
    """
    The NetAddr IPv4 Network tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the IPv4 network object with testcase arguments.
        """

        self._ip4_network = Ip4Network(*self._args, **self._kwargs)

    def test__net_addr__ip4_network__str(self) -> None:
        """
        Ensure the IPv4 network '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip4_network),
            self._results["__str__"],
        )

    def test__net_addr__ip4_network__repr(self) -> None:
        """
        Ensure the IPv4 network '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip4_network),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_network__eq(self) -> None:
        """
        Ensure the IPv4 network '__eq__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._ip4_network == self._ip4_network,
            msg="An Ip4Network instance must compare equal to itself.",
        )

        self.assertTrue(
            self._ip4_network == Ip4Network(str(self._ip4_network)),
            msg="Ip4Network must compare equal to one reconstructed from its string representation.",
        )

        if int(self._ip4_network.mask) != 0:
            self.assertFalse(
                self._ip4_network
                == Ip4Network(
                    (
                        Ip4Address((int(self._ip4_network.address) - 1) & 0xFF_FF_FF_FF),
                        self._ip4_network.mask,
                    ),
                ),
                msg="Ip4Network instances with different network addresses must not compare equal.",
            )

        self.assertFalse(
            self._ip4_network
            == Ip4Network(
                (
                    self._ip4_network.address,
                    Ip4Mask(f"/{(len(self._ip4_network.mask) + 1) % 33}"),
                ),
            ),
            msg="Ip4Network instances with different masks must not compare equal.",
        )

        self.assertFalse(
            self._ip4_network == "not an IPv4 network",
            msg="Ip4Network must not compare equal to a foreign string value.",
        )

    def test__net_addr__ip4_network__version(self) -> None:
        """
        Ensure the IPv4 network 'version' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_network.version,
            self._results["version"],
        )

    def test__net_addr__ip4_network__is_ip4(self) -> None:
        """
        Ensure the IPv4 network 'is_ip4' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_network.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_network__is_ip6(self) -> None:
        """
        Ensure the IPv4 network 'is_ip6' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_network.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_network__address(self) -> None:
        """
        Ensure the IPv4 network 'address' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_network.address,
            self._results["address"],
        )

    def test__net_addr__ip4_network__mask(self) -> None:
        """
        Ensure the IPv4 network 'mask' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_network.mask,
            self._results["mask"],
        )

    def test__net_addr__ip4_network__last(self) -> None:
        """
        Ensure the IPv4 network 'last' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_network.last,
            self._results["last"],
        )

    def test__net_addr__ip4_network__broadcast(self) -> None:
        """
        Ensure the IPv4 network 'broadcast' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_network.broadcast,
            self._results["broadcast"],
        )


@parameterized_class(
    [
        {
            "_description": "Ip4Address inside network",
            "_network": "192.168.1.0/24",
            "_object": Ip4Address("192.168.1.100"),
            "_result": True,
        },
        {
            "_description": "Ip4Address equals network address",
            "_network": "192.168.1.0/24",
            "_object": Ip4Address("192.168.1.0"),
            "_result": True,
        },
        {
            "_description": "Ip4Address equals broadcast address",
            "_network": "192.168.1.0/24",
            "_object": Ip4Address("192.168.1.255"),
            "_result": True,
        },
        {
            "_description": "Ip4Address outside network",
            "_network": "192.168.1.0/24",
            "_object": Ip4Address("192.168.2.1"),
            "_result": False,
        },
        {
            "_description": "Ip4IfAddr inside network",
            "_network": "192.168.1.0/24",
            "_object": Ip4IfAddr("192.168.1.50/24"),
            "_result": True,
        },
        {
            "_description": "Ip4IfAddr outside network",
            "_network": "192.168.1.0/24",
            "_object": Ip4IfAddr("192.168.2.50/24"),
            "_result": False,
        },
        {
            "_description": "Unsupported type returns False",
            "_network": "192.168.1.0/24",
            "_object": "192.168.1.1",
            "_result": False,
        },
        {
            "_description": "Ip6Address cross-version returns False",
            "_network": "192.168.1.0/24",
            "_object": Ip6Address("2001:db8::1"),
            "_result": False,
        },
        {
            "_description": "Ip6IfAddr cross-version returns False",
            "_network": "192.168.1.0/24",
            "_object": Ip6IfAddr("2001:db8::1/64"),
            "_result": False,
        },
        {
            "_description": "Integer type returns False",
            "_network": "192.168.1.0/24",
            "_object": 0xC0A80101,
            "_result": False,
        },
        {
            "_description": "None returns False",
            "_network": "192.168.1.0/24",
            "_object": None,
            "_result": False,
        },
    ]
)
class TestNetAddrIp4NetworkContains(TestCase):
    """
    The NetAddr IPv4 network '__contains__()' tests.
    """

    _description: str
    _network: str
    _object: Any
    _result: bool

    def test__net_addr__ip4_network__contains(self) -> None:
        """
        Ensure the IPv4 network '__contains__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._object in Ip4Network(self._network),
            self._result,
            msg=f"'__contains__()' returned wrong value for case: {self._description}.",
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 network format: '192.168.1.0//24'",
            "_args": [
                "192.168.1.0//24",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '192.168.1.0//24'",
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1./24'",
            "_args": [
                "192.168.1./24",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '192.168.1./24'",
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1.0/33'",
            "_args": [
                "192.168.1.0/33",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '192.168.1.0/33'",
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1.0 128.255.255.255' (non-contiguous mask)",
            "_args": [
                "192.168.1.0 128.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '192.168.1.0 128.255.255.255'",
            },
        },
        {
            "_description": "Test the IPv4 network format: '256.168.1.0/24' (invalid address)",
            "_args": [
                "256.168.1.0/24",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '256.168.1.0/24'",
            },
        },
        {
            "_description": "Test the IPv4 network format: 12345 (invalid type)",
            "_args": [
                12345,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: 12345",
            },
        },
        {
            "_description": "Test the IPv4 network format: ('10.0.0.0', '/24') (mistyped tuple)",
            "_args": [
                ("10.0.0.0", "/24"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: ('10.0.0.0', '/24')",
            },
        },
        {
            "_description": "Test the IPv4 network format: (Ip4Address('10.0.0.0'),) (wrong-length tuple)",
            "_args": [
                (Ip4Address("10.0.0.0"),),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: (Ip4Address('10.0.0.0'),)",
            },
        },
    ]
)
class TestNetAddrIp4NetworkErrors(TestCase):
    """
    The NetAddr IPv4 network error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_network__errors(self) -> None:
        """
        Ensure the IPv4 network raises an error on invalid input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Network(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


class TestNetAddrIp4NetworkEquality(TestCase):
    """
    The NetAddr IPv4 network equality and inequality tests not tied to
    a parameterized matrix.
    """

    def test__net_addr__ip4_network__eq__cross_version(self) -> None:
        """
        Ensure an IPv4 network never compares equal to an IPv6 network
        even when their string representations overlap.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            Ip4Network("192.168.1.0/24"),
            Ip6Network("2001:db8::/24"),
            msg="Ip4Network must not compare equal to an Ip6Network.",
        )

    def test__net_addr__ip4_network__eq__foreign_types(self) -> None:
        """
        Ensure the IPv4 network is never equal to a value of a foreign
        type, including its own component pieces.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        network = Ip4Network("192.168.1.0/24")

        self.assertFalse(
            network == "192.168.1.0/24",
            msg="Ip4Network must not compare equal to its string representation.",
        )
        self.assertFalse(
            network == network.address,
            msg="Ip4Network must not compare equal to its Ip4Address component.",
        )
        self.assertFalse(
            network == network.mask,
            msg="Ip4Network must not compare equal to its Ip4Mask component.",
        )
        self.assertFalse(
            network == Ip4IfAddr("192.168.1.1/24"),
            msg="Ip4Network must not compare equal to an Ip4IfAddr.",
        )
        self.assertFalse(
            network == 0xC0A80100,
            msg="Ip4Network must not compare equal to an integer.",
        )
        self.assertFalse(
            network == None,  # noqa: E711
            msg="Ip4Network must not compare equal to None.",
        )

    def test__net_addr__ip4_network__ne(self) -> None:
        """
        Ensure the IPv4 network '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        network = Ip4Network("192.168.1.0/24")
        self.assertTrue(
            network != Ip4Network("192.168.2.0/24"),
            msg="Ip4Network instances with different network addresses must be unequal.",
        )
        self.assertTrue(
            network != Ip4Network("192.168.1.0/25"),
            msg="Ip4Network instances with different masks must be unequal.",
        )
        self.assertFalse(
            network != Ip4Network("192.168.1.0/24"),
            msg="Ip4Network instances with matching address and mask must not be unequal.",
        )
        self.assertTrue(
            network != "192.168.1.0/24",
            msg="Ip4Network must be unequal to its string representation.",
        )


class TestNetAddrIp4NetworkHashConsistency(TestCase):
    """
    The NetAddr IPv4 network hash consistency tests.
    """

    def test__net_addr__ip4_network__hash__distinct_instances(self) -> None:
        """
        Ensure two independently constructed equal networks hash identically.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Network("192.168.1.100/24")
        b = Ip4Network((Ip4Address("192.168.1.200"), Ip4Mask("/24")))
        c = Ip4Network("192.168.1.0 255.255.255.0")

        self.assertEqual(
            a,
            b,
            msg="Ip4Network built from CIDR string and (address, mask) tuple must compare equal.",
        )
        self.assertEqual(
            a,
            c,
            msg="Ip4Network built from CIDR string and 'address mask' string must compare equal.",
        )
        self.assertEqual(
            hash(a),
            hash(b),
            msg="Equal Ip4Network values must hash to the same value across constructor forms.",
        )
        self.assertEqual(
            hash(a),
            hash(c),
            msg="Equal Ip4Network values must hash to the same value across string forms.",
        )

    def test__net_addr__ip4_network__usable_in_set(self) -> None:
        """
        Ensure equal IPv4 networks collapse into a single element when
        used in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Network("192.168.1.0/24")
        b = Ip4Network((Ip4Address("192.168.1.100"), Ip4Mask("/24")))
        c = Ip4Network("192.168.2.0/24")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip4Network values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip4Network values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip4Network values as the same key.",
        )

    def test__net_addr__ip4_network__usable_in_dict(self) -> None:
        """
        Ensure equal IPv4 networks refer to the same dict entry regardless
        of which constructor form was used to build the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Network("192.168.1.0/24")
        b = Ip4Network((Ip4Address("192.168.1.100"), Ip4Mask("/24")))

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip4Network must behave consistently as a dict key across input forms.",
        )


class TestNetAddrIp4NetworkRoundtrip(TestCase):
    """
    The NetAddr IPv4 network string roundtrip tests.
    """

    def test__net_addr__ip4_network__roundtrip__str(self) -> None:
        """
        Ensure 'Ip4Network(str(x))' yields a network equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in (
            "0.0.0.0/0",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.0/24",
            "192.168.1.100/31",
            "255.255.255.255/32",
        ):
            with self.subTest(spec=spec):
                network = Ip4Network(spec)
                self.assertEqual(
                    Ip4Network(str(network)),
                    network,
                    msg=f"Roundtrip through str() must preserve network {spec!r}.",
                )

    def test__net_addr__ip4_network__roundtrip__copy(self) -> None:
        """
        Ensure constructing an Ip4Network from another Ip4Network yields
        an equal network with the same hash.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = Ip4Network("192.168.1.100/24")
        clone = Ip4Network(source)

        self.assertEqual(
            clone,
            source,
            msg="Copy-constructed Ip4Network must compare equal to the source.",
        )
        self.assertEqual(
            hash(clone),
            hash(source),
            msg="Copy-constructed Ip4Network must share the source's hash.",
        )
        self.assertEqual(
            clone.address,
            source.address,
            msg="Copy-constructed Ip4Network must preserve the network address.",
        )
        self.assertEqual(
            clone.mask,
            source.mask,
            msg="Copy-constructed Ip4Network must preserve the mask.",
        )


@parameterized_class(
    [
        {
            "_description": "Ip4Network 192.0.2.0/30 (4 addresses, 2 hosts).",
            "_network": "192.0.2.0/30",
            "_results": {
                "num_addresses": 4,
                "iter": ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"],
                "hosts": ["192.0.2.1", "192.0.2.2"],
                "supernet": "192.0.2.0/29",
                "subnets": ["192.0.2.0/31", "192.0.2.2/31"],
            },
        },
        {
            "_description": "Ip4Network 192.0.2.0/31 (RFC 3021 point-to-point).",
            "_network": "192.0.2.0/31",
            "_results": {
                "num_addresses": 2,
                "iter": ["192.0.2.0", "192.0.2.1"],
                "hosts": ["192.0.2.0", "192.0.2.1"],
                "supernet": "192.0.2.0/30",
                "subnets": ["192.0.2.0/32", "192.0.2.1/32"],
            },
        },
        {
            "_description": "Ip4Network 192.0.2.5/32 (single host).",
            "_network": "192.0.2.5/32",
            "_results": {
                "num_addresses": 1,
                "iter": ["192.0.2.5"],
                "hosts": ["192.0.2.5"],
                "supernet": "192.0.2.4/31",
                "subnets": ["192.0.2.5/32"],
            },
        },
    ]
)
class TestNetAddrIp4NetworkEnumeration(TestCase):
    """
    The NetAddr IPv4 network enumeration / subnetting tests.
    """

    _description: str
    _network: str
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the network under test from its CIDR string.
        """

        self._net = Ip4Network(self._network)

    def test__net_addr__ip4_network__num_addresses(self) -> None:
        """
        Ensure 'num_addresses' counts every address in the
        block, network and broadcast inclusive.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._net.num_addresses,
            self._results["num_addresses"],
            msg=f"Unexpected num_addresses for case: {self._description}",
        )

    def test__net_addr__ip4_network__iter(self) -> None:
        """
        Ensure iterating the network yields every address from
        the network address through the broadcast address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            [str(address) for address in self._net],
            self._results["iter"],
            msg=f"Unexpected iteration for case: {self._description}",
        )

    def test__net_addr__ip4_network__hosts(self) -> None:
        """
        Ensure 'hosts' excludes the network and broadcast
        addresses, while a /31 and a single-host /32 yield
        every address instead.

        Reference: RFC 3021 (Using 31-Bit Prefixes on IPv4 Point-to-Point Links).
        """

        self.assertEqual(
            [str(address) for address in self._net.hosts()],
            self._results["hosts"],
            msg=f"Unexpected hosts for case: {self._description}",
        )

    def test__net_addr__ip4_network__supernet(self) -> None:
        """
        Ensure 'supernet' returns the immediately containing
        block one prefix bit shorter.

        Reference: RFC 4632 (Classless Inter-domain Routing).
        """

        self.assertEqual(
            str(self._net.supernet()),
            self._results["supernet"],
            msg=f"Unexpected supernet for case: {self._description}",
        )

    def test__net_addr__ip4_network__subnets(self) -> None:
        """
        Ensure 'subnets' tiles the network with the blocks one
        prefix bit longer.

        Reference: RFC 4632 (Classless Inter-domain Routing).
        """

        self.assertEqual(
            [str(subnet) for subnet in self._net.subnets()],
            self._results["subnets"],
            msg=f"Unexpected subnets for case: {self._description}",
        )


class TestNetAddrIp4NetworkRelations(TestCase):
    """
    The NetAddr IPv4 network containment / overlap tests.
    """

    def test__net_addr__ip4_network__relations(self) -> None:
        """
        Ensure overlaps / subnet_of / supernet_of report
        containment correctly, including the disjoint and
        cross-version cases.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        outer = Ip4Network("10.0.0.0/8")
        inner = Ip4Network("10.1.0.0/16")
        other = Ip4Network("192.168.0.0/16")

        for label, actual, expected in [
            ("outer overlaps inner", outer.overlaps(inner), True),
            ("outer overlaps other", outer.overlaps(other), False),
            ("inner subnet_of outer", inner.subnet_of(outer), True),
            ("outer subnet_of inner", outer.subnet_of(inner), False),
            ("outer supernet_of inner", outer.supernet_of(inner), True),
            ("inner supernet_of outer", inner.supernet_of(outer), False),
            ("cross-version overlaps", outer.overlaps(Ip6Network("::/0")), False),
            ("cross-version subnet_of", outer.subnet_of(Ip6Network("::/0")), False),
        ]:
            with self.subTest(relation=label):
                self.assertEqual(
                    actual,
                    expected,
                    msg=f"Unexpected result for: {label}",
                )


class TestNetAddrIp4NetworkSubnettingArgs(TestCase):
    """
    The NetAddr IPv4 subnets / supernet argument tests.
    """

    def test__net_addr__ip4_network__subnets__new_prefix(self) -> None:
        """
        Ensure 'subnets' honours an explicit target prefix
        length.

        Reference: RFC 4632 (Classless Inter-domain Routing).
        """

        self.assertEqual(
            [str(s) for s in Ip4Network("192.0.2.0/24").subnets(new_prefix=26)],
            ["192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26", "192.0.2.192/26"],
            msg="subnets(new_prefix=26) must tile a /24 into four /26 blocks.",
        )

    def test__net_addr__ip4_network__supernet__new_prefix_and_diff(self) -> None:
        """
        Ensure 'supernet' honours both an explicit target
        prefix length and a prefix-length delta, including the
        /0 boundary.

        Reference: RFC 4632 (Classless Inter-domain Routing).
        """

        self.assertEqual(
            str(Ip4Network("192.0.2.0/24").supernet(prefixlen_diff=8)),
            "192.0.0.0/16",
            msg="supernet(prefixlen_diff=8) must shorten a /24 to /16.",
        )
        self.assertEqual(
            str(Ip4Network("10.20.30.0/24").supernet(new_prefix=0)),
            "0.0.0.0/0",
            msg="supernet(new_prefix=0) must collapse to the default route.",
        )

    def test__net_addr__ip4_network__supernet__default_route_idempotent(self) -> None:
        """
        Ensure 'supernet' on a /0 returns the network itself
        regardless of the arguments, since the default route has
        no shorter-prefix container, matching the standard
        library.

        Reference: PyTCP test infrastructure (stdlib ipaddress parity, no RFC clause).
        """

        default = Ip4Network("0.0.0.0/0")
        self.assertEqual(
            default.supernet(),
            default,
            msg="supernet() of /0 must return the /0 itself.",
        )
        self.assertEqual(
            default.supernet(prefixlen_diff=8),
            default,
            msg="supernet(prefixlen_diff=...) of /0 must still return the /0 itself.",
        )

    def test__net_addr__ip4_network__subnetting__boundary_message(self) -> None:
        """
        Ensure the subnets / supernet out-of-range boundary
        errors report the resulting prefix length rather than a
        'prefixlen_diff' the caller never supplied (the new_prefix
        code path).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip4NetworkSanityError) as subnets_error:
            list(Ip4Network("10.0.0.0/8").subnets(new_prefix=33))
        self.assertIn(
            "/33",
            str(subnets_error.exception),
            msg="subnets(new_prefix=33) message must reference the requested /33.",
        )
        self.assertNotIn(
            "prefixlen_diff",
            str(subnets_error.exception),
            msg="subnets(new_prefix=...) message must not mention prefixlen_diff.",
        )

        with self.assertRaises(Ip4NetworkSanityError) as supernet_error:
            Ip4Network("10.0.0.0/8").supernet(new_prefix=-1)
        self.assertIn(
            "/-1",
            str(supernet_error.exception),
            msg="supernet(new_prefix=-1) message must reference the requested /-1.",
        )
        self.assertNotIn(
            "prefixlen_diff",
            str(supernet_error.exception),
            msg="supernet(new_prefix=...) message must not mention prefixlen_diff.",
        )

    def test__net_addr__ip4_network__subnetting__errors(self) -> None:
        """
        Ensure invalid subnets / supernet arguments raise
        Ip4NetworkSanityError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        cases: list[tuple[str, Callable[[], object]]] = [
            ("subnets new_prefix <= prefixlen", lambda: list(Ip4Network("10.0.0.0/8").subnets(new_prefix=4))),
            ("subnets prefixlen_diff < 1", lambda: list(Ip4Network("10.0.0.0/8").subnets(prefixlen_diff=0))),
            ("subnets past /32", lambda: list(Ip4Network("10.0.0.0/8").subnets(new_prefix=33))),
            ("supernet new_prefix >= prefixlen", lambda: Ip4Network("10.0.0.0/8").supernet(new_prefix=8)),
            ("supernet below /0", lambda: Ip4Network("10.0.0.0/8").supernet(prefixlen_diff=9)),
            ("supernet negative prefixlen_diff", lambda: Ip4Network("10.0.0.0/24").supernet(prefixlen_diff=-2)),
            ("supernet zero prefixlen_diff", lambda: Ip4Network("10.0.0.0/24").supernet(prefixlen_diff=0)),
        ]
        for label, thunk in cases:
            with self.subTest(case=label):
                with self.assertRaises(Ip4NetworkSanityError, msg=f"{label} must raise Ip4NetworkSanityError"):
                    thunk()


class TestNetAddrIp4NetworkOrdering(TestCase):
    """
    The NetAddr IPv4 network ordering tests.
    """

    def test__net_addr__ip4_network__ordering(self) -> None:
        """
        Ensure IPv4 networks are totally ordered by network
        address then prefix length (longer prefix sorts later
        when the network address is equal).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4Network("10.0.0.0/8")
        b = Ip4Network("10.0.0.0/24")
        c = Ip4Network("192.168.0.0/16")

        self.assertEqual(
            sorted([c, b, a]),
            [a, b, c],
            msg="Ip4Network must sort by (network address, prefix length).",
        )
        self.assertTrue(a < b, msg="Same network, longer prefix must sort after.")
        self.assertTrue(b < c, msg="Lower network address must sort before.")
        self.assertEqual(min(c, b, a), a, msg="min() must return the lowest Ip4Network.")

    def test__net_addr__ip4_network__ordering__cross_version_raises(self) -> None:
        """
        Ensure ordering an IPv4 network against an IPv6 network
        raises TypeError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError, msg="Ip4Network < Ip6Network must raise TypeError."):
            _ = Ip4Network("10.0.0.0/8") < Ip6Network("2001:db8::/32")


@parameterized_class(
    [
        {
            "_description": "Ip4Network 192.0.2.0/24",
            "_network": "192.0.2.0/24",
            "_results": {
                "hostmask": Ip4Wildcard("0.0.0.255"),
                "with_prefixlen": "192.0.2.0/24",
                "with_netmask": "192.0.2.0/255.255.255.0",
                "with_hostmask": "192.0.2.0/0.0.0.255",
            },
        },
        {
            "_description": "Ip4Network 10.0.0.0/8",
            "_network": "10.0.0.0/8",
            "_results": {
                "hostmask": Ip4Wildcard("0.255.255.255"),
                "with_prefixlen": "10.0.0.0/8",
                "with_netmask": "10.0.0.0/255.0.0.0",
                "with_hostmask": "10.0.0.0/0.255.255.255",
            },
        },
        {
            "_description": "Ip4Network 0.0.0.0/0",
            "_network": "0.0.0.0/0",
            "_results": {
                "hostmask": Ip4Wildcard("255.255.255.255"),
                "with_prefixlen": "0.0.0.0/0",
                "with_netmask": "0.0.0.0/0.0.0.0",
                "with_hostmask": "0.0.0.0/255.255.255.255",
            },
        },
        {
            "_description": "Ip4Network 192.0.2.5/32",
            "_network": "192.0.2.5/32",
            "_results": {
                "hostmask": Ip4Wildcard("0.0.0.0"),
                "with_prefixlen": "192.0.2.5/32",
                "with_netmask": "192.0.2.5/255.255.255.255",
                "with_hostmask": "192.0.2.5/0.0.0.0",
            },
        },
    ]
)
class TestNetAddrIp4NetworkWithForms(TestCase):
    """
    The NetAddr IPv4 network hostmask / with_* representation tests.
    """

    _description: str
    _network: str
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the network under test from its CIDR string.
        """

        self._net = Ip4Network(self._network)

    def test__net_addr__ip4_network__hostmask(self) -> None:
        """
        Ensure 'hostmask' is the inverted-netmask Ip4Wildcard
        (the contiguous special case of an ACL wildcard).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._net.hostmask,
            Ip4Wildcard,
            msg=f"hostmask must be an Ip4Wildcard for case: {self._description}",
        )
        self.assertEqual(
            self._net.hostmask,
            self._results["hostmask"],
            msg=f"Unexpected hostmask for case: {self._description}",
        )

    def test__net_addr__ip4_network__format(self) -> None:
        """
        Ensure __format__ renders the pl / nm / hm notations;
        the default and 'pl' equal str(); an unknown spec
        raises ValueError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec, key in [("pl", "with_prefixlen"), ("nm", "with_netmask"), ("hm", "with_hostmask")]:
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(self._net, spec),
                    self._results[key],
                    msg=f"Unexpected format {spec!r} for case: {self._description}",
                )

        self.assertEqual(
            f"{self._net}",
            self._results["with_prefixlen"],
            msg=f"Default format must equal the prefixlen form for: {self._description}",
        )

        with self.assertRaises(Ip4NetworkSanityError, msg="An unknown format spec must raise Ip4NetworkSanityError."):
            format(self._net, "zz")


class TestNetAddrIp4NetworkPrefixlen(TestCase):
    """
    The NetAddr IPv4 network prefixlen / max_prefixlen tests.
    """

    def test__net_addr__ip4_network__prefixlen(self) -> None:
        """
        Ensure 'prefixlen' is the mask prefix length and
        'max_prefixlen' is 32.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for cidr, prefixlen in [("0.0.0.0/0", 0), ("192.0.2.0/24", 24), ("192.0.2.5/32", 32)]:
            with self.subTest(network=cidr):
                net = Ip4Network(cidr)
                self.assertEqual(net.prefixlen, prefixlen, msg=f"Unexpected prefixlen for {cidr}.")
                self.assertEqual(net.max_prefixlen, 32, msg=f"max_prefixlen must be 32 for {cidr}.")


class TestNetAddrIp4NetworkGetitem(TestCase):
    """
    The NetAddr IPv4 network indexing tests.
    """

    def test__net_addr__ip4_network__getitem(self) -> None:
        """
        Ensure 'network[i]' returns the i-th address (negative
        indexes count from the last address); out-of-range
        raises Ip4NetworkSanityError; slices are not supported.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        net = Ip4Network("192.0.2.0/24")
        for index, expected in [
            (0, Ip4Address("192.0.2.0")),
            (1, Ip4Address("192.0.2.1")),
            (255, Ip4Address("192.0.2.255")),
            (-1, Ip4Address("192.0.2.255")),
            (-256, Ip4Address("192.0.2.0")),
        ]:
            with self.subTest(index=index):
                self.assertEqual(net[index], expected, msg=f"net[{index}] must be {expected}.")

        for bad in (256, -257):
            with self.subTest(index=bad):
                with self.assertRaises(Ip4NetworkSanityError, msg=f"net[{bad}] must raise Ip4NetworkSanityError."):
                    _ = net[bad]

        single = Ip4Network("192.0.2.5/32")
        self.assertEqual(single[0], Ip4Address("192.0.2.5"), msg="single[0] must be the host.")
        self.assertEqual(single[-1], Ip4Address("192.0.2.5"), msg="single[-1] must be the host.")
        with self.assertRaises(Ip4NetworkSanityError, msg="single[1] must raise Ip4NetworkSanityError."):
            _ = single[1]

        with self.assertRaises(TypeError, msg="Slicing must not be supported."):
            _ = net[0:2]  # type: ignore[index]


class TestNetAddrIp4NetworkAddressExclude(TestCase):
    """
    The NetAddr IPv4 network address_exclude (CIDR set-subtraction) tests.
    """

    def test__net_addr__ip4_network__address_exclude(self) -> None:
        """
        Ensure 'address_exclude' returns the minimal aggregate
        CIDRs covering self minus other, in stdlib descent
        order; an equal operand yields nothing.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        n = Ip4Network("192.0.2.0/24")
        for other, expected in [
            (Ip4Network("192.0.2.128/25"), ["192.0.2.0/25"]),
            (Ip4Network("192.0.2.64/26"), ["192.0.2.128/25", "192.0.2.0/26"]),
            (Ip4Network("192.0.2.0/24"), []),
            (
                Ip4Network("192.0.2.1/32"),
                [
                    "192.0.2.128/25",
                    "192.0.2.64/26",
                    "192.0.2.32/27",
                    "192.0.2.16/28",
                    "192.0.2.8/29",
                    "192.0.2.4/30",
                    "192.0.2.2/31",
                    "192.0.2.0/32",
                ],
            ),
        ]:
            with self.subTest(other=str(other)):
                self.assertEqual(
                    [str(x) for x in n.address_exclude(other)],
                    expected,
                    msg=f"Unexpected address_exclude({other}) result.",
                )

    def test__net_addr__ip4_network__address_exclude__errors(self) -> None:
        """
        Ensure excluding a non-contained or cross-version
        network raises Ip4NetworkSanityError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        n = Ip4Network("192.0.2.0/24")
        with self.assertRaises(Ip4NetworkSanityError, msg="A non-contained operand must raise Ip4NetworkSanityError."):
            list(n.address_exclude(Ip4Network("198.51.100.0/25")))
        with self.assertRaises(Ip4NetworkSanityError, msg="A cross-version operand must raise Ip4NetworkSanityError."):
            list(n.address_exclude(Ip6Network("2001:db8::/32")))  # type: ignore[arg-type]

    def test__net_addr__ip4_network__address_exclude__single_address_only_raises_netaddrerror(self) -> None:
        """
        Ensure 'address_exclude' on a single-address (/32)
        network only ever escapes a NetAddrError subclass: an
        equal operand yields nothing and a non-contained operand
        raises Ip4NetworkSanityError, never a bare ValueError
        from the internal subnet split.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        n = Ip4Network("192.0.2.1/32")
        self.assertEqual(
            list(n.address_exclude(Ip4Network("192.0.2.1/32"))),
            [],
            msg="Excluding a /32 from itself must yield nothing.",
        )
        with self.assertRaises(
            Ip4NetworkSanityError,
            msg="A non-contained operand against a /32 must raise Ip4NetworkSanityError, never ValueError.",
        ):
            list(n.address_exclude(Ip4Network("192.0.2.0/24")))


class TestNetAddrIp4NetworkSummarize(TestCase):
    """
    The NetAddr IPv4 IpNetwork.summarize prefix-aggregation tests.
    """

    def test__net_addr__ip4_network__summarize(self) -> None:
        """
        Ensure 'summarize' aggregates a set of addresses and
        networks into the minimal covering CIDR set — adjacent
        and overlapping entries merged, gaps preserved.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        cases: list[tuple[list[Ip4Address | Ip4Network], list[str]]] = [
            ([Ip4Network("10.0.0.0/24"), Ip4Network("10.0.1.0/24")], ["10.0.0.0/23"]),
            ([Ip4Network("192.0.2.0/24"), Ip4Network("192.0.2.128/25")], ["192.0.2.0/24"]),
            ([Ip4Address("10.0.0.0"), Ip4Address("10.0.0.1")], ["10.0.0.0/31"]),
            ([Ip4Network("10.0.0.0/24"), Ip4Network("10.0.2.0/24")], ["10.0.0.0/24", "10.0.2.0/24"]),
            (
                [
                    Ip4Network("10.0.0.0/30"),
                    Ip4Address("10.0.0.4"),
                    Ip4Address("10.0.0.5"),
                    Ip4Address("10.0.0.6"),
                    Ip4Address("10.0.0.7"),
                ],
                ["10.0.0.0/29"],
            ),
            ([], []),
        ]
        for items, expected in cases:
            with self.subTest(items=items):
                self.assertEqual(
                    [str(network) for network in IpNetwork.summarize(items)],
                    expected,
                    msg=f"summarize({items}) must be {expected}.",
                )

    def test__net_addr__ip4_network__summarize_mixed_version_raises(self) -> None:
        """
        Ensure 'summarize' raises 'IpNetworkSanityError' on a
        mixed-version input set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mixed = [Ip4Network("10.0.0.0/24"), Ip6Network("2001:db8::/64")]
        with self.assertRaises(IpNetworkSanityError):
            list(IpNetwork.summarize(mixed))  # type: ignore[arg-type]

    def test__net_addr__ip4_network__summarize_bad_item_raises(self) -> None:
        """
        Ensure 'summarize' raises 'IpNetworkSanityError' when an
        item is neither an IP address nor an IP network.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpNetworkSanityError):
            list(IpNetwork.summarize([5]))  # type: ignore[list-item]


class TestNetAddrIp4NetworkStrict(TestCase):
    """
    The NetAddr Ip4Network strict-mode constructor tests.
    """

    def test__net_addr__ip4_network__strict_clean_ok(self) -> None:
        """
        Ensure a network whose address has no host bits set
        constructs normally under strict=True (str and tuple
        forms), and copy/None never trip strict.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        self.assertEqual(
            Ip4Network("192.168.1.0/24", strict=True),
            Ip4Network("192.168.1.0/24"),
            msg="A host-bit-free CIDR must construct under strict.",
        )
        self.assertEqual(
            Ip4Network((Ip4Address("10.0.0.0"), Ip4Mask("/24")), strict=True),
            Ip4Network("10.0.0.0/24"),
            msg="A host-bit-free tuple must construct under strict.",
        )
        self.assertEqual(
            Ip4Network(Ip4Network("10.0.0.0/24"), strict=True),
            Ip4Network("10.0.0.0/24"),
            msg="Copy construction must not trip strict.",
        )

    def test__net_addr__ip4_network__strict_host_bits_raise(self) -> None:
        """
        Ensure strict=True rejects an address carrying bits
        outside the mask, for both the string and tuple forms.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        with self.assertRaises(Ip4NetworkFormatError):
            Ip4Network("192.168.1.100/24", strict=True)
        with self.assertRaises(Ip4NetworkFormatError):
            Ip4Network("10.0.0.5 255.255.255.0", strict=True)
        with self.assertRaises(Ip4NetworkFormatError):
            Ip4Network((Ip4Address("10.0.0.5"), Ip4Mask("/24")), strict=True)

    def test__net_addr__ip4_network__default_masks(self) -> None:
        """
        Ensure the default (strict=False) still silently masks
        host bits, preserving the existing constructor contract.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        self.assertEqual(
            Ip4Network("192.168.1.100/24"),
            Ip4Network("192.168.1.0/24"),
            msg="Default construction must keep masking host bits.",
        )


class TestNetAddrIp4NetworkWhitespace(TestCase):
    """
    The NetAddr Ip4Network surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip4_network__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("10.0.0.0/24", "10.0.0.0 255.255.255.0"):
            expected = Ip4Network(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip4Network(wrapped),
                        expected,
                        msg=f"Ip4Network({wrapped!r}) must equal Ip4Network({value!r}).",
                    )


class TestNetAddrIp4NetworkStdlibParity(TestCase):
    """
    The NetAddr Ip4Network stdlib-ipaddress parity tests.
    """

    def test__net_addr__ip4_network__bare_address_is_host_route(self) -> None:
        """
        Ensure a prefix-less address parses as a /32 host route.

        Reference: PyTCP test infrastructure (stdlib ipaddress parity, no RFC clause).
        """

        net = Ip4Network("10.0.0.1")
        self.assertEqual(str(net), "10.0.0.1/32", msg="A bare address must parse as /32.")
        self.assertEqual(net.address, Ip4Address("10.0.0.1"), msg="The host address must be preserved.")
        self.assertEqual(net.mask, Ip4Mask("/32"), msg="The mask must be /32.")

    def test__net_addr__ip4_network__dotted_netmask_form(self) -> None:
        """
        Ensure the 'address/d.d.d.d' dotted-netmask form parses.

        Reference: PyTCP test infrastructure (stdlib ipaddress parity, no RFC clause).
        """

        net = Ip4Network("192.168.1.100/255.255.255.0")
        self.assertEqual(str(net), "192.168.1.0/24", msg="Dotted netmask must be honoured and host bits masked.")
        self.assertEqual(net.mask, Ip4Mask("255.255.255.0"), msg="The mask must be /24.")

    def test__net_addr__ip4_network__dotted_netmask_strict(self) -> None:
        """
        Ensure strict=True with the dotted-netmask form rejects
        host bits and accepts an aligned network.

        Reference: PyTCP test infrastructure (stdlib ipaddress parity, no RFC clause).
        """

        self.assertEqual(
            str(Ip4Network("10.0.0.0/255.0.0.0", strict=True)),
            "10.0.0.0/8",
            msg="An aligned dotted-netmask network must pass strict=True.",
        )
        with self.assertRaises(Ip4NetworkFormatError, msg="Host bits with strict=True must raise."):
            Ip4Network("10.1.2.3/255.0.0.0", strict=True)


class TestNetAddrIp4NetworkCauseChain(TestCase):
    """
    The NetAddr IPv4 network error-cause-chain tests.
    """

    def test__net_addr__ip4_network__string_reject_preserves_cause(self) -> None:
        """
        Ensure a malformed network string raises
        Ip4NetworkFormatError that preserves the swallowed
        sub-constructor failure as '__cause__', so a traceback
        shows which token (address vs mask) was rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for bad, cause in [
            ("999.0.0.1/24", Ip4AddressFormatError),
            ("10.0.0.1/99", Ip4MaskFormatError),
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(Ip4NetworkFormatError) as ctx:
                    Ip4Network(bad)
                self.assertIsInstance(
                    ctx.exception.__cause__,
                    cause,
                    msg=f"The swallowed {cause.__name__} must be preserved as __cause__ for {bad!r}.",
                )
