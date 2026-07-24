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
This module contains tests for the NetAddr package IPv6 network support class.

net_addr/tests/unit/test__ip6_network.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4Network,
    Ip6Address,
    Ip6AddressFormatError,
    Ip6IfAddr,
    Ip6Mask,
    Ip6MaskFormatError,
    Ip6Network,
    Ip6NetworkFormatError,
    Ip6NetworkSanityError,
    Ip6Wildcard,
    IpNetwork,
    IpNetworkSanityError,
    IpVersion,
)
from net_addr.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 network: ::/0 (str)",
            "_args": [
                "::/0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "::/0",
                "__repr__": "Ip6Network('::/0')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address(),
                "mask": Ip6Mask(),
                "last": Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: ::/0 (None)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "::/0",
                "__repr__": "Ip6Network('::/0')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address(),
                "mask": Ip6Mask(),
                "last": Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: 2001::/96 (Ip6Address, Ip6Mask)",
            "_args": [
                (Ip6Address("2001::"), Ip6Mask("/96")),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "2001::/96",
                "__repr__": "Ip6Network('2001::/96')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001::"),
                "mask": Ip6Mask("/96"),
                "last": Ip6Address("2001::ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: 2001:0:aaaa:bbbb:cccc:dddd:eeee:ffff/64 (str)",
            "_args": [
                "2001:0:aaaa:bbbb:cccc:dddd:eeee:ffff/64",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "2001:0:aaaa:bbbb::/64",
                "__repr__": "Ip6Network('2001:0:aaaa:bbbb::/64')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:0:aaaa:bbbb::"),
                "mask": Ip6Mask("/64"),
                "last": Ip6Address("2001:0:aaaa:bbbb:ffff:ffff:ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: 2002::dddd:cccc:dddd:eeee:ffff/32 (str)",
            "_args": [
                "2002::dddd:cccc:dddd:eeee:ffff/32",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "2002::/32",
                "__repr__": "Ip6Network('2002::/32')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2002::"),
                "mask": Ip6Mask("/32"),
                "last": Ip6Address("2002:0:ffff:ffff:ffff:ffff:ffff:ffff"),
            },
        },
        {
            "_description": "Test the IPv6 network: ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128 (str)",
            "_args": [
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
                "__repr__": "Ip6Network('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                "mask": Ip6Mask("/128"),
                "last": Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            },
        },
    ]
)
class TestNetAddrIp6Network(TestCase):
    """
    The NetAddr IPv6 Network tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the IPv6 network object with testcase arguments.
        """

        self._ip6_network = Ip6Network(*self._args, **self._kwargs)

    def test__net_addr__ip6_network__str(self) -> None:
        """
        Ensure the IPv6 network '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip6_network),
            self._results["__str__"],
        )

    def test__net_addr__ip6_network__repr(self) -> None:
        """
        Ensure the IPv6 network '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip6_network),
            self._results["__repr__"],
        )

    def test__net_addr__ip6_network__eq(self) -> None:
        """
        Ensure the IPv6 network '__eq__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._ip6_network == self._ip6_network,
            msg="Ip6Network must compare equal to itself.",
        )

        if int(self._ip6_network.mask) != 0:
            self.assertFalse(
                self._ip6_network
                == Ip6Network(
                    (
                        Ip6Address((int(self._ip6_network.address) - 1) & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF),
                        self._ip6_network.mask,
                    ),
                ),
                msg="Ip6Network values with different addresses must compare unequal.",
            )

        self.assertFalse(
            self._ip6_network
            == Ip6Network(
                (
                    self._ip6_network.address,
                    Ip6Mask(f"/{(len(self._ip6_network.mask) + 1) % 129}"),
                ),
            ),
            msg="Ip6Network values with different masks must compare unequal.",
        )

        self.assertFalse(
            self._ip6_network == "not an IPv6 network",
            msg="Ip6Network must not compare equal to an arbitrary string.",
        )

    def test__net_addr__ip6_network__version(self) -> None:
        """
        Ensure the IPv6 network 'version' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_network.version,
            self._results["version"],
        )

    def test__net_addr__ip6_network__is_ip4(self) -> None:
        """
        Ensure the IPv6 network 'is_ip4' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_network.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip6_network__is_ip6(self) -> None:
        """
        Ensure the IPv6 network 'is_ip6' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_network.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip6_network__address(self) -> None:
        """
        Ensure the IPv6 network 'address' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_network.address,
            self._results["address"],
        )

    def test__net_addr__ip6_network__mask(self) -> None:
        """
        Ensure the IPv6 network 'mask' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_network.mask,
            self._results["mask"],
        )

    def test__net_addr__ip6_network__last(self) -> None:
        """
        Ensure the IPv6 network 'last' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_network.last,
            self._results["last"],
        )


@parameterized_class(
    [
        {
            "_description": "Ip6Address inside network",
            "_network": "2001:db8::/64",
            "_object": Ip6Address("2001:db8::1"),
            "_result": True,
        },
        {
            "_description": "Ip6Address equals network address",
            "_network": "2001:db8::/64",
            "_object": Ip6Address("2001:db8::"),
            "_result": True,
        },
        {
            "_description": "Ip6Address equals last address",
            "_network": "2001:db8::/64",
            "_object": Ip6Address("2001:db8::ffff:ffff:ffff:ffff"),
            "_result": True,
        },
        {
            "_description": "Ip6Address outside network",
            "_network": "2001:db8::/64",
            "_object": Ip6Address("2001:db9::1"),
            "_result": False,
        },
        {
            "_description": "Ip6IfAddr inside network",
            "_network": "2001:db8::/64",
            "_object": Ip6IfAddr("2001:db8::50/64"),
            "_result": True,
        },
        {
            "_description": "Ip6IfAddr outside network",
            "_network": "2001:db8::/64",
            "_object": Ip6IfAddr("2001:db9::50/64"),
            "_result": False,
        },
        {
            "_description": "Ip6IfAddr at network address (lower boundary)",
            "_network": "2001:db8::/64",
            "_object": Ip6IfAddr("2001:db8::/64"),
            "_result": True,
        },
        {
            "_description": "Ip6IfAddr at last address (upper boundary)",
            "_network": "2001:db8::/64",
            "_object": Ip6IfAddr("2001:db8::ffff:ffff:ffff:ffff/64"),
            "_result": True,
        },
        {
            "_description": "Unsupported type returns False",
            "_network": "2001:db8::/64",
            "_object": "2001:db8::1",
            "_result": False,
        },
        {
            "_description": "Ip4Address cross-version returns False",
            "_network": "2001:db8::/64",
            "_object": Ip4Address("192.168.1.1"),
            "_result": False,
        },
        {
            "_description": "Ip4IfAddr cross-version returns False",
            "_network": "2001:db8::/64",
            "_object": Ip4IfAddr("192.168.1.1/24"),
            "_result": False,
        },
        {
            "_description": "Integer type returns False",
            "_network": "2001:db8::/64",
            "_object": 0x20010DB8_00000000_00000000_00000001,
            "_result": False,
        },
        {
            "_description": "None returns False",
            "_network": "2001:db8::/64",
            "_object": None,
            "_result": False,
        },
    ]
)
class TestNetAddrIp6NetworkContains(TestCase):
    """
    The NetAddr IPv6 network '__contains__()' tests.
    """

    _description: str
    _network: str
    _object: Any
    _result: bool

    def test__net_addr__ip6_network__contains(self) -> None:
        """
        Ensure the IPv6 network '__contains__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._object in Ip6Network(self._network),
            self._result,
            msg=f"'__contains__()' returned wrong value for case: {self._description}.",
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 network format: '2001:://64'",
            "_args": [
                "2001:://64",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": "The IPv6 network format is invalid: '2001:://64'",
            },
        },
        {
            "_description": "Test the IPv6 network format: '1:2:3:4:5:6:7:8:9/64'",
            "_args": [
                "1:2:3:4:5:6:7:8:9/64",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": "The IPv6 network format is invalid: '1:2:3:4:5:6:7:8:9/64'",
            },
        },
        {
            "_description": "Test the IPv6 network format: '1:2:3:4:5:6:7:8/129'",
            "_args": [
                "1:2:3:4:5:6:7:8/129",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": "The IPv6 network format is invalid: '1:2:3:4:5:6:7:8/129'",
            },
        },
        {
            "_description": "Test the IPv6 network format: 12345 (invalid type)",
            "_args": [
                12345,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": "The IPv6 network format is invalid: 12345",
            },
        },
        {
            "_description": "Test the IPv6 network format: ('2001:db8::', '/64') (mistyped tuple)",
            "_args": [
                ("2001:db8::", "/64"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": "The IPv6 network format is invalid: ('2001:db8::', '/64')",
            },
        },
        {
            "_description": "Test the IPv6 network format: (Ip6Address('2001:db8::'),) (wrong-length tuple)",
            "_args": [
                (Ip6Address("2001:db8::"),),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": "The IPv6 network format is invalid: (Ip6Address('2001:db8::'),)",
            },
        },
        {
            "_description": "Test the IPv6 network format: 'fe80::1%eth0/64' (zoned address in network literal)",
            "_args": [
                "fe80::1%eth0/64",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": "The IPv6 network format is invalid: 'fe80::1%eth0/64'",
            },
        },
        {
            "_description": "Test the IPv6 network format: (Ip6Address('fe80::1%eth0'), Ip6Mask('/64')) (zoned tuple)",
            "_args": [
                (Ip6Address("fe80::1%eth0"), Ip6Mask("/64")),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6NetworkFormatError,
                "error_message": (
                    "The IPv6 network format is invalid: " "(Ip6Address('fe80::1%eth0'), Ip6Mask('/64'))"
                ),
            },
        },
    ]
)
class TestNetAddrIp6NetworkErrors(TestCase):
    """
    The NetAddr IPv6 network error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip6_network__errors(self) -> None:
        """
        Ensure the IPv6 network raises an error on invalid input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip6Network(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


class TestNetAddrIp6NetworkEquality(TestCase):
    """
    The NetAddr IPv6 network equality and inequality tests not tied to
    a parameterized matrix.
    """

    def test__net_addr__ip6_network__eq__cross_version(self) -> None:
        """
        Ensure an IPv6 network never compares equal to an IPv4 network
        even when their prefix lengths overlap.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            Ip6Network("2001:db8::/24"),
            Ip4Network("192.168.1.0/24"),
            msg="Ip6Network must not compare equal to an Ip4Network.",
        )

    def test__net_addr__ip6_network__eq__foreign_types(self) -> None:
        """
        Ensure the IPv6 network is never equal to a value of a foreign
        type, including its own component pieces.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        network = Ip6Network("2001:db8::/64")

        self.assertFalse(
            network == "2001:db8::/64",
            msg="Ip6Network must not compare equal to its string representation.",
        )
        self.assertFalse(
            network == network.address,
            msg="Ip6Network must not compare equal to its Ip6Address component.",
        )
        self.assertFalse(
            network == network.mask,
            msg="Ip6Network must not compare equal to its Ip6Mask component.",
        )
        self.assertFalse(
            network == Ip6IfAddr("2001:db8::1/64"),
            msg="Ip6Network must not compare equal to an Ip6IfAddr.",
        )
        self.assertFalse(
            network == 0x20010DB8_00000000_00000000_00000000,
            msg="Ip6Network must not compare equal to an integer.",
        )
        self.assertFalse(
            network == None,  # noqa: E711
            msg="Ip6Network must not compare equal to None.",
        )

    def test__net_addr__ip6_network__ne(self) -> None:
        """
        Ensure the IPv6 network '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        network = Ip6Network("2001:db8::/64")
        self.assertTrue(
            network != Ip6Network("2001:db9::/64"),
            msg="Ip6Network instances with different network addresses must be unequal.",
        )
        self.assertTrue(
            network != Ip6Network("2001:db8::/96"),
            msg="Ip6Network instances with different masks must be unequal.",
        )
        self.assertFalse(
            network != Ip6Network("2001:db8::/64"),
            msg="Ip6Network instances with matching address and mask must not be unequal.",
        )
        self.assertTrue(
            network != "2001:db8::/64",
            msg="Ip6Network must be unequal to its string representation.",
        )


class TestNetAddrIp6NetworkHashConsistency(TestCase):
    """
    The NetAddr IPv6 network hash consistency tests.
    """

    def test__net_addr__ip6_network__hash__distinct_instances(self) -> None:
        """
        Ensure two independently constructed equal networks hash identically.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Network("2001:db8::abcd/64")
        b = Ip6Network((Ip6Address("2001:db8::1234"), Ip6Mask("/64")))

        self.assertEqual(
            a,
            b,
            msg="Ip6Network built from CIDR string and (address, mask) tuple must compare equal.",
        )
        self.assertEqual(
            hash(a),
            hash(b),
            msg="Equal Ip6Network values must hash to the same value across constructor forms.",
        )

    def test__net_addr__ip6_network__usable_in_set(self) -> None:
        """
        Ensure equal IPv6 networks collapse into a single element when
        used in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Network("2001:db8::/64")
        b = Ip6Network((Ip6Address("2001:db8::abcd"), Ip6Mask("/64")))
        c = Ip6Network("2001:db9::/64")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip6Network values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip6Network values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip6Network values as the same key.",
        )

    def test__net_addr__ip6_network__usable_in_dict(self) -> None:
        """
        Ensure equal IPv6 networks refer to the same dict entry regardless
        of which constructor form was used to build the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Network("2001:db8::/64")
        b = Ip6Network((Ip6Address("2001:db8::abcd"), Ip6Mask("/64")))

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip6Network must behave consistently as a dict key across input forms.",
        )


class TestNetAddrIp6NetworkRoundtrip(TestCase):
    """
    The NetAddr IPv6 network string roundtrip tests.
    """

    def test__net_addr__ip6_network__roundtrip__str(self) -> None:
        """
        Ensure 'Ip6Network(str(x))' yields a network equal to 'x'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in (
            "::/0",
            "2001::/16",
            "2001:db8::/32",
            "2001:db8::/64",
            "2001:db8::1/128",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
        ):
            with self.subTest(spec=spec):
                network = Ip6Network(spec)
                self.assertEqual(
                    Ip6Network(str(network)),
                    network,
                    msg=f"Roundtrip through str() must preserve network {spec!r}.",
                )

    def test__net_addr__ip6_network__roundtrip__copy(self) -> None:
        """
        Ensure constructing an Ip6Network from another Ip6Network yields
        an equal network with the same hash.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = Ip6Network("2001:db8::abcd/64")
        clone = Ip6Network(source)

        self.assertEqual(
            clone,
            source,
            msg="Copy-constructed Ip6Network must compare equal to the source.",
        )
        self.assertEqual(
            hash(clone),
            hash(source),
            msg="Copy-constructed Ip6Network must share the source's hash.",
        )
        self.assertEqual(
            clone.address,
            source.address,
            msg="Copy-constructed Ip6Network must preserve the network address.",
        )
        self.assertEqual(
            clone.mask,
            source.mask,
            msg="Copy-constructed Ip6Network must preserve the mask.",
        )


@parameterized_class(
    [
        {
            "_description": "Ip6Network 2001:db8::/126 (4 addresses, 3 hosts).",
            "_network": "2001:db8::/126",
            "_results": {
                "num_addresses": 4,
                "iter": ["2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"],
                "hosts": ["2001:db8::1", "2001:db8::2", "2001:db8::3"],
                "supernet": "2001:db8::/125",
                "subnets": ["2001:db8::/127", "2001:db8::2/127"],
            },
        },
        {
            "_description": "Ip6Network 2001:db8::/127 (point-to-point).",
            "_network": "2001:db8::/127",
            "_results": {
                "num_addresses": 2,
                "iter": ["2001:db8::", "2001:db8::1"],
                "hosts": ["2001:db8::", "2001:db8::1"],
                "supernet": "2001:db8::/126",
                "subnets": ["2001:db8::/128", "2001:db8::1/128"],
            },
        },
        {
            "_description": "Ip6Network 2001:db8::5/128 (single host).",
            "_network": "2001:db8::5/128",
            "_results": {
                "num_addresses": 1,
                "iter": ["2001:db8::5"],
                "hosts": ["2001:db8::5"],
                "supernet": "2001:db8::4/127",
                "subnets": ["2001:db8::5/128"],
            },
        },
    ]
)
class TestNetAddrIp6NetworkEnumeration(TestCase):
    """
    The NetAddr IPv6 network enumeration / subnetting tests.
    """

    _description: str
    _network: str
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the network under test from its CIDR string.
        """

        self._net = Ip6Network(self._network)

    def test__net_addr__ip6_network__num_addresses(self) -> None:
        """
        Ensure 'num_addresses' counts every address in the
        block, network address inclusive.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._net.num_addresses,
            self._results["num_addresses"],
            msg=f"Unexpected num_addresses for case: {self._description}",
        )

    def test__net_addr__ip6_network__iter(self) -> None:
        """
        Ensure iterating the network yields every address from
        the network address through the last address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            [str(address) for address in self._net],
            self._results["iter"],
            msg=f"Unexpected iteration for case: {self._description}",
        )

    def test__net_addr__ip6_network__hosts(self) -> None:
        """
        Ensure 'hosts' excludes only the Subnet-Router anycast
        (network) address — IPv6 has no broadcast — while /127
        and /128 yield every address.

        Reference: RFC 4291 (IP Version 6 Addressing Architecture).
        """

        self.assertEqual(
            [str(address) for address in self._net.hosts()],
            self._results["hosts"],
            msg=f"Unexpected hosts for case: {self._description}",
        )

    def test__net_addr__ip6_network__supernet(self) -> None:
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

    def test__net_addr__ip6_network__subnets(self) -> None:
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


class TestNetAddrIp6NetworkRelations(TestCase):
    """
    The NetAddr IPv6 network containment / overlap tests.
    """

    def test__net_addr__ip6_network__relations(self) -> None:
        """
        Ensure overlaps / subnet_of / supernet_of report
        containment correctly, including the disjoint and
        cross-version cases.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        outer = Ip6Network("2001:db8::/32")
        inner = Ip6Network("2001:db8:1::/48")
        other = Ip6Network("2001:dead::/32")

        for label, actual, expected in [
            ("outer overlaps inner", outer.overlaps(inner), True),
            ("outer overlaps other", outer.overlaps(other), False),
            ("inner subnet_of outer", inner.subnet_of(outer), True),
            ("outer supernet_of inner", outer.supernet_of(inner), True),
            ("cross-version overlaps", outer.overlaps(Ip4Network("0.0.0.0/0")), False),
            # Single-address overlap exactly at a block edge: the /128
            # sits on the last address of the /126. Pins both
            # 'self.address <= other.last' and 'other.address <=
            # self.last' at the boundary (a strict '<' would miss it).
            ("edge /128 overlaps /126", Ip6Network("2001:db8::3/128").overlaps(Ip6Network("2001:db8::/126")), True),
            ("edge /126 overlaps /128", Ip6Network("2001:db8::/126").overlaps(Ip6Network("2001:db8::3/128")), True),
            (
                "adjacent /128 disjoint /126",
                Ip6Network("2001:db8::4/128").overlaps(Ip6Network("2001:db8::/126")),
                False,
            ),
        ]:
            with self.subTest(relation=label):
                self.assertEqual(
                    actual,
                    expected,
                    msg=f"Unexpected result for: {label}",
                )


class TestNetAddrIp6NetworkOrdering(TestCase):
    """
    The NetAddr IPv6 network ordering tests.
    """

    def test__net_addr__ip6_network__ordering(self) -> None:
        """
        Ensure IPv6 networks are totally ordered by network
        address then prefix length.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6Network("2001:db8::/32")
        b = Ip6Network("2001:db8::/48")
        c = Ip6Network("2001:dead::/32")

        self.assertEqual(
            sorted([c, b, a]),
            [a, b, c],
            msg="Ip6Network must sort by (network address, prefix length).",
        )
        self.assertTrue(a < b < c, msg="Chained Ip6Network ordering must hold.")
        self.assertEqual(max(c, b, a), c, msg="max() must return the highest Ip6Network.")

    def test__net_addr__ip6_network__ordering__total_order_relations(self) -> None:
        """
        Ensure every ordering operator is pinned in both directions
        and reflexively, including the prefix-length tiebreak between
        two networks that share a network address — so a flipped or
        weakened comparison in any of '<', '<=', '>', '>=' is caught.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Same network address, different prefix length: the shorter
        # prefix (/32) sorts before the longer (/48) via the mask
        # tiebreak.
        a = Ip6Network("2001:db8::/32")
        b = Ip6Network("2001:db8::/48")

        # '<' — true direction, false direction, irreflexive.
        self.assertLess(a, b, msg="Same network, shorter prefix must be strictly less.")
        self.assertFalse(b < a, msg="'<' must be False in the reverse direction.")
        self.assertFalse(a < a, msg="'<' must be irreflexive.")

        # '<=' — true direction, false direction, reflexive.
        self.assertLessEqual(a, b, msg="'<=' must hold in the forward direction.")
        self.assertFalse(b <= a, msg="'<=' must be False in the reverse direction.")
        self.assertLessEqual(a, a, msg="'<=' must be reflexive.")

        # '>' — true direction, false direction, irreflexive.
        self.assertGreater(b, a, msg="Same network, longer prefix must be strictly greater.")
        self.assertFalse(a > b, msg="'>' must be False in the reverse direction.")
        self.assertFalse(a > a, msg="'>' must be irreflexive.")

        # '>=' — true direction, false direction, reflexive.
        self.assertGreaterEqual(b, a, msg="'>=' must hold in the forward direction.")
        self.assertFalse(a >= b, msg="'>=' must be False in the reverse direction.")
        self.assertGreaterEqual(a, a, msg="'>=' must be reflexive.")

    def test__net_addr__ip6_network__ordering__cross_version_raises(self) -> None:
        """
        Ensure ordering an IPv6 network against an IPv4 network
        raises TypeError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError, msg="Ip6Network < Ip4Network must raise TypeError."):
            _ = Ip6Network("2001:db8::/32") < Ip4Network("10.0.0.0/8")


@parameterized_class(
    [
        {
            "_description": "Ip6Network 2001:db8::/32",
            "_network": "2001:db8::/32",
            "_results": {
                "hostmask": Ip6Wildcard("::ffff:ffff:ffff:ffff:ffff:ffff"),
                "with_prefixlen": "2001:db8::/32",
                "with_netmask": "2001:db8::/ffff:ffff::",
                "with_hostmask": "2001:db8::/::ffff:ffff:ffff:ffff:ffff:ffff",
            },
        },
        {
            "_description": "Ip6Network ::/0",
            "_network": "::/0",
            "_results": {
                "hostmask": Ip6Wildcard("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                "with_prefixlen": "::/0",
                "with_netmask": "::/::",
                "with_hostmask": "::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            },
        },
        {
            "_description": "Ip6Network 2001:db8::5/128",
            "_network": "2001:db8::5/128",
            "_results": {
                "hostmask": Ip6Wildcard("::"),
                "with_prefixlen": "2001:db8::5/128",
                "with_netmask": "2001:db8::5/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "with_hostmask": "2001:db8::5/::",
            },
        },
    ]
)
class TestNetAddrIp6NetworkWithForms(TestCase):
    """
    The NetAddr IPv6 network hostmask / with_* representation tests.
    """

    _description: str
    _network: str
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the network under test from its CIDR string.
        """

        self._net = Ip6Network(self._network)

    def test__net_addr__ip6_network__hostmask(self) -> None:
        """
        Ensure 'hostmask' is the inverted-netmask Ip6Wildcard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._net.hostmask,
            Ip6Wildcard,
            msg=f"hostmask must be an Ip6Wildcard for case: {self._description}",
        )
        self.assertEqual(
            self._net.hostmask,
            self._results["hostmask"],
            msg=f"Unexpected hostmask for case: {self._description}",
        )

    def test__net_addr__ip6_network__format(self) -> None:
        """
        Ensure __format__ renders the pl / nm / hm notations;
        the default and 'pl' equal str(); an unknown spec
        raises Ip6NetworkSanityError.

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

        # A spec ending in 's' routes through Python's str formatting
        # for width / alignment, applied to the default (prefixlen)
        # rendering. A multi-character width spec also pins that only
        # the final character selects this branch (not the whole spec
        # or a wrong slice position).
        for spec in ("s", ">20s", "<20s", "^18s"):
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(self._net, spec),
                    format(self._results["with_prefixlen"], spec),
                    msg=f"Width/alignment spec {spec!r} must format the prefixlen string for: {self._description}",
                )

        # Unknown specs must raise the sanity error — including ones
        # whose final character sorts at or below 's' (e.g. 'zq'), which
        # a '<='-relaxation of the width-branch test ('[-1:] == "s"')
        # would mis-route to str formatting (leaking a ValueError).
        for spec in ("zz", "zq", "qa"):
            with self.subTest(spec=spec):
                with self.assertRaises(
                    Ip6NetworkSanityError,
                    msg=f"Unknown format spec {spec!r} must raise Ip6NetworkSanityError.",
                ):
                    format(self._net, spec)


class TestNetAddrIp6NetworkPrefixlen(TestCase):
    """
    The NetAddr IPv6 network prefixlen / max_prefixlen tests.
    """

    def test__net_addr__ip6_network__prefixlen(self) -> None:
        """
        Ensure 'prefixlen' is the mask prefix length and
        'max_prefixlen' is 128.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for cidr, prefixlen in [("::/0", 0), ("2001:db8::/32", 32), ("2001:db8::5/128", 128)]:
            with self.subTest(network=cidr):
                net = Ip6Network(cidr)
                self.assertEqual(net.prefixlen, prefixlen, msg=f"Unexpected prefixlen for {cidr}.")
                self.assertEqual(net.max_prefixlen, 128, msg=f"max_prefixlen must be 128 for {cidr}.")


class TestNetAddrIp6NetworkGetitem(TestCase):
    """
    The NetAddr IPv6 network indexing tests.
    """

    def test__net_addr__ip6_network__getitem(self) -> None:
        """
        Ensure 'network[i]' returns the i-th address (negative
        indexes count from the last address); out-of-range
        raises Ip6NetworkSanityError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        net = Ip6Network("2001:db8::/126")
        for index, expected in [
            (0, Ip6Address("2001:db8::")),
            (3, Ip6Address("2001:db8::3")),
            (-1, Ip6Address("2001:db8::3")),
            (-4, Ip6Address("2001:db8::")),
        ]:
            with self.subTest(index=index):
                self.assertEqual(net[index], expected, msg=f"net[{index}] must be {expected}.")

        # 4 == count (the first invalid index); 5 / 100 are strictly
        # past the end so a '<'-vs-'!='/'is not' weakening of the upper
        # bound is caught.
        for bad in (4, 5, 100, -5):
            with self.subTest(index=bad):
                with self.assertRaises(Ip6NetworkSanityError, msg=f"net[{bad}] must raise Ip6NetworkSanityError."):
                    _ = net[bad]


class TestNetAddrIp6NetworkNumAddressesEdge(TestCase):
    """
    The NetAddr IPv6 network num_addresses default-route edge test.
    """

    def test__net_addr__ip6_network__num_addresses__default_route(self) -> None:
        """
        Ensure 'num_addresses' counts the whole IPv6 space for the
        ::/0 default route, where the network address is 0 — pinning
        the subtraction form against a modulo (which would divide by
        the zero network address).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            Ip6Network("::/0").num_addresses,
            2**128,
            msg="num_addresses of ::/0 must be the full 2**128 address space.",
        )

    def test__net_addr__ip6_network__subnetting_arg_boundaries(self) -> None:
        """
        Ensure the subnets / supernet prefix-length boundary
        arguments raise or succeed exactly at the equal / one-step
        edges — a subnet must be strictly longer, a supernet strictly
        shorter, and a positive prefixlen_diff greater than one is
        honoured.

        Reference: RFC 4632 (Classless Inter-domain Routing).
        """

        net = Ip6Network("2001:db8::/48")
        with self.assertRaises(Ip6NetworkSanityError, msg="subnets(new_prefix == prefixlen) must raise."):
            list(net.subnets(new_prefix=48))
        with self.assertRaises(Ip6NetworkSanityError, msg="supernet(new_prefix == prefixlen) must raise."):
            net.supernet(new_prefix=48)
        with self.assertRaises(Ip6NetworkSanityError, msg="supernet(new_prefix > prefixlen) must raise."):
            net.supernet(new_prefix=64)
        self.assertEqual(
            [str(s) for s in Ip6Network("2001:db8::/48").subnets(prefixlen_diff=2)],
            ["2001:db8::/50", "2001:db8:0:4000::/50", "2001:db8:0:8000::/50", "2001:db8:0:c000::/50"],
            msg="subnets(prefixlen_diff=2) must tile a /48 into four /50 blocks.",
        )


class TestNetAddrIp6NetworkAddressExclude(TestCase):
    """
    The NetAddr IPv6 network address_exclude tests.
    """

    def test__net_addr__ip6_network__address_exclude(self) -> None:
        """
        Ensure 'address_exclude' returns the minimal aggregate
        CIDRs covering self minus other; an equal operand
        yields nothing.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        n = Ip6Network("2001:db8::/32")
        self.assertEqual(
            [str(x) for x in n.address_exclude(Ip6Network("2001:db8:8000::/33"))],
            ["2001:db8::/33"],
            msg="Excluding the upper /33 must yield the lower /33.",
        )
        self.assertEqual(
            list(n.address_exclude(Ip6Network("2001:db8::/32"))),
            [],
            msg="Excluding self must yield nothing.",
        )
        with self.assertRaises(Ip6NetworkSanityError, msg="A non-contained operand must raise Ip6NetworkSanityError."):
            list(n.address_exclude(Ip6Network("2001:dead::/32")))

    def test__net_addr__ip6_network__address_exclude__single_address_only_raises_netaddrerror(self) -> None:
        """
        Ensure 'address_exclude' on a single-address (/128)
        network only ever escapes a NetAddrError subclass: an
        equal operand yields nothing and a non-contained operand
        raises Ip6NetworkSanityError, never a bare ValueError
        from the internal subnet split.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        n = Ip6Network("2001:db8::1/128")
        self.assertEqual(
            list(n.address_exclude(Ip6Network("2001:db8::1/128"))),
            [],
            msg="Excluding a /128 from itself must yield nothing.",
        )
        with self.assertRaises(
            Ip6NetworkSanityError,
            msg="A non-contained operand against a /128 must raise Ip6NetworkSanityError, never ValueError.",
        ):
            list(n.address_exclude(Ip6Network("2001:db8::/32")))


class TestNetAddrIp6NetworkSummarize(TestCase):
    """
    The NetAddr IPv6 IpNetwork.summarize prefix-aggregation tests.
    """

    def test__net_addr__ip6_network__summarize(self) -> None:
        """
        Ensure 'summarize' aggregates a set of addresses and
        networks into the minimal covering CIDR set — adjacent
        and overlapping entries merged, gaps preserved.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        cases: list[tuple[list[Ip6Address | Ip6Network], list[str]]] = [
            ([Ip6Network("2001:db8::/64"), Ip6Network("2001:db8:0:1::/64")], ["2001:db8::/63"]),
            (
                [
                    Ip6Address("2001:db8::"),
                    Ip6Address("2001:db8::1"),
                    Ip6Address("2001:db8::2"),
                    Ip6Address("2001:db8::3"),
                ],
                ["2001:db8::/126"],
            ),
            ([Ip6Network("2001:db8::/64"), Ip6Network("2001:db8:0:2::/64")], ["2001:db8::/64", "2001:db8:0:2::/64"]),
            # Greedy multi-CIDR descent: a non-aligned, non-power-of-two
            # range forces _summarize_ints to emit decreasing-size
            # blocks, exercising both the align-limited and span-limited
            # min() branches.
            (
                [Ip6Address(f"2001:db8::{nibble}") for nibble in range(1, 7)],
                ["2001:db8::1/128", "2001:db8::2/127", "2001:db8::4/127", "2001:db8::6/128"],
            ),
            # A range starting at 2001:db8:: exercises the 'lo == 0'
            # alignment branch (align := bits) relative to the merged
            # span origin.
            (
                [Ip6Address(f"2001:db8::{nibble}") for nibble in range(0, 7)],
                ["2001:db8::/126", "2001:db8::4/127", "2001:db8::6/128"],
            ),
            # A one-address GAP (::1 missing) must NOT merge — pins the
            # '+ 1' adjacency tolerance in _merge_spans against widening.
            (
                [Ip6Address("2001:db8::"), Ip6Address("2001:db8::2")],
                ["2001:db8::/128", "2001:db8::2/128"],
            ),
            # A block contained in the MIDDLE of a wider one (a /90 not
            # at the /64's start) must keep the wider span — pins the
            # 'max(prev_hi, hi)' merge against collapsing to the
            # narrower contained endpoint (a contained-at-start block
            # would let 'hi' dominate and hide the bug).
            (
                [Ip6Network("2001:db8::/64"), Ip6Network("2001:db8::40:0:0:0/90")],
                ["2001:db8::/64"],
            ),
            # A separate block, a gap, then two adjacent-and-alignable
            # blocks that merge into a wider aggregate (/63). With the
            # earlier block already in the merged list, this pins the
            # merge against the LAST span ('merged[-1]') rather than the
            # first — and the /63 only forms if the merge happens at all.
            (
                [Ip6Network("2001:db8::/64"), Ip6Network("2001:db8:0:2::/64"), Ip6Network("2001:db8:0:3::/64")],
                ["2001:db8::/64", "2001:db8:0:2::/63"],
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

    def test__net_addr__ip6_network__summarize_mixed_version_raises(self) -> None:
        """
        Ensure 'summarize' raises 'IpNetworkSanityError' on a
        mixed-version input set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mixed = [Ip6Network("2001:db8::/64"), Ip4Network("10.0.0.0/24")]
        with self.assertRaises(IpNetworkSanityError):
            list(IpNetwork.summarize(mixed))  # type: ignore[arg-type]


class TestNetAddrIp6NetworkStrict(TestCase):
    """
    The NetAddr Ip6Network strict-mode constructor tests.
    """

    def test__net_addr__ip6_network__strict_clean_ok(self) -> None:
        """
        Ensure a network whose address has no host bits set
        constructs normally under strict=True.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        self.assertEqual(
            Ip6Network("2001:db8::/64", strict=True),
            Ip6Network("2001:db8::/64"),
            msg="A host-bit-free CIDR must construct under strict.",
        )
        self.assertEqual(
            Ip6Network((Ip6Address("2001:db8::"), Ip6Mask("/64")), strict=True),
            Ip6Network("2001:db8::/64"),
            msg="A host-bit-free tuple must construct under strict.",
        )

    def test__net_addr__ip6_network__strict_host_bits_raise(self) -> None:
        """
        Ensure strict=True rejects an address carrying bits
        outside the mask (string and tuple forms).

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        with self.assertRaises(Ip6NetworkFormatError):
            Ip6Network("2001:db8::1/64", strict=True)
        with self.assertRaises(Ip6NetworkFormatError):
            Ip6Network((Ip6Address("2001:db8::1"), Ip6Mask("/64")), strict=True)

    def test__net_addr__ip6_network__default_masks(self) -> None:
        """
        Ensure the default (strict=False) still silently masks
        host bits, preserving the existing constructor contract.

        Reference: RFC 4632 §3.1 (CIDR address/prefix).
        """

        self.assertEqual(
            Ip6Network("2001:db8::1/64"),
            Ip6Network("2001:db8::/64"),
            msg="Default construction must keep masking host bits.",
        )


class TestNetAddrIp6NetworkWhitespace(TestCase):
    """
    The NetAddr Ip6Network surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip6_network__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("2001:db8::/64",):
            expected = Ip6Network(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip6Network(wrapped),
                        expected,
                        msg=f"Ip6Network({wrapped!r}) must equal Ip6Network({value!r}).",
                    )


class TestNetAddrIp6NetworkStdlibParity(TestCase):
    """
    The NetAddr Ip6Network stdlib-ipaddress parity tests.
    """

    def test__net_addr__ip6_network__bare_address_is_host_route(self) -> None:
        """
        Ensure a prefix-less address parses as a /128 host route.

        Reference: PyTCP test infrastructure (stdlib ipaddress parity, no RFC clause).
        """

        net = Ip6Network("2001:db8::1")
        self.assertEqual(str(net), "2001:db8::1/128", msg="A bare address must parse as /128.")
        self.assertEqual(net.address, Ip6Address("2001:db8::1"), msg="The host address must be preserved.")
        self.assertEqual(int(net.mask), (1 << 128) - 1, msg="The mask must be /128.")


class TestNetAddrIp6NetworkCauseChain(TestCase):
    """
    The NetAddr IPv6 network error-cause-chain tests.
    """

    def test__net_addr__ip6_network__string_reject_preserves_cause(self) -> None:
        """
        Ensure a malformed network string raises
        Ip6NetworkFormatError that preserves the swallowed
        sub-constructor failure as '__cause__', so a traceback
        shows which token (address vs mask) was rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for bad, cause in [
            ("2001:db8::zzzz/64", Ip6AddressFormatError),
            ("2001:db8::1/999", Ip6MaskFormatError),
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(Ip6NetworkFormatError) as ctx:
                    Ip6Network(bad)
                self.assertIsInstance(
                    ctx.exception.__cause__,
                    cause,
                    msg=f"The swallowed {cause.__name__} must be preserved as __cause__ for {bad!r}.",
                )
