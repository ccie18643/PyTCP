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
This module contains tests for the NetAddr package IPv4 host support class.

net_addr/tests/unit/test__ip4_ifaddr.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip4IfAddr,
    Ip4IfAddrFormatError,
    Ip4IfAddrSanityError,
    Ip4Mask,
    Ip4Network,
    Ip4NetworkFormatError,
    Ip6IfAddr,
    IpVersion,
)
from net_addr.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (str)",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4IfAddr('192.168.1.100/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4IfAddr)",
            "_args": [
                Ip4IfAddr("192.168.1.100/24"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4IfAddr('192.168.1.100/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100 255.255.255.0 (str, space netmask form)",
            "_args": [
                "192.168.1.100 255.255.255.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4IfAddr('192.168.1.100/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Address, Ip4Mask)",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Mask("255.255.255.0")),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4IfAddr('192.168.1.100/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Address, Ip4Network)",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Network("192.168.1.0/24")),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4IfAddr('192.168.1.100/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
            },
        },
    ]
)
class TestNetAddrIp4Host(TestCase):
    """
    The NetAddr IPv4 Host tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the IPv4 host object with testcase arguments.
        """

        self._ip4_ifaddr = Ip4IfAddr(*self._args, **self._kwargs)

    def test__net_addr__ip4_host__str(self) -> None:
        """
        Ensure the IPv4 host '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip4_ifaddr),
            self._results["__str__"],
        )

    def test__net_addr__ip4_host__repr(self) -> None:
        """
        Ensure the IPv4 host '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip4_ifaddr),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_host__eq(self) -> None:
        """
        Ensure the IPv4 host '__eq__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._ip4_ifaddr == self._ip4_ifaddr,
            msg="An Ip4IfAddr instance must compare equal to itself.",
        )

        self.assertTrue(
            self._ip4_ifaddr == Ip4IfAddr(str(self._ip4_ifaddr)),
            msg="Ip4IfAddr must compare equal to one reconstructed from its string representation.",
        )

        self.assertFalse(
            self._ip4_ifaddr == "not an IPv4 host",
            msg="Ip4IfAddr must not compare equal to a foreign string value.",
        )

        self.assertFalse(
            self._ip4_ifaddr == None,  # noqa: E711
            msg="Ip4IfAddr must not compare equal to None.",
        )

        self.assertFalse(
            self._ip4_ifaddr
            == Ip4IfAddr(
                (
                    Ip4Address((int(self._ip4_ifaddr.address) ^ 0x01) & 0xFF_FF_FF_FF),
                    self._ip4_ifaddr.network,
                ),
            ),
            msg="Ip4IfAddr instances with different addresses must not compare equal.",
        )

        self.assertFalse(
            self._ip4_ifaddr
            == Ip4IfAddr(
                (
                    self._ip4_ifaddr.address,
                    Ip4Mask(f"/{(len(self._ip4_ifaddr.network.mask) + 1) % 33}"),
                ),
            ),
            msg="Ip4IfAddr instances with different networks must not compare equal.",
        )

    def test__net_addr__ip4_host__version(self) -> None:
        """
        Ensure the IPv4 host 'version' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.version,
            self._results["version"],
        )

    def test__net_addr__ip4_host__is_ip4(self) -> None:
        """
        Ensure the IPv4 host 'is_ip4' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_host__is_ip6(self) -> None:
        """
        Ensure the IPv4 host 'is_ip6' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_host__address(self) -> None:
        """
        Ensure the IPv4 host 'address' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.address,
            self._results["address"],
        )

    def test__net_addr__ip4_host__network(self) -> None:
        """
        Ensure the IPv4 host 'network' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.network,
            self._results["network"],
        )


class TestNetAddrIp4HostSemantics(TestCase):
    """
    The NetAddr IPv4 host semantic tests not tied to a parameterized matrix.
    """

    def test__net_addr__ip4_host__eq__ignores_metadata(self) -> None:
        """
        Ensure '__eq__()' compares only address and network.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        plain = Ip4IfAddr("192.168.1.100/24")
        other = Ip4IfAddr((Ip4Address("192.168.1.100"), Ip4Mask("/24")))

        self.assertEqual(
            plain,
            other,
            msg="Ip4IfAddr equality must compare only address and network.",
        )
        self.assertEqual(
            hash(plain),
            hash(other),
            msg="Equal Ip4IfAddr values must hash to the same value.",
        )

    def test__net_addr__ip4_host__eq__cross_version(self) -> None:
        """
        Ensure '__eq__()' returns False when compared to an Ip6IfAddr.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            Ip4IfAddr("192.168.1.100/24"),
            Ip6IfAddr("2001:db8::c0a8:164/64"),
            msg="Ip4IfAddr must not compare equal to an Ip6IfAddr.",
        )

    def test__net_addr__ip4_host__eq__foreign_types(self) -> None:
        """
        Ensure the IPv4 host is never equal to a value of a foreign type,
        including its own component pieces.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip4IfAddr("192.168.1.100/24")

        self.assertFalse(
            host == "192.168.1.100/24",
            msg="Ip4IfAddr must not compare equal to its string representation.",
        )
        self.assertFalse(
            host == host.address,
            msg="Ip4IfAddr must not compare equal to its Ip4Address component.",
        )
        self.assertFalse(
            host == host.network,
            msg="Ip4IfAddr must not compare equal to its Ip4Network component.",
        )
        self.assertFalse(
            host == 0,
            msg="Ip4IfAddr must not compare equal to an integer.",
        )

    def test__net_addr__ip4_host__ne(self) -> None:
        """
        Ensure the IPv4 host '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip4IfAddr("192.168.1.100/24")
        self.assertTrue(
            host != Ip4IfAddr("192.168.1.101/24"),
            msg="Ip4IfAddr instances with different addresses must be unequal.",
        )
        self.assertFalse(
            host != Ip4IfAddr("192.168.1.100/24"),
            msg="Ip4IfAddr instances with the same address and network must not be unequal.",
        )
        self.assertTrue(
            host != "192.168.1.100/24",
            msg="Ip4IfAddr must be unequal to its string representation.",
        )

    def test__net_addr__ip4_host__hash__distinct_instances(self) -> None:
        """
        Ensure two independently constructed equal hosts hash identically.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("192.168.1.100/24")
        b = Ip4IfAddr((Ip4Address("192.168.1.100"), Ip4Mask("/24")))
        self.assertEqual(
            a,
            b,
            msg="Ip4IfAddr built from string and from (address, mask) tuple must compare equal.",
        )
        self.assertEqual(
            hash(a),
            hash(b),
            msg="Equal Ip4IfAddr values must hash to the same value across constructor forms.",
        )

    def test__net_addr__ip4_host__usable_in_set(self) -> None:
        """
        Ensure equal IPv4 hosts collapse into a single element when used
        in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("192.168.1.100/24")
        b = Ip4IfAddr((Ip4Address("192.168.1.100"), Ip4Mask("/24")))
        c = Ip4IfAddr("192.168.1.101/24")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip4IfAddr values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip4IfAddr values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip4IfAddr values as the same key.",
        )

    def test__net_addr__ip4_host__usable_in_dict(self) -> None:
        """
        Ensure equal IPv4 hosts refer to the same dict entry regardless
        of which constructor form was used to build the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("192.168.1.100/24")
        b = Ip4IfAddr((Ip4Address("192.168.1.100"), Ip4Mask("/24")))

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip4IfAddr must behave consistently as a dict key across input forms.",
        )

    def test__net_addr__ip4_host__roundtrip__str(self) -> None:
        """
        Ensure 'Ip4IfAddr(str(x))' yields a host equal to 'x' (metadata-free).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in ("0.0.0.0/0", "10.0.0.1/8", "192.168.1.100/24", "255.255.255.254/31"):
            with self.subTest(spec=spec):
                host = Ip4IfAddr(spec)
                self.assertEqual(
                    Ip4IfAddr(str(host)),
                    host,
                    msg=f"Roundtrip through str() must preserve host {spec!r}.",
                )

    def test__net_addr__ip4_host__copy_preserves_fields(self) -> None:
        """
        Ensure copying an Ip4IfAddr preserves address and network.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = Ip4IfAddr("192.168.1.100/24")
        clone = Ip4IfAddr(source)

        self.assertEqual(
            clone.address,
            source.address,
            msg="Copying an Ip4IfAddr must preserve its address.",
        )
        self.assertEqual(
            clone.network,
            source.network,
            msg="Copying an Ip4IfAddr must preserve its network.",
        )


@parameterized_class(
    [
        {
            "_description": "Test Ip4IfAddrSanityError: address not in network.",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Network("192.168.2.0/24")),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrSanityError,
                "error_message": (
                    "The IPv4 address doesn't belong to the provided network: "
                    "(Ip4Address('192.168.1.100'), Ip4Network('192.168.2.0/24'))"
                ),
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: invalid input type.",
            "_args": [
                12345,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: 12345",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: invalid string format.",
            "_args": [
                "not-a-host",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: 'not-a-host'",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: string with extra slash.",
            "_args": [
                "192.168.1.0/24/extra",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: '192.168.1.0/24/extra'",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: None input.",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: None",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: maskless (Ip4Address, None) tuple is rejected.",
            "_args": [
                (Ip4Address("10.0.0.1"), None),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: (Ip4Address('10.0.0.1'), None)",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: string with out-of-range mask.",
            "_args": [
                "10.0.0.1/99",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: '10.0.0.1/99'",
            },
        },
    ]
)
class TestNetAddrIp4HostErrors(TestCase):
    """
    The NetAddr IPv4 host error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_host__errors(self) -> None:
        """
        Ensure the IPv4 host raises an error on invalid input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4IfAddr(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


class TestNetAddrIp4IfAddrFormat(TestCase):
    """
    The NetAddr IPv4 interface-address __format__ tests.
    """

    def test__net_addr__ip4_ifaddr__format(self) -> None:
        """
        Ensure __format__ renders the host address in the
        pl / nm / hm notations; default and 'pl' equal str();
        an unknown spec raises ValueError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("192.0.2.5/24")
        for spec, expected in [
            ("", "192.0.2.5/24"),
            ("pl", "192.0.2.5/24"),
            ("nm", "192.0.2.5/255.255.255.0"),
            ("hm", "192.0.2.5/0.0.0.255"),
        ]:
            with self.subTest(spec=spec):
                self.assertEqual(format(a, spec), expected, msg=f"format({spec!r}) must be {expected!r}.")

        self.assertEqual(f"{a}", "192.0.2.5/24", msg="Default format must equal str().")

        # A spec ending in 's' routes through Python's str formatting
        # for width / alignment, applied to the default rendering. A
        # multi-character width spec also pins that only the final
        # character selects this branch.
        for spec in ("s", ">20s", "<20s", "^18s"):
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(a, spec),
                    format("192.0.2.5/24", spec),
                    msg=f"Width/alignment spec {spec!r} must format the default rendering.",
                )

        # Unknown specs must raise the sanity error — including ones
        # whose final character sorts at or below 's' (e.g. 'zq'), which
        # a '<='-relaxation of the width-branch test ('[-1:] == "s"')
        # would mis-route to str formatting (leaking a ValueError).
        for spec in ("zz", "zq", "qa"):
            with self.subTest(spec=spec):
                with self.assertRaises(
                    Ip4IfAddrSanityError,
                    msg=f"Unknown format spec {spec!r} must raise Ip4IfAddrSanityError.",
                ):
                    format(a, spec)


class TestNetAddrIp4IfAddrWhitespace(TestCase):
    """
    The NetAddr Ip4IfAddr surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip4_ifaddr__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("10.0.0.7/24",):
            expected = Ip4IfAddr(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip4IfAddr(wrapped),
                        expected,
                        msg=f"Ip4IfAddr({wrapped!r}) must equal Ip4IfAddr({value!r}).",
                    )


class TestNetAddrIp4IfAddrStdlibParity(TestCase):
    """
    The NetAddr Ip4IfAddr stdlib-ipaddress parity tests.
    """

    def test__net_addr__ip4_ifaddr__bare_address_is_host(self) -> None:
        """
        Ensure a prefix-less address parses as a /32 interface
        address.

        Reference: PyTCP test infrastructure (stdlib ipaddress parity, no RFC clause).
        """

        ifaddr = Ip4IfAddr("10.0.0.5")
        self.assertEqual(str(ifaddr), "10.0.0.5/32", msg="A bare address must parse as /32.")

    def test__net_addr__ip4_ifaddr__dotted_netmask_form(self) -> None:
        """
        Ensure the 'address/d.d.d.d' dotted-netmask form parses.

        Reference: PyTCP test infrastructure (stdlib ipaddress parity, no RFC clause).
        """

        ifaddr = Ip4IfAddr("10.0.0.5/255.255.255.0")
        self.assertEqual(str(ifaddr), "10.0.0.5/24", msg="Dotted netmask must yield /24 with the host preserved.")


class TestNetAddrIp4IfAddrCauseChain(TestCase):
    """
    The NetAddr IPv4 interface-address error-cause-chain tests.
    """

    def test__net_addr__ip4_ifaddr__string_reject_preserves_cause(self) -> None:
        """
        Ensure a malformed interface-address string raises
        Ip4IfAddrFormatError that preserves the swallowed
        sub-constructor failure as '__cause__', so a traceback
        shows which token (address vs network) was rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for bad, cause in [
            ("999.0.0.1/24", Ip4AddressFormatError),
            ("10.0.0.1/99", Ip4NetworkFormatError),
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(Ip4IfAddrFormatError) as ctx:
                    Ip4IfAddr(bad)
                self.assertIsInstance(
                    ctx.exception.__cause__,
                    cause,
                    msg=f"The swallowed {cause.__name__} must be preserved as __cause__ for {bad!r}.",
                )


class TestNetAddrIp4IfAddrOrdering(TestCase):
    """
    The NetAddr IPv4 interface-address ordering tests.
    """

    def test__net_addr__ip4_ifaddr__ordering(self) -> None:
        """
        Ensure IPv4 interface addresses are totally ordered by
        host address then network (so they sort consistently
        with the sibling value types), matching equality.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("10.0.0.5/24")
        b = Ip4IfAddr("10.0.0.5/25")
        c = Ip4IfAddr("10.0.0.6/24")

        self.assertEqual(
            sorted([c, b, a]),
            [a, b, c],
            msg="Ip4IfAddr must sort by (host address, network).",
        )
        self.assertTrue(a < b, msg="Same host address, longer-prefix network must sort after.")
        self.assertTrue(b < c, msg="Lower host address must sort before.")
        self.assertLessEqual(a, a, msg="An interface address must be <= itself.")
        self.assertGreaterEqual(c, a, msg="A higher interface address must be >= a lower one.")
        self.assertEqual(min(c, b, a), a, msg="min() must return the lowest Ip4IfAddr.")

    def test__net_addr__ip4_ifaddr__ordering__total_order_relations(self) -> None:
        """
        Ensure every ordering operator is pinned in both directions
        and reflexively, including the network tiebreak between two
        interface addresses that share a host address, and that
        equality rejects a strictly-greater operand in either argument
        order — so a flipped or weakened comparison in '<', '<=', '>',
        '>=' or '==' is caught.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Same host address, different network: the /25 network sorts
        # after the /24 via the mask tiebreak.
        a = Ip4IfAddr("10.0.0.5/24")
        b = Ip4IfAddr("10.0.0.5/25")

        self.assertLess(a, b, msg="Same host, longer-prefix network must be strictly less.")
        self.assertFalse(b < a, msg="'<' must be False in the reverse direction.")
        self.assertFalse(a < a, msg="'<' must be irreflexive.")

        self.assertLessEqual(a, b, msg="'<=' must hold in the forward direction.")
        self.assertFalse(b <= a, msg="'<=' must be False in the reverse direction.")
        self.assertLessEqual(a, a, msg="'<=' must be reflexive.")

        self.assertGreater(b, a, msg="Same host, longer-prefix network must be strictly greater.")
        self.assertFalse(a > b, msg="'>' must be False in the reverse direction.")
        self.assertFalse(a > a, msg="'>' must be irreflexive.")

        self.assertGreaterEqual(b, a, msg="'>=' must hold in the forward direction.")
        self.assertFalse(a >= b, msg="'>=' must be False in the reverse direction.")
        self.assertGreaterEqual(a, a, msg="'>=' must be reflexive.")

        self.assertNotEqual(a, b, msg="Interface addresses differing only by network must not be equal.")
        self.assertNotEqual(b, a, msg="Inequality must hold with the greater interface address on the left.")

        # Different host address, same network: equality must reject it
        # in either argument order — pins the host-address comparison in
        # __eq__ (the network-only pair above leaves it unexercised).
        higher = Ip4IfAddr("10.0.0.6/24")
        self.assertNotEqual(higher, a, msg="A higher host address must not equal a lower one (greater on left).")
        self.assertNotEqual(a, higher, msg="A lower host address must not equal a higher one (lesser on left).")

    def test__net_addr__ip4_ifaddr__ordering__cross_version_raises(self) -> None:
        """
        Ensure ordering an IPv4 interface address against an
        IPv6 interface address raises TypeError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError, msg="Ip4IfAddr < Ip6IfAddr must raise TypeError."):
            _ = Ip4IfAddr("10.0.0.5/24") < Ip6IfAddr("2001:db8::5/64")
