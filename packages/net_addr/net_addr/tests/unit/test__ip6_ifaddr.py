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
This module contains tests for the NetAddr package IPv6 host support class.

net_addr/tests/unit/test__ip6_ifaddr.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import (
    Ip4IfAddr,
    Ip6Address,
    Ip6AddressFormatError,
    Ip6IfAddr,
    Ip6IfAddrFormatError,
    Ip6IfAddrSanityError,
    Ip6Mask,
    Ip6MaskFormatError,
    Ip6Network,
    IpVersion,
    MacAddress,
)
from net_addr.ip6_ifaddr import _is_reserved_iid
from net_addr.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (str)",
            "_args": [
                "2001:b:c:d:1:2:3:4/64",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6IfAddr('2001:b:c:d:1:2:3:4/64')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
            },
        },
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (Ip6IfAddr)",
            "_args": [
                Ip6IfAddr("2001:b:c:d:1:2:3:4/64"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6IfAddr('2001:b:c:d:1:2:3:4/64')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
            },
        },
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (Ip6Address, Ip6Mask)",
            "_args": [
                (Ip6Address("2001:b:c:d:1:2:3:4"), Ip6Mask("/64")),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6IfAddr('2001:b:c:d:1:2:3:4/64')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
            },
        },
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (Ip6Address, Ip6Network)",
            "_args": [
                (
                    Ip6Address("2001:b:c:d:1:2:3:4"),
                    Ip6Network("2001:b:c:d::/64"),
                ),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6IfAddr('2001:b:c:d:1:2:3:4/64')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
            },
        },
    ]
)
class TestNetAddrIp6Host(TestCase):
    """
    The NetAddr IPv6 Host tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the IPv6 host object with testcase arguments.
        """

        self._ip6_ifaddr = Ip6IfAddr(*self._args, **self._kwargs)

    def test__net_addr__ip6_host__str(self) -> None:
        """
        Ensure the IPv6 host '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip6_ifaddr),
            self._results["__str__"],
        )

    def test__net_addr__ip6_host__repr(self) -> None:
        """
        Ensure the IPv6 host '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip6_ifaddr),
            self._results["__repr__"],
        )

    def test__net_addr__ip6_host__eq(self) -> None:
        """
        Ensure the IPv6 host '__eq__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._ip6_ifaddr == self._ip6_ifaddr,
            msg="An Ip6IfAddr instance must compare equal to itself.",
        )

        self.assertTrue(
            self._ip6_ifaddr == Ip6IfAddr(str(self._ip6_ifaddr)),
            msg="Ip6IfAddr must compare equal to one reconstructed from its string representation.",
        )

        self.assertFalse(
            self._ip6_ifaddr == "not an IPv6 host",
            msg="Ip6IfAddr must not compare equal to a foreign string value.",
        )

        self.assertFalse(
            self._ip6_ifaddr == None,  # noqa: E711
            msg="Ip6IfAddr must not compare equal to None.",
        )

        self.assertFalse(
            self._ip6_ifaddr
            == Ip6IfAddr(
                (
                    Ip6Address((int(self._ip6_ifaddr.address) ^ 0x01) & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF),
                    self._ip6_ifaddr.network,
                ),
            ),
            msg="Ip6IfAddr instances with different addresses must not compare equal.",
        )

    def test__net_addr__ip6_host__version(self) -> None:
        """
        Ensure the IPv6 host 'version' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_ifaddr.version,
            self._results["version"],
        )

    def test__net_addr__ip6_host__is_ip4(self) -> None:
        """
        Ensure the IPv6 host 'is_ip4' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_ifaddr.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip6_host__is_ip6(self) -> None:
        """
        Ensure the IPv6 host 'is_ip6' property returns a correct
        value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_ifaddr.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip6_host__address(self) -> None:
        """
        Ensure the IPv6 host 'address' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_ifaddr.address,
            self._results["address"],
        )

    def test__net_addr__ip6_host__network(self) -> None:
        """
        Ensure the IPv6 host 'network' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip6_ifaddr.network,
            self._results["network"],
        )


class TestNetAddrIp6HostSemantics(TestCase):
    """
    The NetAddr IPv6 host semantic tests not tied to a parameterized matrix.
    """

    def test__net_addr__ip6_host__eq__ignores_metadata(self) -> None:
        """
        Ensure '__eq__()' compares only address and network.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        plain = Ip6IfAddr("2001:db8::1/64")
        other = Ip6IfAddr((Ip6Address("2001:db8::1"), Ip6Mask("/64")))

        self.assertEqual(
            plain,
            other,
            msg="Ip6IfAddr equality must compare only address and network.",
        )
        self.assertEqual(
            hash(plain),
            hash(other),
            msg="Equal Ip6IfAddr values must hash to the same value.",
        )

    def test__net_addr__ip6_host__eq__cross_version(self) -> None:
        """
        Ensure '__eq__()' returns False when compared to an Ip4IfAddr.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            Ip6IfAddr("2001:db8::c0a8:164/64"),
            Ip4IfAddr("192.168.1.100/24"),
            msg="Ip6IfAddr must not compare equal to an Ip4IfAddr.",
        )

    def test__net_addr__ip6_host__eq__foreign_types(self) -> None:
        """
        Ensure the IPv6 host is never equal to a value of a foreign type,
        including its own component pieces.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip6IfAddr("2001:db8::1/64")

        self.assertFalse(
            host == "2001:db8::1/64",
            msg="Ip6IfAddr must not compare equal to its string representation.",
        )
        self.assertFalse(
            host == host.address,
            msg="Ip6IfAddr must not compare equal to its Ip6Address component.",
        )
        self.assertFalse(
            host == host.network,
            msg="Ip6IfAddr must not compare equal to its Ip6Network component.",
        )
        self.assertFalse(
            host == 0,
            msg="Ip6IfAddr must not compare equal to an integer.",
        )

    def test__net_addr__ip6_host__ne(self) -> None:
        """
        Ensure the IPv6 host '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip6IfAddr("2001:db8::1/64")
        self.assertTrue(
            host != Ip6IfAddr("2001:db8::2/64"),
            msg="Ip6IfAddr instances with different addresses must be unequal.",
        )
        self.assertFalse(
            host != Ip6IfAddr("2001:db8::1/64"),
            msg="Ip6IfAddr instances with the same address and network must not be unequal.",
        )
        self.assertTrue(
            host != "2001:db8::1/64",
            msg="Ip6IfAddr must be unequal to its string representation.",
        )

    def test__net_addr__ip6_host__hash__distinct_instances(self) -> None:
        """
        Ensure two independently constructed equal hosts hash identically.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6IfAddr("2001:db8::1/64")
        b = Ip6IfAddr((Ip6Address("2001:db8::1"), Ip6Mask("/64")))
        self.assertEqual(
            a,
            b,
            msg="Ip6IfAddr built from string and (address, mask) tuple must compare equal.",
        )
        self.assertEqual(
            hash(a),
            hash(b),
            msg="Equal Ip6IfAddr values must hash to the same value across constructor forms.",
        )

    def test__net_addr__ip6_host__usable_in_set(self) -> None:
        """
        Ensure equal IPv6 hosts collapse into a single element when used
        in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6IfAddr("2001:db8::1/64")
        b = Ip6IfAddr((Ip6Address("2001:db8::1"), Ip6Mask("/64")))
        c = Ip6IfAddr("2001:db8::2/64")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip6IfAddr values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip6IfAddr values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip6IfAddr values as the same key.",
        )

    def test__net_addr__ip6_host__usable_in_dict(self) -> None:
        """
        Ensure equal IPv6 hosts refer to the same dict entry regardless
        of which constructor form was used to build the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6IfAddr("2001:db8::1/64")
        b = Ip6IfAddr((Ip6Address("2001:db8::1"), Ip6Mask("/64")))

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip6IfAddr must behave consistently as a dict key across input forms.",
        )

    def test__net_addr__ip6_host__roundtrip__str(self) -> None:
        """
        Ensure 'Ip6IfAddr(str(x))' yields a host equal to 'x' (metadata-free).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in ("::/0", "::1/128", "2001:db8::1/64", "fe80::1/10", "ff02::1/128"):
            with self.subTest(spec=spec):
                host = Ip6IfAddr(spec)
                self.assertEqual(
                    Ip6IfAddr(str(host)),
                    host,
                    msg=f"Roundtrip through str() must preserve host {spec!r}.",
                )

    def test__net_addr__ip6_host__copy_preserves_fields(self) -> None:
        """
        Ensure copying an Ip6IfAddr preserves address and network.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = Ip6IfAddr("2001:db8::1/64")
        clone = Ip6IfAddr(source)

        self.assertEqual(
            clone.address,
            source.address,
            msg="Copying an Ip6IfAddr must preserve its address.",
        )
        self.assertEqual(
            clone.network,
            source.network,
            msg="Copying an Ip6IfAddr must preserve its network.",
        )


class TestNetAddrIp6HostFromEui64(TestCase):
    """
    The NetAddr IPv6 host 'from_eui64()' classmethod tests.
    """

    def test__net_addr__ip6_host__from_eui64(self) -> None:
        """
        Ensure 'from_eui64()' builds a /64 host from a MAC and network.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip6IfAddr.from_eui64(
            mac_address=MacAddress("02:00:00:11:22:33"),
            ip6_network=Ip6Network("2001:db8::/64"),
        )

        self.assertEqual(
            host.network,
            Ip6Network("2001:db8::/64"),
            msg="EUI64 host must keep the source /64 network.",
        )
        self.assertEqual(
            host.address,
            Ip6Address("2001:db8::ff:fe11:2233"),
            msg="EUI64 address must flip the U/L bit and embed the MAC.",
        )

    def test__net_addr__ip6_host__from_eui64__non_degenerate(self) -> None:
        """
        Ensure 'from_eui64()' embeds every MAC octet and every prefix
        bit — a non-degenerate MAC (bits set in every octet) placed in
        a fully populated /64 so a corrupted netmask, U/L flip, or
        field placement changes the resulting address.

        Reference: RFC 4291 §2.5.1 (modified EUI-64 IIDs are 64 bits).
        """

        # aa:bb:cc:dd:ee:ff is the canonical EUI-64 vector: the U/L bit
        # flip turns the leading 0xaa into 0xa8 and 0xff:0xfe is inserted
        # between the two 24-bit MAC halves. The prefix uses all four
        # leading hextets so a corrupted /64 netmask is observable.
        self.assertEqual(
            Ip6IfAddr.from_eui64(
                mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
                ip6_network=Ip6Network("2001:db8:aaaa:bbbb::/64"),
            ).address,
            Ip6Address("2001:db8:aaaa:bbbb:a8bb:ccff:fedd:eeff"),
            msg="from_eui64() must flip the U/L bit, insert ff:fe, and keep the full /64 prefix.",
        )

        # A second vector with a different leading octet hardens the U/L
        # flip (0x12 -> 0x10) across a link-local prefix.
        self.assertEqual(
            Ip6IfAddr.from_eui64(
                mac_address=MacAddress("12:34:56:78:9a:bc"),
                ip6_network=Ip6Network("fe80::/64"),
            ).address,
            Ip6Address("fe80::1034:56ff:fe78:9abc"),
            msg="from_eui64() U/L flip must turn 0x12 into 0x10 and embed the MAC.",
        )

        # An all-ones top-64 prefix sets every prefix bit, so any
        # corruption of the /64 netmask (which masks exactly bits
        # 64-127) changes the result — closing the netmask-arithmetic
        # mutants a partially-populated prefix leaves unconstrained.
        self.assertEqual(
            Ip6IfAddr.from_eui64(
                mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
                ip6_network=Ip6Network("ffff:ffff:ffff:ffff::/64"),
            ).address,
            Ip6Address("ffff:ffff:ffff:ffff:a8bb:ccff:fedd:eeff"),
            msg="from_eui64() must preserve an all-ones /64 prefix exactly.",
        )

    def test__net_addr__ip6_host__from_eui64__non_64_mask_raises(self) -> None:
        """
        Ensure 'from_eui64()' rejects a network whose mask is not
        /64 with 'Ip6IfAddrSanityError' carrying a plain
        operation-precondition message.

        Reference: RFC 4291 §2.5.1 (modified EUI-64 IIDs are 64 bits).
        """

        with self.assertRaises(
            Ip6IfAddrSanityError,
            msg="from_eui64() must reject a network whose mask is not /64.",
        ) as error:
            Ip6IfAddr.from_eui64(
                mac_address=MacAddress("02:00:00:11:22:33"),
                ip6_network=Ip6Network("2001:db8::/48"),
            )

        self.assertEqual(
            str(error.exception),
            "network mask must be /64 for an EUI-64 IID; got /48",
            msg="from_eui64() must report the rejected mask length.",
        )


class TestNetAddrIp6HostFromRfc7217(TestCase):
    """
    The NetAddr IPv6 host 'from_rfc7217()' classmethod tests
    — cryptographic stable-opaque IIDs.
    """

    def test__net_addr__ip6_host__from_rfc7217__deterministic(self) -> None:
        """
        Ensure two calls with identical inputs produce the
        same address (the IID is a deterministic PRF output).

        Reference: RFC 7217 §5 (Algorithm Specification).
        """

        host_a = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )
        host_b = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )

        self.assertEqual(
            host_a.address,
            host_b.address,
            msg=f"Same inputs must produce the same RFC 7217 address. Got: {host_a!r} vs {host_b!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__different_prefix(self) -> None:
        """
        Ensure two different prefixes produce different IIDs —
        the design goal that prevents host correlation across
        networks.

        Reference: RFC 7217 §3 (design goals).
        """

        host_a = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8:0:1::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )
        host_b = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8:0:2::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )

        self.assertNotEqual(
            int(host_a.address) & ((1 << 64) - 1),
            int(host_b.address) & ((1 << 64) - 1),
            msg=(
                "Different prefixes must yield different IIDs "
                f"(unlinkability). Got IID(a)={int(host_a.address) & ((1 << 64) - 1):x}, "
                f"IID(b)={int(host_b.address) & ((1 << 64) - 1):x}"
            ),
        )

    def test__net_addr__ip6_host__from_rfc7217__different_mac(self) -> None:
        """
        Ensure different MAC addresses produce different IIDs.

        Reference: RFC 7217 §5 (Net_Iface in PRF input).
        """

        host_a = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )
        host_b = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:aa:bb:cc"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )

        self.assertNotEqual(
            host_a.address,
            host_b.address,
            msg=f"Different MACs must yield different addresses. Got: {host_a!r} vs {host_b!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__different_secret_key(self) -> None:
        """
        Ensure different secret keys produce different IIDs.

        Reference: RFC 7217 §5 (secret_key in PRF input).
        """

        host_a = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"first-128-bit-secret-key-bytes--",
        )
        host_b = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"second-128-bit-secret-key-bytes-",
        )

        self.assertNotEqual(
            host_a.address,
            host_b.address,
            msg=f"Different secret keys must yield different addresses. Got: {host_a!r} vs {host_b!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__dad_counter_changes_iid(self) -> None:
        """
        Ensure incrementing the DAD counter (which the host
        does on a DAD conflict) yields a different IID for the
        same {prefix, mac, secret_key} tuple.

        Reference: RFC 7217 §5 (DAD_Counter input + §6 conflict resolution).
        """

        host_0 = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
            dad_counter=0,
        )
        host_1 = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
            dad_counter=1,
        )

        self.assertNotEqual(
            host_0.address,
            host_1.address,
            msg=f"Different DAD counters must yield different IIDs. Got: {host_0!r} vs {host_1!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__golden_vector(self) -> None:
        """
        Ensure 'from_rfc7217' reproduces a byte-exact known IID for a
        fixed {prefix, mac, secret, dad} tuple — pinning the whole PRF
        construction (the F() input assembly, the digest slice, and
        the prefix/IID combine) which the differential determinism /
        unlinkability tests leave unconstrained.

        Reference: RFC 7217 §5 (Algorithm Specification).
        """

        host = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8:aaaa:bbbb::/64"),
            mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
            dad_counter=0,
        )
        self.assertEqual(
            host.address,
            Ip6Address("2001:db8:aaaa:bbbb:7860:ab56:5da3:c5a9"),
            msg="from_rfc7217 must reproduce the exact PRF-derived IID for the fixed golden input.",
        )

        # An all-ones top-64 prefix sets every prefix bit, so any
        # corruption of the /64 netmask (which masks exactly bits
        # 64-127) changes the result — closing the netmask-arithmetic
        # mutants a partially-populated prefix leaves unconstrained.
        self.assertEqual(
            Ip6IfAddr.from_rfc7217(
                ip6_network=Ip6Network("ffff:ffff:ffff:ffff::/64"),
                mac_address=MacAddress("aa:bb:cc:dd:ee:ff"),
                secret_key=b"a-fixed-128-bit-secret-key-bytes",
                dad_counter=0,
            ).address,
            Ip6Address("ffff:ffff:ffff:ffff:a6bf:2117:5bda:6d09"),
            msg="from_rfc7217 must preserve an all-ones /64 prefix exactly.",
        )

    def test__net_addr__ip6_host__from_rfc7217__minimum_secret_length(self) -> None:
        """
        Ensure a secret key of exactly the 16-byte minimum is accepted
        (the boundary just above the rejection threshold), so the
        length guard rejects strictly-shorter keys only.

        Reference: RFC 7217 §5 (secret_key length).
        """

        host = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"sixteen-byte-key",
        )
        self.assertEqual(
            host.network,
            Ip6Network("2001:db8::/64"),
            msg="A 16-byte secret_key (the minimum) must be accepted.",
        )

    def test__net_addr__ip6_host__from_rfc7217__keeps_prefix(self) -> None:
        """
        Ensure the resulting address keeps the source /64
        network — only the IID changes.

        Reference: RFC 7217 §5 (PRF output replaces IID, prefix preserved).
        """

        host = Ip6IfAddr.from_rfc7217(
            ip6_network=Ip6Network("2001:db8:cafe::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )

        self.assertEqual(
            host.network,
            Ip6Network("2001:db8:cafe::/64"),
            msg=f"RFC 7217 host must keep the source /64 network. Got: {host!r}",
        )
        # Address upper 64 bits = network upper 64 bits.
        self.assertEqual(
            int(host.address) >> 64,
            int(Ip6Address("2001:db8:cafe::")) >> 64,
            msg=f"Address upper-64 must equal prefix. Got: {host.address!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__non_64_mask_raises(self) -> None:
        """
        Ensure 'from_rfc7217()' rejects a network whose mask is
        not /64 (the same constraint as 'from_eui64') with
        'Ip6IfAddrSanityError' carrying a plain operation-
        precondition message.

        Reference: RFC 4291 §2.5.1 (modified EUI-64 IIDs are 64 bits).
        """

        with self.assertRaises(
            Ip6IfAddrSanityError,
            msg="from_rfc7217() must reject a network whose mask is not /64.",
        ) as error:
            Ip6IfAddr.from_rfc7217(
                ip6_network=Ip6Network("2001:db8::/48"),
                mac_address=MacAddress("02:00:00:11:22:33"),
                secret_key=b"a-fixed-128-bit-secret-key-bytes",
            )

        self.assertEqual(
            str(error.exception),
            "network mask must be /64 for an RFC 7217 IID; got /48",
            msg="from_rfc7217() must report the rejected mask length.",
        )

    def test__net_addr__ip6_host__from_rfc7217__rejects_short_secret_key(self) -> None:
        """
        Ensure 'from_rfc7217()' rejects a secret_key shorter
        than 16 bytes (the spec-mandated minimum) with
        'Ip6IfAddrSanityError' carrying a plain operation-
        precondition message, without echoing the key bytes.

        Reference: RFC 7217 §5 (secret_key SHOULD be ≥ 128 bits).
        """

        with self.assertRaises(
            Ip6IfAddrSanityError,
            msg="from_rfc7217() must reject a secret_key < 16 bytes (128 bits).",
        ) as error:
            Ip6IfAddr.from_rfc7217(
                ip6_network=Ip6Network("2001:db8::/64"),
                mac_address=MacAddress("02:00:00:11:22:33"),
                secret_key=b"too-short",
            )

        self.assertEqual(
            str(error.exception),
            "secret_key length 9 < 16 bytes (RFC 7217 §5 minimum)",
            msg="from_rfc7217() must report the key-length problem without leaking the key.",
        )


class TestNetAddrIp6HostFromRfc8981Temp(TestCase):
    """
    The NetAddr IPv6 host 'from_rfc8981_temp()' classmethod
    tests — random IIDs for RFC 8981 temporary addresses.
    """

    def test__net_addr__ip6_host__from_rfc8981_temp__keeps_prefix(self) -> None:
        """
        Ensure the resulting host keeps the source /64 network
        and that the address upper-64 bits equal the prefix.

        Reference: RFC 8981 §3.3.2 (random IID + prefix concat).
        """

        prefix = Ip6Network("2001:db8:cafe::/64")
        host = Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)

        self.assertEqual(
            host.network,
            prefix,
            msg=f"Temporary host must keep the source /64 network. Got: {host!r}",
        )
        self.assertEqual(
            int(host.address) >> 64,
            int(Ip6Address("2001:db8:cafe::")) >> 64,
            msg=f"Address upper-64 must equal prefix. Got: {host.address!r}",
        )

    def test__net_addr__ip6_host__from_rfc8981_temp__different_each_call(self) -> None:
        """
        Ensure two consecutive calls yield different IIDs —
        the IID is derived from a fresh 64-bit random draw, so
        collision probability is negligible.

        Reference: RFC 8981 §3.3.2 (random IID).
        """

        prefix = Ip6Network("2001:db8::/64")
        host_a = Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)
        host_b = Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)

        self.assertNotEqual(
            host_a.address,
            host_b.address,
            msg=f"Two random IIDs must differ. Got: {host_a!r} vs {host_b!r}",
        )

    def test__net_addr__ip6_host__from_rfc8981_temp__non_64_mask_raises(self) -> None:
        """
        Ensure 'from_rfc8981_temp()' rejects a network whose
        mask is not /64 (the IID width is fixed at 64 bits) with
        'Ip6IfAddrSanityError' carrying a plain operation-
        precondition message.

        Reference: RFC 4291 §2.5.1 (IIDs are 64 bits for unicast addresses).
        """

        with self.assertRaises(
            Ip6IfAddrSanityError,
            msg="from_rfc8981_temp() must reject a network whose mask is not /64.",
        ) as error:
            Ip6IfAddr.from_rfc8981_temp(ip6_network=Ip6Network("2001:db8::/48"))

        self.assertEqual(
            str(error.exception),
            "network mask must be /64 for an RFC 8981 temporary IID; got /48",
            msg="from_rfc8981_temp() must report the rejected mask length.",
        )

    def test__net_addr__ip6_host__from_rfc8981_temp__avoids_reserved_iid(self) -> None:
        """
        Ensure the generator regenerates if the random draw
        produces a reserved IID — Subnet-Router Anycast
        (all-zero IID) and Reserved Subnet Anycast IIDs must
        NOT be returned.

        Reference: RFC 5453 (reserved IIDs).
        Reference: RFC 8981 §3.3.2 (avoidance requirement).
        """

        from unittest.mock import patch

        prefix = Ip6Network("2001:db8::/64")
        # First three draws return reserved IIDs; the fourth
        # returns a usable random value.
        reserved_iids = [
            (0).to_bytes(8, "big"),  # Subnet-Router Anycast.
            (0xFDFFFFFFFFFFFF80).to_bytes(8, "big"),  # Reserved Anycast lower bound.
            (0xFDFFFFFFFFFFFFFF).to_bytes(8, "big"),  # Reserved Anycast upper bound.
            (0x1234567890ABCDEF).to_bytes(8, "big"),  # Acceptable random value.
        ]
        with patch(
            "net_addr.ip6_ifaddr.secrets.token_bytes",
            side_effect=reserved_iids,
        ):
            host = Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)

        self.assertEqual(
            int(host.address) & ((1 << 64) - 1),
            0x1234567890ABCDEF,
            msg=(
                "Generator must regenerate past reserved IIDs and return "
                f"the first acceptable random value. Got: {host!r}"
            ),
        )

    def test__net_addr__ip6_host__from_rfc8981_temp__exhaustion_raises(self) -> None:
        """
        Ensure the generator raises after exhausting its retry
        budget without finding a non-reserved IID — protects
        against a (practically impossible) starvation loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from unittest.mock import patch

        prefix = Ip6Network("2001:db8::/64")
        # Every draw returns a reserved IID; the generator
        # should give up.
        with patch(
            "net_addr.ip6_ifaddr.secrets.token_bytes",
            return_value=(0).to_bytes(8, "big"),
        ):
            with self.assertRaises(
                Ip6IfAddrSanityError,
                msg="Exhausting reserved-IID retries must raise Ip6IfAddrSanityError.",
            ):
                Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 host where address is not part of the network.",
            "_args": [
                (Ip6Address("a::1:2:3:4"), Ip6Network("b::/64")),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6IfAddrSanityError,
                "error_message": (
                    "The IPv6 address doesn't belong to the provided network: "
                    "(Ip6Address('a::1:2:3:4'), Ip6Network('b::/64'))"
                ),
            },
        },
        {
            "_description": "Test Ip6IfAddrFormatError: invalid input type.",
            "_args": [12345],
            "_kwargs": {},
            "_results": {
                "error": Ip6IfAddrFormatError,
                "error_message": "The IPv6 interface address format is invalid: 12345",
            },
        },
        {
            "_description": "Test Ip6IfAddrFormatError: invalid string.",
            "_args": ["not-a-host"],
            "_kwargs": {},
            "_results": {
                "error": Ip6IfAddrFormatError,
                "error_message": "The IPv6 interface address format is invalid: 'not-a-host'",
            },
        },
        {
            "_description": "Test Ip6IfAddrFormatError: None input.",
            "_args": [None],
            "_kwargs": {},
            "_results": {
                "error": Ip6IfAddrFormatError,
                "error_message": "The IPv6 interface address format is invalid: None",
            },
        },
        {
            "_description": "Test Ip6IfAddrFormatError: tuple with invalid second element.",
            "_args": [(Ip6Address("2001:db8::1"), 12345)],
            "_kwargs": {},
            "_results": {
                "error": Ip6IfAddrFormatError,
                "error_message": "The IPv6 interface address format is invalid: (Ip6Address('2001:db8::1'), 12345)",
            },
        },
        {
            "_description": "Test Ip6IfAddrFormatError: string with out-of-range mask.",
            "_args": ["2001:db8::1/200"],
            "_kwargs": {},
            "_results": {
                "error": Ip6IfAddrFormatError,
                "error_message": "The IPv6 interface address format is invalid: '2001:db8::1/200'",
            },
        },
    ]
)
class TestNetAddrIp6HostErrors(TestCase):
    """
    The NetAddr IPv6 host error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip6_host__errors(self) -> None:
        """
        Ensure the IPv6 host raises an error on invalid input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip6IfAddr(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


class TestNetAddrIp6IfAddrFormat(TestCase):
    """
    The NetAddr IPv6 interface-address __format__ tests.
    """

    def test__net_addr__ip6_ifaddr__format(self) -> None:
        """
        Ensure __format__ renders the host address in the
        pl / nm / hm notations; default and 'pl' equal str();
        an unknown spec raises ValueError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6IfAddr("2001:db8::5/64")
        for spec, expected in [
            ("", "2001:db8::5/64"),
            ("pl", "2001:db8::5/64"),
            ("nm", "2001:db8::5/ffff:ffff:ffff:ffff::"),
            ("hm", "2001:db8::5/::ffff:ffff:ffff:ffff"),
        ]:
            with self.subTest(spec=spec):
                self.assertEqual(format(a, spec), expected, msg=f"format({spec!r}) must be {expected!r}.")

        self.assertEqual(f"{a}", "2001:db8::5/64", msg="Default format must equal str().")

        # A spec ending in 's' routes through Python's str formatting
        # for width / alignment, applied to the default rendering. A
        # multi-character width spec also pins that only the final
        # character selects this branch.
        for spec in ("s", ">22s", "<22s", "^20s"):
            with self.subTest(spec=spec):
                self.assertEqual(
                    format(a, spec),
                    format("2001:db8::5/64", spec),
                    msg=f"Width/alignment spec {spec!r} must format the default rendering.",
                )

        # Unknown specs must raise the sanity error — including ones
        # whose final character sorts at or below 's' (e.g. 'zq'), which
        # a '<='-relaxation of the width-branch test ('[-1:] == "s"')
        # would mis-route to str formatting (leaking a ValueError).
        for spec in ("zz", "zq", "qa"):
            with self.subTest(spec=spec):
                with self.assertRaises(
                    Ip6IfAddrSanityError,
                    msg=f"Unknown format spec {spec!r} must raise Ip6IfAddrSanityError.",
                ):
                    format(a, spec)


class TestNetAddrIp6IfAddrScoped(TestCase):
    """
    The NetAddr IPv6 interface-address RFC 4007 scoped
    (zone-identifier) construction tests.
    """

    def test__net_addr__ip6_ifaddr__scoped__forms_consistent(self) -> None:
        """
        Ensure a scoped link-local interface address builds
        identically from the (address, mask) tuple, the
        (address, network) tuple, and the string form, with the
        zone kept on the address and stripped from the derived
        network.

        Reference: RFC 4007 §6 (zone qualifies the address, not the prefix).
        """

        from_mask = Ip6IfAddr((Ip6Address("fe80::1%tap0"), Ip6Mask("/64")))
        from_network = Ip6IfAddr((Ip6Address("fe80::1%tap0"), Ip6Network("fe80::/64")))
        from_string = Ip6IfAddr("fe80::1%tap0/64")

        for label, ifaddr in (
            ("(address, mask)", from_mask),
            ("(address, network)", from_network),
            ("string", from_string),
        ):
            with self.subTest(form=label):
                self.assertEqual(
                    str(ifaddr),
                    "fe80::1%tap0/64",
                    msg=f"Scoped ifaddr from {label} must render with its zone.",
                )
                self.assertEqual(
                    repr(ifaddr),
                    "Ip6IfAddr('fe80::1%tap0/64')",
                    msg=f"Scoped ifaddr from {label} repr must round-trip.",
                )
                self.assertEqual(
                    ifaddr.address,
                    Ip6Address("fe80::1%tap0"),
                    msg=f"Scoped ifaddr from {label} must keep the zoned address.",
                )
                self.assertEqual(
                    ifaddr.address.scope_id,
                    "tap0",
                    msg=f"Scoped ifaddr from {label} must preserve the RFC 4007 zone.",
                )
                self.assertEqual(
                    ifaddr.network,
                    Ip6Network("fe80::/64"),
                    msg=f"Scoped ifaddr from {label} must derive an unscoped network.",
                )

        self.assertEqual(
            from_mask,
            from_network,
            msg="Scoped ifaddr must compare equal across the mask and network tuple forms.",
        )
        self.assertEqual(
            from_mask,
            from_string,
            msg="Scoped ifaddr must compare equal across the tuple and string forms.",
        )
        self.assertEqual(
            len({from_mask, from_network, from_string}),
            1,
            msg="Equal scoped ifaddr values must collapse to a single set element.",
        )

    def test__net_addr__ip6_ifaddr__scoped__network_drops_zone(self) -> None:
        """
        Ensure the derived network never carries the RFC 4007
        zone even though the interface address does.

        Reference: RFC 4007 §6 (a prefix has no zone identifier).
        """

        ifaddr = Ip6IfAddr("fe80::abcd%eth2/64")

        self.assertIsNone(
            ifaddr.network.address.scope_id,
            msg="The derived network address must not carry a zone identifier.",
        )
        self.assertEqual(
            ifaddr.address.scope_id,
            "eth2",
            msg="The interface address must retain its zone identifier.",
        )

    def test__net_addr__ip6_ifaddr__scoped__string_without_prefix_is_host(self) -> None:
        """
        Ensure a scoped address string with no prefix length is a
        /128 interface address that retains its zone while the
        derived network drops it.

        Reference: RFC 4007 §6 (a prefix has no zone identifier).
        Reference: PyTCP test infrastructure (stdlib ipaddress parity, no RFC clause).
        """

        ifaddr = Ip6IfAddr("fe80::1%tap0")

        self.assertEqual(str(ifaddr), "fe80::1%tap0/128", msg="A bare scoped address must parse as /128.")
        self.assertEqual(
            ifaddr.address.scope_id,
            "tap0",
            msg="The interface address must retain its zone identifier.",
        )
        self.assertIsNone(
            ifaddr.network.address.scope_id,
            msg="The derived network address must not carry a zone identifier.",
        )


class TestNetAddrIp6IfAddrWhitespace(TestCase):
    """
    The NetAddr Ip6IfAddr surrounding-whitespace tolerance tests.
    """

    def test__net_addr__ip6_ifaddr__whitespace_tolerated(self) -> None:
        """
        Ensure surrounding whitespace is stripped from a string
        argument, uniformly with every other net_addr value
        type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in ("2001:db8::7/64",):
            expected = Ip6IfAddr(value)
            for wrapped in (f" {value}", f"{value} ", f"\t{value}\n", f"  {value}  \n"):
                with self.subTest(value=value, wrapped=wrapped):
                    self.assertEqual(
                        Ip6IfAddr(wrapped),
                        expected,
                        msg=f"Ip6IfAddr({wrapped!r}) must equal Ip6IfAddr({value!r}).",
                    )


class TestNetAddrIp6IfAddrStdlibParity(TestCase):
    """
    The NetAddr Ip6IfAddr stdlib-ipaddress parity tests.
    """

    def test__net_addr__ip6_ifaddr__bare_address_is_host(self) -> None:
        """
        Ensure a prefix-less address parses as a /128 interface
        address.

        Reference: PyTCP test infrastructure (stdlib ipaddress parity, no RFC clause).
        """

        ifaddr = Ip6IfAddr("2001:db8::5")
        self.assertEqual(str(ifaddr), "2001:db8::5/128", msg="A bare address must parse as /128.")


class TestNetAddrIp6IfAddrCauseChain(TestCase):
    """
    The NetAddr IPv6 interface-address error-cause-chain tests.
    """

    def test__net_addr__ip6_ifaddr__string_reject_preserves_cause(self) -> None:
        """
        Ensure a malformed interface-address string raises
        Ip6IfAddrFormatError that preserves the swallowed
        sub-constructor failure as '__cause__', so a traceback
        shows which token (address vs mask) was rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for bad, cause in [
            ("2001:db8::zzzz/64", Ip6AddressFormatError),
            ("2001:db8::1/999", Ip6MaskFormatError),
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(Ip6IfAddrFormatError) as ctx:
                    Ip6IfAddr(bad)
                self.assertIsInstance(
                    ctx.exception.__cause__,
                    cause,
                    msg=f"The swallowed {cause.__name__} must be preserved as __cause__ for {bad!r}.",
                )


class TestNetAddrIp6IfAddrOrdering(TestCase):
    """
    The NetAddr IPv6 interface-address ordering tests.
    """

    def test__net_addr__ip6_ifaddr__ordering(self) -> None:
        """
        Ensure IPv6 interface addresses are totally ordered by
        host address then network (so they sort consistently
        with the sibling value types), matching equality.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip6IfAddr("2001:db8::5/64")
        b = Ip6IfAddr("2001:db8::5/96")
        c = Ip6IfAddr("2001:db8::6/64")

        self.assertEqual(
            sorted([c, b, a]),
            [a, b, c],
            msg="Ip6IfAddr must sort by (host address, network).",
        )
        self.assertTrue(a < b, msg="Same host address, longer-prefix network must sort after.")
        self.assertTrue(b < c, msg="Lower host address must sort before.")
        self.assertEqual(min(c, b, a), a, msg="min() must return the lowest Ip6IfAddr.")

    def test__net_addr__ip6_ifaddr__ordering__total_order_relations(self) -> None:
        """
        Ensure every ordering operator is pinned in both directions
        and reflexively, including the network tiebreak between two
        interface addresses that share a host address, and that
        equality rejects a strictly-greater operand in either argument
        order — so a flipped or weakened comparison in '<', '<=', '>',
        '>=' or '==' is caught.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Same host address, different network: the /65 network sorts
        # after the /64 via the mask tiebreak.
        a = Ip6IfAddr("2001:db8::5/64")
        b = Ip6IfAddr("2001:db8::5/65")

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
        higher = Ip6IfAddr("2001:db8::6/64")
        self.assertNotEqual(higher, a, msg="A higher host address must not equal a lower one (greater on left).")
        self.assertNotEqual(a, higher, msg="A lower host address must not equal a higher one (lesser on left).")

    def test__net_addr__ip6_ifaddr__ordering__scope_consistent_with_equality(self) -> None:
        """
        Ensure a scoped and an unscoped interface address with
        the same host bits and network are unequal and remain
        deterministically ordered (the RFC 4007 zone is folded
        into the order key, consistently with equality).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        plain = Ip6IfAddr("fe80::1/64")
        scoped = Ip6IfAddr("fe80::1%eth0/64")

        self.assertNotEqual(plain, scoped, msg="A zone makes the interface address distinct.")
        self.assertEqual(
            sorted([scoped, plain]),
            [plain, scoped],
            msg="The unscoped interface address must order before the scoped one.",
        )

    def test__net_addr__ip6_ifaddr__ordering__cross_version_raises(self) -> None:
        """
        Ensure ordering an IPv6 interface address against an
        IPv4 interface address raises TypeError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError, msg="Ip6IfAddr < Ip4IfAddr must raise TypeError."):
            _ = Ip6IfAddr("2001:db8::5/64") < Ip4IfAddr("10.0.0.5/24")


class TestNetAddrIp6ReservedIid(TestCase):
    """
    The NetAddr RFC 5453 reserved-IID predicate tests.
    """

    def test__net_addr__ip6__is_reserved_iid(self) -> None:
        """
        Ensure '_is_reserved_iid' flags exactly the RFC 5453 / RFC 2526
        reserved interface identifiers — the all-zero Subnet-Router
        Anycast IID and the Reserved Subnet Anycast block
        (fdff:ffff:ffff:ff80 .. ffff) inclusive — and accepts every
        IID just outside those bounds. Tested directly with crafted
        IIDs (the generators only reach this path on a ~7e-18 random
        hit, so the predicate is pinned at its boundaries here).

        Reference: RFC 5453 (Reserved IPv6 Interface Identifiers).
        Reference: RFC 2526 §3 (Reserved Subnet Anycast Addresses).
        """

        for iid, reserved in [
            (0x0000_0000_0000_0000, True),  # Subnet-Router Anycast (all-zero)
            (0x0000_0000_0000_0001, False),  # one above the anycast IID
            (0xFDFF_FFFF_FFFF_FF7F, False),  # one below the reserved block
            (0xFDFF_FFFF_FFFF_FF80, True),  # reserved block lower bound
            (0xFDFF_FFFF_FFFF_FFFF, True),  # reserved block upper bound
            (0xFE00_0000_0000_0000, False),  # one above the reserved block
        ]:
            with self.subTest(iid=hex(iid)):
                self.assertEqual(
                    _is_reserved_iid(iid),
                    reserved,
                    msg=f"_is_reserved_iid({iid:#018x}) must be {reserved}.",
                )
