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
This module contains tests for the RFC 6724 source-address-selection
helpers.

pytcp/tests/unit/protocols/ip6/test__ip6__source_selection.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address
from pytcp.protocols.ip6.ip6__source_selection import (
    common_prefix_len,
    ip6_address_scope,
)


@parameterized_class(
    [
        {
            "_description": "Loopback ::1 has interface-local scope (RFC 4007 §5).",
            "_address": Ip6Address("::1"),
            "_expected_scope": 0x1,
        },
        {
            "_description": "Link-local fe80::1 has link-local scope.",
            "_address": Ip6Address("fe80::1"),
            "_expected_scope": 0x2,
        },
        {
            "_description": "Link-local fe80::ffff:ffff:ffff:ffff has link-local scope.",
            "_address": Ip6Address("fe80::ffff:ffff:ffff:ffff"),
            "_expected_scope": 0x2,
        },
        {
            "_description": "ULA fc00::1 has global scope (RFC 4291 §2.5.7).",
            "_address": Ip6Address("fc00::1"),
            "_expected_scope": 0xE,
        },
        {
            "_description": "GUA 2001:db8::1 has global scope.",
            "_address": Ip6Address("2001:db8::1"),
            "_expected_scope": 0xE,
        },
        {
            "_description": "Link-local multicast ff02::1 has link-local scope.",
            "_address": Ip6Address("ff02::1"),
            "_expected_scope": 0x2,
        },
        {
            "_description": "Interface-local multicast ff01::1 has interface-local scope.",
            "_address": Ip6Address("ff01::1"),
            "_expected_scope": 0x1,
        },
        {
            "_description": "Site-local multicast ff05::1 has site-local scope.",
            "_address": Ip6Address("ff05::1"),
            "_expected_scope": 0x5,
        },
        {
            "_description": "Global multicast ff0e::1 has global scope.",
            "_address": Ip6Address("ff0e::1"),
            "_expected_scope": 0xE,
        },
    ]
)
class TestIp6AddressScope(TestCase):
    """
    The 'ip6_address_scope' helper tests.
    """

    _description: str
    _address: Ip6Address
    _expected_scope: int

    def test__lib__ip6_source_selection__scope(self) -> None:
        """
        Ensure 'ip6_address_scope' returns the RFC 4007/4291 scope
        value for the address — interface-local for loopback,
        link-local for fe80::/10 and ff02::/16, site-local for
        ff05::/16, and global for everything else.

        Reference: RFC 6724 §3.1 (Scope Comparisons).
        Reference: RFC 4007 §5 (IPv6 Scoped Address Architecture).
        Reference: RFC 4291 §2.7 (Multicast scope field).
        """

        self.assertEqual(
            ip6_address_scope(self._address),
            self._expected_scope,
            msg=f"Unexpected scope for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "Identical addresses share a 128-bit prefix.",
            "_a": Ip6Address("2001:db8::1"),
            "_b": Ip6Address("2001:db8::1"),
            "_expected_len": 128,
        },
        {
            "_description": "Two host addresses in the same /64, IIDs 0x07 and 0x91, share 120 bits.",
            "_a": Ip6Address("2001:db8:0:1::7"),
            "_b": Ip6Address("2001:db8:0:1::91"),
            "_expected_len": 120,
        },
        {
            "_description": "Two host addresses spanning subnet IDs 1 and 2 share 62 bits.",
            "_a": Ip6Address("2001:db8:0:1::7"),
            "_b": Ip6Address("2001:db8:0:2::7"),
            "_expected_len": 62,
        },
        {
            "_description": "Two addresses with different /16 prefixes share 15 bits.",
            "_a": Ip6Address("2001::1"),
            "_b": Ip6Address("2002::1"),
            "_expected_len": 14,
        },
        {
            "_description": "Two addresses with no leading bits in common share 0 bits.",
            "_a": Ip6Address("8000::"),
            "_b": Ip6Address("::"),
            "_expected_len": 0,
        },
        {
            "_description": "All-zero and all-one addresses share 0 bits.",
            "_a": Ip6Address("::"),
            "_b": Ip6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            "_expected_len": 0,
        },
    ]
)
class TestCommonPrefixLen(TestCase):
    """
    The 'common_prefix_len' helper tests.
    """

    _description: str
    _a: Ip6Address
    _b: Ip6Address
    _expected_len: int

    def test__lib__ip6_source_selection__common_prefix_len(self) -> None:
        """
        Ensure 'common_prefix_len' returns the number of leading
        bits the two IPv6 addresses share, capped at 128 for
        identical inputs and zero for inputs that disagree on bit
        zero.

        Reference: RFC 6724 §2.2 (CommonPrefixLen definition).
        """

        self.assertEqual(
            common_prefix_len(self._a, self._b),
            self._expected_len,
            msg=f"Unexpected common-prefix length for case: {self._description}",
        )

    def test__lib__ip6_source_selection__common_prefix_len__symmetric(self) -> None:
        """
        Ensure 'common_prefix_len' is symmetric: swapping the
        arguments returns the same value.

        Reference: RFC 6724 §2.2 (CommonPrefixLen definition).
        """

        self.assertEqual(
            common_prefix_len(self._a, self._b),
            common_prefix_len(self._b, self._a),
            msg=f"Asymmetric common-prefix length for case: {self._description}",
        )


class TestIp6AddressScopeEdgeCases(TestCase):
    """
    The 'ip6_address_scope' edge-case tests.
    """

    def test__lib__ip6_source_selection__scope__unspecified_global(self) -> None:
        """
        Ensure the unspecified address (::) is treated as global
        scope so the selector remains well-defined when an
        unspecified destination is passed in for sort
        comparisons.

        Reference: RFC 4007 §5 (Scope of an IPv6 Address).
        Reference: RFC 6724 §2.1 (Scope is implementation-defined for ::).
        """

        self.assertEqual(
            ip6_address_scope(Ip6Address()),
            0xE,
            msg="Unspecified IPv6 address must default to global scope.",
        )

    def test__lib__ip6_source_selection__scope__strict_ordering(self) -> None:
        """
        Ensure scope values increase monotonically from
        interface-local < link-local < site-local < global so the
        rule-2 'prefer smallest scope >= dst' tiebreak is
        well-defined under integer comparison.

        Reference: RFC 6724 §3.1 (Scope Comparisons).
        Reference: RFC 4007 §5 (IPv6 Scoped Address Architecture).
        """

        self.assertLess(
            ip6_address_scope(Ip6Address("::1")),
            ip6_address_scope(Ip6Address("fe80::1")),
            msg="Interface-local scope must be smaller than link-local scope.",
        )
        self.assertLess(
            ip6_address_scope(Ip6Address("fe80::1")),
            ip6_address_scope(Ip6Address("ff05::1")),
            msg="Link-local scope must be smaller than site-local scope.",
        )
        self.assertLess(
            ip6_address_scope(Ip6Address("ff05::1")),
            ip6_address_scope(Ip6Address("2001:db8::1")),
            msg="Site-local scope must be smaller than global scope.",
        )


class TestCommonPrefixLenInvariants(TestCase):
    """
    The 'common_prefix_len' invariant tests.
    """

    def test__lib__ip6_source_selection__common_prefix_len__bounded(self) -> None:
        """
        Ensure 'common_prefix_len' result stays within [0, 128]
        for every pair of valid IPv6 addresses.

        Reference: RFC 6724 §2.2 (CommonPrefixLen definition).
        """

        for a, b in (
            (Ip6Address("::"), Ip6Address("::")),
            (Ip6Address("ffff::"), Ip6Address("8000::")),
            (Ip6Address("2001:db8::1"), Ip6Address("2001:db8::2")),
        ):
            length = common_prefix_len(a, b)
            self.assertGreaterEqual(length, 0, msg=f"common_prefix_len went negative for {a!r} vs {b!r}")
            self.assertLessEqual(length, 128, msg=f"common_prefix_len exceeded 128 for {a!r} vs {b!r}")

    def test__lib__ip6_source_selection__common_prefix_len__matches_definition(self) -> None:
        """
        Ensure 'common_prefix_len' returns N for two addresses
        that disagree at bit position N — the canonical
        definition the rule-8 sort key relies on.

        Reference: RFC 6724 §2.2 (CommonPrefixLen definition).
        """

        bit_64_disagree = (
            Ip6Address("2001:db8:0:0:8000::"),
            Ip6Address("2001:db8::"),
        )
        self.assertEqual(
            common_prefix_len(*bit_64_disagree),
            64,
            msg="Disagreement at bit 64 must yield common-prefix length of 64.",
        )

        bit_127_disagree: tuple[Ip6Address, Ip6Address] = (
            Ip6Address("::"),
            Ip6Address("::1"),
        )
        self.assertEqual(
            common_prefix_len(*bit_127_disagree),
            127,
            msg="Disagreement at bit 127 must yield common-prefix length of 127.",
        )


# Silence unused-import warnings when 'Any' is referenced only by
# the parameterized_class decorator's mypy noise.
_ = Any
