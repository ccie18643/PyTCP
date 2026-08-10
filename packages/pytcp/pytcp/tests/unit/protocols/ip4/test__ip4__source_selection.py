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
This module contains tests for the RFC 6724 §6 IPv4 source-
address-selection helpers.

pytcp/tests/unit/protocols/ip4/test__ip4__source_selection.py

ver 3.0.10
"""

from unittest import TestCase

from net_addr import Ip4Address
from pytcp.protocols.ip4.ip4__source_selection import (
    common_prefix_len,
    ip4_address_scope,
)
from pytcp.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Loopback 127.0.0.1 has interface-local scope.",
            "_address": Ip4Address("127.0.0.1"),
            "_expected_scope": 0x1,
        },
        {
            "_description": "Loopback boundary 127.255.255.254 has interface-local scope.",
            "_address": Ip4Address("127.255.255.254"),
            "_expected_scope": 0x1,
        },
        {
            "_description": "Link-local 169.254.1.1 has link-local scope.",
            "_address": Ip4Address("169.254.1.1"),
            "_expected_scope": 0x2,
        },
        {
            "_description": "RFC 1918 private 10.0.0.1 has global scope.",
            "_address": Ip4Address("10.0.0.1"),
            "_expected_scope": 0xE,
        },
        {
            "_description": "RFC 1918 private 192.168.1.1 has global scope.",
            "_address": Ip4Address("192.168.1.1"),
            "_expected_scope": 0xE,
        },
        {
            "_description": "Public address 8.8.8.8 has global scope.",
            "_address": Ip4Address("8.8.8.8"),
            "_expected_scope": 0xE,
        },
    ]
)
class TestIp4AddressScope(TestCase):
    """
    The 'ip4_address_scope' helper tests.
    """

    _description: str
    _address: Ip4Address
    _expected_scope: int

    def test__lib__ip4_source_selection__scope(self) -> None:
        """
        Ensure 'ip4_address_scope' returns the RFC 4007 scope
        value for the address — interface-local for loopback,
        link-local for 169.254.0.0/16, global for everything
        else (matching the IPv6 codepoints so a single
        rule-2 comparison works across both families).

        Reference: RFC 6724 §6 (IPv4 source selection follows v6 mapping).
        Reference: RFC 4007 §5 (Scope of an IPv6 / IPv4 address).
        """

        self.assertEqual(
            ip4_address_scope(self._address),
            self._expected_scope,
            msg=f"Unexpected scope for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "Identical addresses share a 32-bit prefix.",
            "_a": Ip4Address("10.0.0.1"),
            "_b": Ip4Address("10.0.0.1"),
            "_expected_len": 32,
        },
        {
            "_description": "Adjacent addresses 10.0.0.1 and 10.0.0.2 share 30 bits.",
            "_a": Ip4Address("10.0.0.1"),
            "_b": Ip4Address("10.0.0.2"),
            "_expected_len": 30,
        },
        {
            "_description": "Same /24 address pair 10.0.0.7 and 10.0.0.91 shares 25 bits.",
            "_a": Ip4Address("10.0.0.7"),
            "_b": Ip4Address("10.0.0.91"),
            "_expected_len": 25,
        },
        {
            "_description": "Same /16 address pair 10.0.0.7 and 10.0.7.1 shares 16+ bits.",
            "_a": Ip4Address("10.0.0.7"),
            "_b": Ip4Address("10.0.7.1"),
            "_expected_len": 21,
        },
        {
            "_description": "Different /8 addresses 10.0.0.1 and 192.168.1.1 share 0 bits.",
            "_a": Ip4Address("10.0.0.1"),
            "_b": Ip4Address("192.168.1.1"),
            "_expected_len": 0,
        },
        {
            "_description": "All-zero and all-one share 0 bits.",
            "_a": Ip4Address("0.0.0.0"),
            "_b": Ip4Address("255.255.255.255"),
            "_expected_len": 0,
        },
    ]
)
class TestIp4CommonPrefixLen(TestCase):
    """
    The IPv4 'common_prefix_len' helper tests.
    """

    _description: str
    _a: Ip4Address
    _b: Ip4Address
    _expected_len: int

    def test__lib__ip4_source_selection__common_prefix_len(self) -> None:
        """
        Ensure 'common_prefix_len' returns the number of leading
        bits the two IPv4 addresses share, capped at 32 for
        identical inputs and zero for inputs that disagree on
        bit zero.

        Reference: RFC 6724 §2.2 (CommonPrefixLen, applied to v4 per §6).
        """

        self.assertEqual(
            common_prefix_len(self._a, self._b),
            self._expected_len,
            msg=f"Unexpected common-prefix length for case: {self._description}",
        )

    def test__lib__ip4_source_selection__common_prefix_len__symmetric(self) -> None:
        """
        Ensure 'common_prefix_len' is symmetric in its arguments.

        Reference: RFC 6724 §2.2 (CommonPrefixLen definition).
        """

        self.assertEqual(
            common_prefix_len(self._a, self._b),
            common_prefix_len(self._b, self._a),
            msg=f"Asymmetric common-prefix length for case: {self._description}",
        )


class TestIp4SourceSelectionInvariants(TestCase):
    """
    Invariant tests for the IPv4 source-selection helpers.
    """

    def test__lib__ip4_source_selection__scope__strict_ordering(self) -> None:
        """
        Ensure scope values increase monotonically:
        interface-local < link-local < global. The integer
        comparison drives rule 2's 'prefer smallest scope ≥
        dst' tiebreak so this ordering must hold.

        Reference: RFC 6724 §3.1 (Scope Comparisons).
        """

        self.assertLess(
            ip4_address_scope(Ip4Address("127.0.0.1")),
            ip4_address_scope(Ip4Address("169.254.1.1")),
            msg="Interface-local IPv4 scope must be smaller than link-local.",
        )
        self.assertLess(
            ip4_address_scope(Ip4Address("169.254.1.1")),
            ip4_address_scope(Ip4Address("10.0.0.1")),
            msg="Link-local IPv4 scope must be smaller than global.",
        )

    def test__lib__ip4_source_selection__common_prefix_len__bounded(self) -> None:
        """
        Ensure 'common_prefix_len' result stays within [0, 32]
        for every pair of valid IPv4 addresses.

        Reference: RFC 6724 §2.2 (CommonPrefixLen definition).
        """

        for a, b in (
            (Ip4Address("0.0.0.0"), Ip4Address("0.0.0.0")),
            (Ip4Address("255.0.0.0"), Ip4Address("128.0.0.0")),
            (Ip4Address("10.0.0.1"), Ip4Address("10.0.0.2")),
        ):
            length = common_prefix_len(a, b)
            self.assertGreaterEqual(length, 0, msg=f"common_prefix_len went negative for {a!r} vs {b!r}")
            self.assertLessEqual(length, 32, msg=f"common_prefix_len exceeded 32 for {a!r} vs {b!r}")
