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
This module contains tests for the RFC 6724 §10.3 default
policy-table helpers.

pytcp/tests/unit/protocols/ip6/test__ip6__policy_table.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase

from net_addr import Ip6Address, Ip6Network
from pytcp.protocols.ip6.ip6__policy_table import (
    DEFAULT_POLICY_TABLE,
    PolicyEntry,
    get_policy_table,
    lookup,
    reset_policy_table,
    set_policy_table,
)
from pytcp.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Loopback ::1 matches the most specific ::1/128 entry.",
            "_address": Ip6Address("::1"),
            "_expected": (50, 0),
        },
        {
            "_description": "IPv4-mapped ::ffff:0:0/96 matches the v4-mapped entry.",
            "_address": Ip6Address("::ffff:192.0.2.1"),
            "_expected": (35, 4),
        },
        {
            "_description": "6to4 prefix 2002::/16 matches the 6to4 entry.",
            "_address": Ip6Address("2002:c000:201::"),
            "_expected": (30, 2),
        },
        {
            "_description": "Teredo 2001:0::/32 matches the Teredo entry.",
            "_address": Ip6Address("2001::1"),
            "_expected": (5, 5),
        },
        {
            "_description": "ULA fc00::/7 matches the ULA entry.",
            "_address": Ip6Address("fc00::1"),
            "_expected": (3, 13),
        },
        {
            "_description": "ULA fdff::1 in fc00::/7 matches the ULA entry.",
            "_address": Ip6Address("fdff::1"),
            "_expected": (3, 13),
        },
        {
            "_description": "Deprecated site-local fec0::/10 matches the site-local entry.",
            "_address": Ip6Address("fec0::1"),
            "_expected": (1, 11),
        },
        {
            "_description": "Deprecated 6bone 3ffe::/16 matches the 6bone entry.",
            "_address": Ip6Address("3ffe::1"),
            "_expected": (1, 12),
        },
        {
            "_description": "IPv4-compatible ::/96 matches the v4-compatible entry.",
            "_address": Ip6Address("::192.0.2.1"),
            "_expected": (1, 3),
        },
        {
            "_description": "Documentation prefix 2001:db8::1 falls through to ::/0.",
            "_address": Ip6Address("2001:db8::1"),
            "_expected": (40, 1),
        },
        {
            "_description": "Global GUA 2620::1 falls through to ::/0.",
            "_address": Ip6Address("2620::1"),
            "_expected": (40, 1),
        },
        {
            "_description": "Link-local fe80::1 falls through to ::/0 (no link-local entry in default table).",
            "_address": Ip6Address("fe80::1"),
            "_expected": (40, 1),
        },
        {
            "_description": "Unspecified :: matches the more-specific ::/96 v4-compatible entry.",
            "_address": Ip6Address("::"),
            "_expected": (1, 3),
        },
    ]
)
class TestIp6PolicyTableLookup(TestCase):
    """
    The RFC 6724 §10.3 default-policy-table lookup tests.
    """

    _description: str
    _address: Ip6Address
    _expected: tuple[int, int]

    def test__lib__ip6_policy_table__lookup(self) -> None:
        """
        Ensure 'lookup' returns the (precedence, label) pair
        from the most-specific matching entry of the default
        policy table.

        Reference: RFC 6724 §10.3 (Default policy table).
        Reference: RFC 6724 §2.1 (Policy table is a longest-match lookup).
        """

        precedence, label = lookup(self._address)

        self.assertEqual(
            (precedence, label),
            self._expected,
            msg=f"Unexpected (precedence, label) for case: {self._description}",
        )


class TestIp6PolicyTableShape(TestCase):
    """
    The RFC 6724 §10.3 default-policy-table shape tests.
    """

    def test__lib__ip6_policy_table__default_table_entry_count(self) -> None:
        """
        Ensure the default policy table contains exactly the
        nine entries enumerated in the RFC §10.3 figure.

        Reference: RFC 6724 §10.3 (Default policy table).
        """

        self.assertEqual(
            len(DEFAULT_POLICY_TABLE),
            9,
            msg="RFC 6724 §10.3 default policy table must contain 9 entries.",
        )

    def test__lib__ip6_policy_table__entries_are_policy_entry_records(self) -> None:
        """
        Ensure every policy-table entry is a 'PolicyEntry'
        instance carrying network, precedence, and label —
        consumers depend on the typed fields rather than tuple
        index access.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for entry in DEFAULT_POLICY_TABLE:
            self.assertIsInstance(
                entry,
                PolicyEntry,
                msg=f"Default policy entry must be a PolicyEntry instance. Got: {type(entry).__name__}",
            )

    def test__lib__ip6_policy_table__catch_all_entry_present(self) -> None:
        """
        Ensure the default policy table contains a ::/0
        catch-all entry so 'lookup' is total — every IPv6
        address must yield a (precedence, label) pair without
        raising.

        Reference: RFC 6724 §10.3 (::/0 default with precedence 40 / label 1).
        """

        catch_all = [entry for entry in DEFAULT_POLICY_TABLE if str(entry.network) == "::/0"]

        self.assertEqual(
            len(catch_all),
            1,
            msg="RFC 6724 §10.3 default policy table must include exactly one ::/0 catch-all.",
        )
        self.assertEqual(
            (catch_all[0].precedence, catch_all[0].label),
            (40, 1),
            msg="The ::/0 catch-all must have precedence 40 and label 1.",
        )


class TestIp6PolicyTableOverride(TestCase):
    """
    The RFC 6724 §10.3 operator policy-table override tests.
    """

    @override
    def setUp(self) -> None:
        """
        Restore the default policy table after every test so an
        override cannot leak into a sibling test.
        """

        self.addCleanup(reset_policy_table)

    def test__set_policy_table_overrides_lookup(self) -> None:
        """
        Ensure installing a custom policy table makes 'lookup' resolve a
        destination's (precedence, label) from the custom table — an
        operator override the source-selection rule-6 consumer reads live.

        Reference: RFC 6724 §2.1 (Policy table is administrator-configurable).
        """

        set_policy_table(
            (
                PolicyEntry(network=Ip6Network("2001:db8::/32"), precedence=99, label=7),
                PolicyEntry(network=Ip6Network("::/0"), precedence=40, label=1),
            )
        )

        self.assertEqual(
            lookup(Ip6Address("2001:db8::1")),
            (99, 7),
            msg="After an override, 'lookup' must resolve from the custom policy table.",
        )

    def test__reset_policy_table_restores_default(self) -> None:
        """
        Ensure 'reset_policy_table' restores the RFC §10.3 default table
        after an operator override.

        Reference: RFC 6724 §10.3 (Default policy table).
        """

        set_policy_table(
            (
                PolicyEntry(network=Ip6Network("2001:db8::/32"), precedence=99, label=7),
                PolicyEntry(network=Ip6Network("::/0"), precedence=40, label=1),
            )
        )
        reset_policy_table()

        self.assertEqual(
            lookup(Ip6Address("2001:db8::1")),
            (40, 1),
            msg="After reset, 'lookup' must resolve from the RFC default table again.",
        )

    def test__set_policy_table_rejects_missing_catch_all(self) -> None:
        """
        Ensure 'set_policy_table' rejects a table with no ::/0 catch-all
        entry, since 'lookup' must stay total (every address must yield a
        (precedence, label) pair without raising).

        Reference: RFC 6724 §10.3 (::/0 default catch-all keeps lookup total).
        """

        with self.assertRaises(ValueError) as ctx:
            set_policy_table((PolicyEntry(network=Ip6Network("2001:db8::/32"), precedence=99, label=7),))

        self.assertIn(
            "::/0",
            str(ctx.exception),
            msg="The rejection message must name the missing ::/0 catch-all requirement.",
        )

    def test__get_policy_table_returns_active_table(self) -> None:
        """
        Ensure 'get_policy_table' returns the currently-active table — the
        default before any override, and the custom table after one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            get_policy_table(),
            DEFAULT_POLICY_TABLE,
            msg="Before any override 'get_policy_table' must return the default table.",
        )
        custom = (
            PolicyEntry(network=Ip6Network("2001:db8::/32"), precedence=99, label=7),
            PolicyEntry(network=Ip6Network("::/0"), precedence=40, label=1),
        )
        set_policy_table(custom)
        self.assertEqual(
            get_policy_table(),
            custom,
            msg="After an override 'get_policy_table' must return the custom table.",
        )
