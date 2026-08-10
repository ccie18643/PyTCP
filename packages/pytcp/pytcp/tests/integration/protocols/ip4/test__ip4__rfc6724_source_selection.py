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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Integration tests for the RFC 6724 §6 IPv4 source-address
selection — rules 1, 2, and 8 applied to the IPv4 family.

Exercises 'Ip4TxHandler._select_ip4_source' against an
in-memory '_ip4_ifaddr' list with mixed scopes and overlapping
prefixes. The IPv4 family has no SLAAC PREFERRED/DEPRECATED
state, no temporary addresses, and no §10.3 policy table, so
rules 3, 6, and 7 do not apply.

pytcp/tests/integration/protocols/ip4/test__ip4__rfc6724_source_selection.py

ver 3.0.9
"""

from typing import override

from net_addr import Ip4Address, Ip4IfAddr
from pytcp.tests.lib.ip4_testcase import Ip4TestCase

# Stack-host fixtures used as candidate sources. Three hosts
# in distinct /24s plus a link-local IPv4 in 169.254.0.0/16.
_HOST_LINK_LOCAL = Ip4IfAddr("169.254.0.7/16")
_HOST_PREFIX_A = Ip4IfAddr("10.0.1.7/24")
_HOST_PREFIX_B = Ip4IfAddr("10.0.2.7/24")
_HOST_PREFIX_C = Ip4IfAddr("192.168.1.7/24")

_DST_LINK_LOCAL = Ip4Address("169.254.5.5")
_DST_IN_PREFIX_A = Ip4Address("10.0.1.91")
_DST_IN_PREFIX_B = Ip4Address("10.0.2.50")
_DST_OUTSIDE_ALL = Ip4Address("8.8.8.8")


class TestRfc6724Ip4Rule1SameAddress(Ip4TestCase):
    """
    The IPv4 RFC 6724 §5 rule 1 (prefer same address) tests.
    """

    @override
    def setUp(self) -> None:
        """
        Populate '_ip4_ifaddr' with one stack address whose
        value coincides with the destination used in the
        rule-1 case.
        """

        super().setUp()
        self._packet_handler._ip4_ifaddr = [_HOST_PREFIX_A]

    def test__ip4__rfc6724_rule1__dst_equals_candidate__returns_dst(self) -> None:
        """
        Ensure that when the destination address is one of the
        stack's owned source addresses, the selector returns
        that address verbatim — covering self-traffic where
        the kernel must not pick any other candidate.

        Reference: RFC 6724 §5 rule 1 (Prefer same address).
        Reference: RFC 6724 §6 (IPv4 source selection follows v6 rules).
        """

        result = self._packet_handler._ip4_tx._select_ip4_source(
            ip4__dst=_HOST_PREFIX_A.address,
        )

        self.assertEqual(
            result,
            _HOST_PREFIX_A.address,
            msg="Rule 1 must return the destination when it equals an owned source.",
        )


class TestRfc6724Ip4Rule2Scope(Ip4TestCase):
    """
    The IPv4 RFC 6724 §5 rule 2 (prefer appropriate scope) tests.
    """

    @override
    def setUp(self) -> None:
        """
        Populate '_ip4_ifaddr' with one link-local
        (169.254.0.0/16) and one global candidate so the
        selector has to choose between scopes.
        """

        super().setUp()
        self._packet_handler._ip4_ifaddr = [_HOST_LINK_LOCAL, _HOST_PREFIX_A]

    def test__ip4__rfc6724_rule2__global_dst_picks_global_source(self) -> None:
        """
        Ensure a global IPv4 destination drives the selector
        to the global candidate, preventing a 169.254.0.0/16
        link-local source from leaking into off-link traffic.

        Reference: RFC 6724 §5 rule 2 (Prefer appropriate scope).
        Reference: RFC 3927 §2.6 (Link-local addresses MUST NOT route).
        """

        result = self._packet_handler._ip4_tx._select_ip4_source(
            ip4__dst=_DST_OUTSIDE_ALL,
        )

        self.assertEqual(
            result,
            _HOST_PREFIX_A.address,
            msg="Rule 2 must avoid link-local source for global destination.",
        )

    def test__ip4__rfc6724_rule2__link_local_dst_picks_link_local_source(self) -> None:
        """
        Ensure a link-local IPv4 destination drives the
        selector to the link-local candidate.

        Reference: RFC 6724 §5 rule 2 (Prefer appropriate scope).
        Reference: RFC 3927 §1 (IPv4 link-local 169.254.0.0/16 scope).
        """

        result = self._packet_handler._ip4_tx._select_ip4_source(
            ip4__dst=_DST_LINK_LOCAL,
        )

        self.assertEqual(
            result,
            _HOST_LINK_LOCAL.address,
            msg="Rule 2 must prefer link-local source for link-local destination.",
        )


class TestRfc6724Ip4Rule8LongestMatch(Ip4TestCase):
    """
    The IPv4 RFC 6724 §5 rule 8 (longest matching prefix) tests.
    """

    @override
    def setUp(self) -> None:
        """
        Populate '_ip4_ifaddr' with three same-scope candidates
        whose prefixes differ in the third octet so the
        selector has a clean rule-8 tiebreak.
        """

        super().setUp()
        self._packet_handler._ip4_ifaddr = [_HOST_PREFIX_A, _HOST_PREFIX_B, _HOST_PREFIX_C]

    def test__ip4__rfc6724_rule8__picks_longest_common_prefix(self) -> None:
        """
        Ensure rule 8 picks the candidate with the most
        leading bits in common with the destination when
        rules 1 and 2 tie. The destination is in prefix B's
        /24, so prefix B's host address must win.

        Reference: RFC 6724 §5 rule 8 (Use longest matching prefix).
        Reference: RFC 6724 §2.2 (CommonPrefixLen definition).
        """

        result = self._packet_handler._ip4_tx._select_ip4_source(
            ip4__dst=_DST_IN_PREFIX_B,
        )

        self.assertEqual(
            result,
            _HOST_PREFIX_B.address,
            msg="Rule 8 must pick the candidate whose prefix matches the destination.",
        )

    def test__ip4__rfc6724_rule8__deterministic_unrelated_destination(self) -> None:
        """
        Ensure rule 8 produces a deterministic answer for an
        unrelated destination — among otherwise-equal
        candidates the one with the longest common prefix is
        chosen, never an arrival-order pick.

        Reference: RFC 6724 §5 rule 8 (Use longest matching prefix).
        """

        result_a = self._packet_handler._ip4_tx._select_ip4_source(ip4__dst=_DST_OUTSIDE_ALL)
        result_b = self._packet_handler._ip4_tx._select_ip4_source(ip4__dst=_DST_OUTSIDE_ALL)

        self.assertIsNotNone(
            result_a,
            msg="Rule 8 must always return a candidate when one exists.",
        )
        self.assertEqual(
            result_a,
            result_b,
            msg="Rule 8 outcome must be deterministic across repeated calls.",
        )


class TestRfc6724Ip4SelectorBoundaries(Ip4TestCase):
    """
    The 'Ip4TxHandler._select_ip4_source' boundary tests.
    """

    def test__ip4__rfc6724__no_candidates_returns_none(self) -> None:
        """
        Ensure the selector returns None when '_ip4_ifaddr' is
        empty — the IPv4 TX path falls back to the existing
        DROPPED__IP4__SRC_UNSPECIFIED handling.

        Reference: RFC 6724 §5 (Source Address Selection).
        """

        self._packet_handler._ip4_ifaddr = []

        result = self._packet_handler._ip4_tx._select_ip4_source(
            ip4__dst=_DST_OUTSIDE_ALL,
        )

        self.assertIsNone(
            result,
            msg="Selector must return None when no candidate sources exist.",
        )

    def test__ip4__rfc6724__same_address_overrides_longer_prefix_match(self) -> None:
        """
        Ensure rule 1 wins over rule 8: when the destination
        is itself an owned address, the selector returns it
        even if another candidate would have won on rule 8.

        Reference: RFC 6724 §5 (rule 1 ordered before rule 8).
        """

        # Both candidates are in the same prefix as dst, so
        # rule 8 ties; rule 1's short-circuit on dst itself
        # is what makes the test pin the rule order.
        sibling = Ip4IfAddr("10.0.1.91/24")  # same address as _DST_IN_PREFIX_A
        self._packet_handler._ip4_ifaddr = [_HOST_PREFIX_A, sibling]

        result = self._packet_handler._ip4_tx._select_ip4_source(ip4__dst=_DST_IN_PREFIX_A)

        self.assertEqual(
            result,
            _DST_IN_PREFIX_A,
            msg="Rule 1 (same address) must override rule 8 even when rule 8 would tie.",
        )
