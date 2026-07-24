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
Integration tests for the RFC 6724 default source-address
selection algorithm — rules 1, 2, 3, and 8.

Exercises 'Ip6TxHandler._select_ip6_source' against an in-memory
host list with mixed scopes, deprecated/preferred SLAAC entries,
and overlapping prefixes. Rule 7 (temporary-address preference)
is covered by a separate file.

pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection.py

ver 3.0.9
"""

import time
from typing import override

from net_addr import Ip6Address, Ip6IfAddr, Ip6Network
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6SlaacAddress
from pytcp.tests.lib.ip6_testcase import Ip6TestCase

# Stack-host fixtures used as candidate sources. Three /64s on the
# same link, plus a link-local. The link-local is what every IPv6
# host autoconfigures; the three global hosts let us exercise
# rule-2 scope matching, rule-3 deprecated-avoidance, and rule-8
# longest-match in isolation.
_HOST_LINK_LOCAL = Ip6IfAddr("fe80::7/64")
_HOST_PREFIX_A = Ip6IfAddr("2001:db8:0:1::7/64")
_HOST_PREFIX_B = Ip6IfAddr("2001:db8:0:2::7/64")
_HOST_PREFIX_C = Ip6IfAddr("2001:db8:0:3::7/64")

# Destinations used to exercise individual rules.
_DST_LINK_LOCAL = Ip6Address("fe80::91")
_DST_IN_PREFIX_A = Ip6Address("2001:db8:0:1::91")
_DST_IN_PREFIX_B = Ip6Address("2001:db8:0:2::91")
_DST_OUTSIDE_ALL = Ip6Address("2001:db8:9:9::91")


class TestRfc6724Rule1SameAddress(Ip6TestCase):
    """
    RFC 6724 §5 rule 1 — prefer same address — tests.
    """

    @override
    def setUp(self) -> None:
        """
        Populate '_ip6_ifaddr' with one stack address whose value
        coincides with the destination used in the rule-1 case.
        """

        super().setUp()
        self._packet_handler._ip6_ifaddr = [_HOST_PREFIX_A]
        self._packet_handler._icmp6_slaac_addresses = []

    def test__ip6__rfc6724_rule1__dst_equals_candidate__returns_dst(self) -> None:
        """
        Ensure that when the destination address is also one of
        the stack's owned source addresses, the selector returns
        that address verbatim — covering the trivial loopback /
        self-traffic case where the kernel must not pick any
        other candidate even if rule 8 would later prefer it.

        Reference: RFC 6724 §5 rule 1 (Prefer same address).
        """

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=_HOST_PREFIX_A.address,
        )

        self.assertEqual(
            result,
            _HOST_PREFIX_A.address,
            msg="Rule 1 must return the destination when it equals an owned source.",
        )


class TestRfc6724Rule2Scope(Ip6TestCase):
    """
    RFC 6724 §5 rule 2 — prefer appropriate scope — tests.
    """

    @override
    def setUp(self) -> None:
        """
        Populate '_ip6_ifaddr' with one link-local and one global
        candidate so the selector has to choose between scopes.
        """

        super().setUp()
        self._packet_handler._ip6_ifaddr = [_HOST_LINK_LOCAL, _HOST_PREFIX_A]
        self._packet_handler._icmp6_slaac_addresses = []

    def test__ip6__rfc6724_rule2__global_dst_picks_global_source(self) -> None:
        """
        Ensure a global destination drives the selector to the
        global candidate even when a link-local candidate is
        also present, preventing scope leak (link-local source
        for off-link destination).

        Reference: RFC 6724 §5 rule 2 (Prefer appropriate scope).
        Reference: RFC 4007 §5 (Scope of an IPv6 address).
        """

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=_DST_OUTSIDE_ALL,
        )

        self.assertEqual(
            result,
            _HOST_PREFIX_A.address,
            msg="Rule 2 must avoid link-local source for global destination.",
        )

    def test__ip6__rfc6724_rule2__link_local_dst_picks_link_local_source(self) -> None:
        """
        Ensure a link-local destination drives the selector to
        the link-local candidate, picking the smallest scope
        that still covers the destination.

        Reference: RFC 6724 §5 rule 2 (Prefer appropriate scope).
        """

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=_DST_LINK_LOCAL,
        )

        self.assertEqual(
            result,
            _HOST_LINK_LOCAL.address,
            msg="Rule 2 must prefer link-local source for link-local destination.",
        )

    def test__ip6__rfc6724_rule2__only_smaller_scope_available__returns_none(self) -> None:
        """
        Ensure the selector returns None when no candidate has
        scope wide enough to cover the destination — emitting
        a link-local source for a global destination would
        produce a structurally broken packet (no peer can
        route a reply back). The caller drops with
        DROPPED__IP6__SRC_UNSPECIFIED, which is the correct
        outcome ("no usable source for this destination")
        rather than emitting an off-link-leaking packet.

        Reference: RFC 6724 §5 rule 2 (Prefer appropriate scope).
        Reference: RFC 4007 §6 (a node may not send a packet
        with a source address of smaller scope than the
        destination).
        Reference: RFC 4291 §2.5.6 (link-local addresses MUST
        NOT leak off-link).
        """

        self._packet_handler._ip6_ifaddr = [_HOST_LINK_LOCAL]

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=_DST_OUTSIDE_ALL,
        )

        self.assertIsNone(
            result,
            msg=(
                "Selector must return None when every candidate's scope is below "
                "the destination's — a link-local source for a global destination "
                "would violate RFC 4007 §6."
            ),
        )

    def test__ip6__rfc6724_rule2__only_link_local_owned__link_local_mcast_dst__returns_link_local(self) -> None:
        """
        Ensure a link-local source is selected for a link-local
        multicast destination (ff02::/16) even when no global
        source exists — link-local scope on both sides is the
        canonical ND case (all-nodes ff02::1, solicited-node
        ff02::1:ff00::/104, all-routers ff02::2). The scope-
        mismatch gate must not break this.

        Reference: RFC 6724 §5 rule 2 (Prefer appropriate scope).
        Reference: RFC 4291 §2.7 (multicast scope encoding;
        ff02:: has scop=2 = link-local).
        """

        self._packet_handler._ip6_ifaddr = [_HOST_LINK_LOCAL]

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=Ip6Address("ff02::1"),
        )

        self.assertEqual(
            result,
            _HOST_LINK_LOCAL.address,
            msg="Link-local src must be selected for ff02:: link-local multicast dst.",
        )

    def test__ip6__rfc6724_rule2__only_link_local_owned__global_mcast_dst__returns_none(self) -> None:
        """
        Ensure the selector returns None when only link-local
        sources exist and the destination is a global-scope
        multicast (ff0e::/16) — same scope rule as for unicast
        destinations, just expressed via the multicast scop
        nibble.

        Reference: RFC 4291 §2.7 (multicast scope encoding;
        ff0e:: has scop=E = global).
        Reference: RFC 4007 §6 (source scope must be >= dest
        scope).
        """

        self._packet_handler._ip6_ifaddr = [_HOST_LINK_LOCAL]

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=Ip6Address("ff0e::1"),
        )

        self.assertIsNone(
            result,
            msg="Link-local src must NOT be selected for ff0e:: global multicast dst.",
        )


class TestRfc6724Rule3Deprecated(Ip6TestCase):
    """
    RFC 6724 §5 rule 3 — avoid deprecated addresses — tests.
    """

    @override
    def setUp(self) -> None:
        """
        Populate '_ip6_ifaddr' with two SLAAC-derived candidates and
        '_icmp6_slaac_addresses' with one PREFERRED entry and one
        DEPRECATED entry so rule 3 has data to act on.
        """

        super().setUp()
        self._packet_handler._ip6_ifaddr = [_HOST_PREFIX_A, _HOST_PREFIX_B]
        now = time.monotonic()
        self._packet_handler._icmp6_slaac_addresses = [
            Icmp6SlaacAddress(
                address=_HOST_PREFIX_A.address,
                prefix=Ip6Network("2001:db8:0:1::/64"),
                preferred_until=now - 1.0,  # already deprecated
                valid_until=now + 3600.0,
                router_address=Ip6Address("fe80::1"),
            ),
            Icmp6SlaacAddress(
                address=_HOST_PREFIX_B.address,
                prefix=Ip6Network("2001:db8:0:2::/64"),
                preferred_until=now + 3600.0,
                valid_until=now + 7200.0,
                router_address=Ip6Address("fe80::1"),
            ),
        ]

    def test__ip6__rfc6724_rule3__prefer_preferred_over_deprecated(self) -> None:
        """
        Ensure the selector avoids a SLAAC source whose preferred
        lifetime has expired (DEPRECATED state) when at least one
        PREFERRED candidate exists at the same scope, even if the
        DEPRECATED candidate would otherwise win on rule 8 (closer
        prefix).

        Reference: RFC 6724 §5 rule 3 (Avoid deprecated addresses).
        Reference: RFC 4862 §5.5.4 (PREFERRED / DEPRECATED state machine).
        """

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=_DST_IN_PREFIX_A,
        )

        self.assertEqual(
            result,
            _HOST_PREFIX_B.address,
            msg=(
                "Rule 3 must prefer the PREFERRED candidate even when a DEPRECATED "
                "candidate has a longer matching prefix."
            ),
        )

    def test__ip6__rfc6724_rule3__non_slaac_addresses_treated_as_preferred(self) -> None:
        """
        Ensure that addresses absent from '_icmp6_slaac_addresses'
        (manually configured / link-local) are treated as
        PREFERRED — only SLAAC entries explicitly tracked as
        DEPRECATED are deprioritised.

        Reference: RFC 6724 §5 rule 3 (Avoid deprecated addresses).
        Reference: RFC 4862 §5.5.4 (state applies to autoconfigured addresses).
        """

        self._packet_handler._ip6_ifaddr = [_HOST_PREFIX_A, _HOST_PREFIX_C]
        # _HOST_PREFIX_A is DEPRECATED in the slaac list. _HOST_PREFIX_C
        # is absent — therefore PREFERRED by default.
        self._packet_handler._icmp6_slaac_addresses = [
            a for a in self._packet_handler._icmp6_slaac_addresses if a.address == _HOST_PREFIX_A.address
        ]

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=_DST_IN_PREFIX_A,
        )

        self.assertEqual(
            result,
            _HOST_PREFIX_C.address,
            msg=(
                "Rule 3 must treat untracked (non-SLAAC) addresses as PREFERRED "
                "and prefer them over a tracked DEPRECATED SLAAC address."
            ),
        )


class TestRfc6724Rule8LongestMatch(Ip6TestCase):
    """
    RFC 6724 §5 rule 8 — longest matching prefix — tests.
    """

    @override
    def setUp(self) -> None:
        """
        Populate '_ip6_ifaddr' with three same-scope same-state
        candidates whose prefixes differ in the third hextet so
        the selector has a clean rule-8 tiebreak after rules 1,
        2, 3 collapse into ties.
        """

        super().setUp()
        self._packet_handler._ip6_ifaddr = [
            _HOST_PREFIX_A,
            _HOST_PREFIX_B,
            _HOST_PREFIX_C,
        ]
        self._packet_handler._icmp6_slaac_addresses = []

    def test__ip6__rfc6724_rule8__picks_longest_common_prefix(self) -> None:
        """
        Ensure rule 8 picks the candidate with the most leading
        bits in common with the destination when rules 1, 2, 3
        all tie. The destination is in prefix B's /64, so prefix
        B's host address must win even though A and C are also
        valid global candidates.

        Reference: RFC 6724 §5 rule 8 (Use longest matching prefix).
        Reference: RFC 6724 §2.2 (CommonPrefixLen definition).
        """

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=_DST_IN_PREFIX_B,
        )

        self.assertEqual(
            result,
            _HOST_PREFIX_B.address,
            msg="Rule 8 must pick the candidate whose prefix matches the destination.",
        )

    def test__ip6__rfc6724_rule8__deterministic_when_no_prefix_overlap(self) -> None:
        """
        Ensure rule 8 produces a deterministic answer when no
        candidate's prefix covers the destination — among
        otherwise-equal candidates the one with the longest
        common prefix to the destination is chosen, never a
        random or arrival-order pick.

        Reference: RFC 6724 §5 rule 8 (Use longest matching prefix).
        """

        result_a = self._packet_handler._ip6_tx._select_ip6_source(ip6__dst=_DST_OUTSIDE_ALL)
        result_b = self._packet_handler._ip6_tx._select_ip6_source(ip6__dst=_DST_OUTSIDE_ALL)

        self.assertIsNotNone(result_a, msg="Rule 8 must always return a candidate when one exists.")
        self.assertEqual(
            result_a,
            result_b,
            msg="Rule 8 outcome must be deterministic across repeated calls.",
        )


class TestRfc6724SelectorBoundaries(Ip6TestCase):
    """
    The 'Ip6TxHandler._select_ip6_source' boundary tests.
    """

    def test__ip6__rfc6724__no_candidates_returns_none(self) -> None:
        """
        Ensure the selector returns None when '_ip6_ifaddr' is
        empty — the IPv6 TX path must fall back to the existing
        DROPPED__IP6__SRC_UNSPECIFIED handling rather than
        raise.

        Reference: RFC 6724 §5 (Source Address Selection).
        """

        self._packet_handler._ip6_ifaddr = []

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=_DST_OUTSIDE_ALL,
        )

        self.assertIsNone(
            result,
            msg="Selector must return None when no candidate sources exist.",
        )

    def test__ip6__rfc6724__rules_compose_in_priority_order(self) -> None:
        """
        Ensure rules 1, 2, 3, 8 compose in priority order: a
        rule-1 hit overrides any subsequent rule-3 deprecation,
        and a rule-2 scope mismatch overrides any rule-8
        prefix-overlap. This pins the lex-tuple sort key against
        regressions that re-order the rules.

        Reference: RFC 6724 §5 (Source Address Selection — rule order).
        """

        # Configuration: dst == _HOST_PREFIX_A.address (rule 1 hits)
        # AND _HOST_PREFIX_A is DEPRECATED (rule 3 would skip it)
        # AND _HOST_PREFIX_B is PREFERRED (rule 3 would prefer it)
        # Rule 1 must win.
        now = time.monotonic()
        self._packet_handler._ip6_ifaddr = [_HOST_PREFIX_A, _HOST_PREFIX_B]
        self._packet_handler._icmp6_slaac_addresses = [
            Icmp6SlaacAddress(
                address=_HOST_PREFIX_A.address,
                prefix=Ip6Network("2001:db8:0:1::/64"),
                preferred_until=now - 1.0,
                valid_until=now + 3600.0,
                router_address=Ip6Address("fe80::1"),
            ),
            Icmp6SlaacAddress(
                address=_HOST_PREFIX_B.address,
                prefix=Ip6Network("2001:db8:0:2::/64"),
                preferred_until=now + 3600.0,
                valid_until=now + 7200.0,
                router_address=Ip6Address("fe80::1"),
            ),
        ]

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=_HOST_PREFIX_A.address,
        )

        self.assertEqual(
            result,
            _HOST_PREFIX_A.address,
            msg="Rule 1 (same address) must override rule 3 (avoid deprecated).",
        )
