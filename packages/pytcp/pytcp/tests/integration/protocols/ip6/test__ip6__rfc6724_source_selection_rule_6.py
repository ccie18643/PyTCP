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
selection rule 6 (prefer matching label per the §10.3 policy
table).

The default §10.3 prefix groups are designed so the label of
a destination usually aligns with the longest-prefix-match
candidate (rule 8). The interesting cases — and the only ones
that actually pin rule-6 behaviour — are pathological
constructions where rule 8 alone would pick the
*non*-matching-label candidate. Each test below is built so
removing rule 6 from the selector would flip the outcome.

pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection_rule_6.py

ver 3.0.9
"""

from net_addr import Ip6Address, Ip6IfAddr
from pytcp.tests.lib.ip6_testcase import Ip6TestCase


class TestRfc6724Rule6PolicyLabel(Ip6TestCase):
    """
    The RFC 6724 §5 rule 6 (prefer matching label) tests.
    """

    def test__ip6__rfc6724_rule6__matching_label_overrides_rule_8(self) -> None:
        """
        Ensure rule 6 overrides rule 8: a matching-label
        candidate with a SHORTER common prefix to the
        destination wins over a non-matching-label candidate
        with a LONGER common prefix. Constructed so the
        non-matching-label candidate would win on rule 8
        alone — the test fails if rule 6 is removed from the
        sort key.

        Concretely: dst is 2003::1 (label 1, catch-all
        ::/0). Candidate A is 2400::/16 GUA (label 1, common
        prefix 5 bits). Candidate B is 2002:cb00::/16 6to4
        (label 2, common prefix 15 bits). Rule 8 alone would
        pick B; rule 6 elevates A.

        Reference: RFC 6724 §5 rule 6 (Prefer matching label).
        Reference: RFC 6724 §10.3 (Default policy table).
        """

        host_label_1_far = Ip6IfAddr("2400::7/64")
        host_label_2_close = Ip6IfAddr("2002:cb00::7/64")
        self._packet_handler._ip6_ifaddr = [host_label_1_far, host_label_2_close]
        self._packet_handler._icmp6_slaac_addresses = []
        self._packet_handler._icmp6_temp_addresses = []

        result = self._packet_handler._ip6_tx._select_ip6_source(ip6__dst=Ip6Address("2003::1"))

        self.assertEqual(
            result,
            host_label_1_far.address,
            msg=(
                "Rule 6 must outrank rule 8: matching-label candidate wins "
                "over non-matching-label candidate with longer common prefix."
            ),
        )

    def test__ip6__rfc6724_rule6__matching_label_wins_when_prefixes_disagree(self) -> None:
        """
        Ensure rule 6 picks the matching-label candidate when
        both candidates share zero leading bits with the
        destination — rule 8 ties at 0, rule 6 breaks the tie.

        Concretely: dst is 2002:cb00::1 (label 2, 6to4).
        Candidate A is fc00:1::7 (label 13 ULA, 0 common
        bits). Candidate B is 2002:0::7 (label 2 6to4, 16
        common bits). Rule 8 picks B; rule 6 also picks B —
        the rules agree, but the test confirms rule 6 doesn't
        pick the wrong-label candidate when its score is
        explicitly considered.

        Reference: RFC 6724 §5 rule 6 (Prefer matching label).
        """

        host_ula = Ip6IfAddr("fc00:1::7/64")
        host_6to4 = Ip6IfAddr("2002:0::7/64")
        self._packet_handler._ip6_ifaddr = [host_ula, host_6to4]
        self._packet_handler._icmp6_slaac_addresses = []
        self._packet_handler._icmp6_temp_addresses = []

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=Ip6Address("2002:cb00::1"),
        )

        self.assertEqual(
            result,
            host_6to4.address,
            msg="Rule 6 must pick the 6to4 source for the 6to4 destination.",
        )

    def test__ip6__rfc6724_rule6__ula_source_for_ula_destination(self) -> None:
        """
        Ensure rule 6 picks a ULA source (label 13) for a
        ULA destination, even when a GUA candidate (label 1)
        is also present.

        Reference: RFC 6724 §5 rule 6 (Prefer matching label).
        Reference: RFC 4193 §1 (ULA scope and prefix fc00::/7).
        """

        host_gua = Ip6IfAddr("2620:0:1::7/64")
        host_ula = Ip6IfAddr("fd00:1::7/64")
        self._packet_handler._ip6_ifaddr = [host_gua, host_ula]
        self._packet_handler._icmp6_slaac_addresses = []
        self._packet_handler._icmp6_temp_addresses = []

        result = self._packet_handler._ip6_tx._select_ip6_source(ip6__dst=Ip6Address("fd99::1"))

        self.assertEqual(
            result,
            host_ula.address,
            msg="Rule 6 must pick the ULA source when destination is ULA-labeled.",
        )

    def test__ip6__rfc6724_rule6__no_label_match_falls_through_to_rule_8(self) -> None:
        """
        Ensure that when no candidate matches the
        destination's label, rule 6 collapses to a tie and
        rule 8 (longest matching prefix) decides. Both
        candidates have label != destination's label, so the
        rule-6 score is zero for both; rule 8 picks the
        prefix-closer one.

        Reference: RFC 6724 §5 (rule order; rule 8 as final tiebreak).
        """

        host_6to4 = Ip6IfAddr("2002:c612::7/64")
        host_ula = Ip6IfAddr("fd00:1::7/64")
        self._packet_handler._ip6_ifaddr = [host_6to4, host_ula]
        self._packet_handler._icmp6_slaac_addresses = []
        self._packet_handler._icmp6_temp_addresses = []

        # dst label 1 (GUA catch-all). Neither candidate matches.
        # Rule 8: 6to4 has 5 common bits with 2620::; ULA
        # has 0. 6to4 wins on prefix length.
        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=Ip6Address("2620:0:1::100"),
        )

        self.assertEqual(
            result,
            host_6to4.address,
            msg="Rule 8 fallback must pick the prefix-closer candidate when rule 6 ties.",
        )

    def test__ip6__rfc6724_rule6__rule_3_outranks_rule_6(self) -> None:
        """
        Ensure rule 3 (avoid deprecated) outranks rule 6: a
        DEPRECATED matching-label candidate loses to a
        PREFERRED non-matching-label one. The rule order is
        1 → 2 → 3 → ... → 6 → 7 → 8, so rule 3 must trump
        rule 6.

        Reference: RFC 6724 §5 (rule order: rule 3 before rule 6).
        Reference: RFC 4862 §5.5.4 (DEPRECATED state).
        """

        import time

        from net_addr import Ip6Network
        from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6SlaacAddress

        host_matching_dep = Ip6IfAddr("2002:dead::7/64")  # label 2, will be DEPRECATED
        host_non_matching_pref = Ip6IfAddr("2620:0:1::7/64")  # label 1, PREFERRED
        self._packet_handler._ip6_ifaddr = [host_matching_dep, host_non_matching_pref]

        now = time.monotonic()
        self._packet_handler._icmp6_slaac_addresses = [
            Icmp6SlaacAddress(
                address=host_matching_dep.address,
                prefix=Ip6Network("2002:dead::/64"),
                preferred_until=now - 1.0,  # DEPRECATED
                valid_until=now + 3600.0,
                router_address=Ip6Address("fe80::1"),
            ),
        ]
        self._packet_handler._icmp6_temp_addresses = []

        result = self._packet_handler._ip6_tx._select_ip6_source(
            ip6__dst=Ip6Address("2002:cb00::1"),  # label 2
        )

        self.assertEqual(
            result,
            host_non_matching_pref.address,
            msg="Rule 3 must outrank rule 6: PREFERRED non-matching beats DEPRECATED matching.",
        )
