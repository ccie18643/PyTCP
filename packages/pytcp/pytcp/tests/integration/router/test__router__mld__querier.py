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
This module contains the M5d MLDv2 querier integration tests: the
'mld.mc_forwarding' activation gate, the startup General-Query burst,
the steady-state periodic Query, querier election (RFC 3810 §7.6.2),
and the router group-membership table learned from Reports (§7.4).

pytcp/tests/integration/router/test__router__mld__querier.py

ver 3.0.9
"""

from net_addr import Ip6Address
from net_proto import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from pytcp.lib.ip6_multicast_filter import Ip6MulticastFilterMode
from pytcp.protocols.icmp6 import mld__constants
from pytcp.tests.lib.network_testcase import (
    HOST_A__MAC_ADDRESS,
    STACK__IP6_HOST,
)
from pytcp.tests.lib.router_testcase import RouterTestCase

# A competing querier on LAN-A with a link address numerically below /
# above the router's own LAN-A address (2001:db8:0:1::7).
_LOWER_QUERIER__IP6 = Ip6Address("2001:db8:0:1::2")
_HIGHER_QUERIER__IP6 = Ip6Address("2001:db8:0:1::99")

# A downstream multicast group + source a LAN-A host reports interest in.
_GROUP = Ip6Address("ff05::1234")
_SOURCE = Ip6Address("2001:db8::a")


class TestRouterMldQuerier(RouterTestCase):
    """
    The M5d MLDv2 querier General-Query emission tests.
    """

    def test__router__mld_querier__disabled_interface_is_silent(self) -> None:
        """
        Ensure an interface whose 'mld.mc_forwarding' switch is off does
        not take the querier role — no Query is emitted over time.

        Reference: RFC 3810 §7 (only a multicast router is a querier).
        """

        self.if1.handler.refresh_mld_querier()
        emitted = self._advance_frames(ms=mld__constants.MLD__QUERY_INTERVAL__MS * 2)

        self._assert_no_forward(emitted)
        self.assertEqual(
            self.if1.handler.packet_stats_tx.icmp6__mld_general_query__send,
            0,
            msg="A host interface (mc_forwarding off) must emit no MLD General Query.",
        )

    def test__router__mld_querier__startup_emits_general_query(self) -> None:
        """
        Ensure bringing up the querier immediately emits the first startup
        General Query to the all-nodes group with the interface's own
        source address.

        Reference: RFC 3810 §7 (querier General Query emission).
        Reference: RFC 3810 §9.7 (Startup Query Count).
        """

        emitted = self._enable_mld_querier(self.if1)

        frames = emitted[self.if1.ifindex]
        self.assertEqual(
            len(frames),
            1,
            msg=f"Querier bring-up must emit exactly one startup General Query; got {len(frames)}.",
        )
        self._assert_mld_general_query(frames[0], source=STACK__IP6_HOST.address)

    def test__router__mld_querier__steady_state_periodic_query(self) -> None:
        """
        Ensure that after the startup burst drains the querier emits a
        General Query once per Query Interval.

        Reference: RFC 3810 §9.2 (Query Interval).
        Reference: RFC 3810 §9.6 (Startup Query Interval).
        """

        self._enable_mld_querier(self.if1)  # startup query 1.
        second = self._advance_frames(ms=mld__constants.MLD__STARTUP_QUERY_INTERVAL__MS)
        self.assertEqual(
            len(second[self.if1.ifindex]),
            1,
            msg="The second startup General Query must fire after one Startup Query Interval.",
        )

        steady = self._advance_frames(ms=mld__constants.MLD__QUERY_INTERVAL__MS)
        self.assertEqual(
            len(steady[self.if1.ifindex]),
            1,
            msg="A steady-state General Query must fire after one Query Interval.",
        )

    def test__router__mld_querier__lower_source_query_steps_down(self) -> None:
        """
        Ensure a General Query from a source address lower than the
        router's own makes the router step down to Non-Querier.

        Reference: RFC 3810 §7.6.2 (querier election — lowest address wins).
        """

        self._enable_mld_querier(self.if1)
        before = self.if1.handler.packet_stats_tx.icmp6__mld_general_query__send

        self._drive_forward(
            ingress=self.if1,
            frame=self._build_mld2_general_query(src_ip=_LOWER_QUERIER__IP6, src_mac=HOST_A__MAC_ADDRESS),
        )

        self.assertEqual(
            self.if1.handler.packet_stats_rx.icmp6__mld_query__election_lost,
            1,
            msg="A lower-address Query must make the router lose the election exactly once.",
        )
        # Advancing draws only the host's own report response to the
        # Query, not a General Query — the querier has stepped down. Assert
        # on the General-Query counter (the emitted frames also carry the
        # host solicited-node Report, which is unrelated host behaviour).
        self._advance_frames(ms=mld__constants.MLD__QUERY_INTERVAL__MS * 2)
        self.assertEqual(
            self.if1.handler.packet_stats_tx.icmp6__mld_general_query__send,
            before,
            msg="A stepped-down (Non-Querier) router must emit no further General Query.",
        )

    def test__router__mld_querier__higher_source_query_ignored(self) -> None:
        """
        Ensure a General Query from a source address higher than the
        router's own leaves it Querier, still emitting General Queries.

        Reference: RFC 3810 §7.6.2 (querier election — higher address loses).
        """

        self._enable_mld_querier(self.if1)

        self._drive_forward(
            ingress=self.if1,
            frame=self._build_mld2_general_query(src_ip=_HIGHER_QUERIER__IP6, src_mac=HOST_A__MAC_ADDRESS),
        )

        self.assertEqual(
            self.if1.handler.packet_stats_rx.icmp6__mld_query__election_lost,
            0,
            msg="A higher-address Query must not cause the router to lose the election.",
        )
        # Still Querier — the second startup General Query fires on
        # schedule (asserted on the counter; the tick also carries the
        # unrelated host Report response to the driven Query).
        self._advance_frames(ms=mld__constants.MLD__STARTUP_QUERY_INTERVAL__MS)
        self.assertEqual(
            self.if1.handler.packet_stats_tx.icmp6__mld_general_query__send,
            mld__constants.MLD__STARTUP_QUERY_COUNT,
            msg="A router that stays Querier must keep emitting startup General Queries.",
        )

    def test__router__mld_querier__resumes_after_other_querier_present(self) -> None:
        """
        Ensure a stepped-down router resumes the Querier role once the
        elected querier has been silent for the Other Querier Present
        Interval.

        Reference: RFC 3810 §7.6.2 (resume Querier on Other Querier Present expiry).
        Reference: RFC 3810 §9.5 (Other Querier Present Timeout).
        """

        self._enable_mld_querier(self.if1)
        self._drive_forward(
            ingress=self.if1,
            frame=self._build_mld2_general_query(src_ip=_LOWER_QUERIER__IP6, src_mac=HOST_A__MAC_ADDRESS),
        )

        before = self.if1.handler.packet_stats_tx.icmp6__mld_general_query__send

        interval_ms = (
            mld__constants.MLD__ROBUSTNESS_VARIABLE * mld__constants.MLD__QUERY_INTERVAL__MS
            + mld__constants.MLD__QUERY_RESPONSE_INTERVAL__MS // 2
        )
        self._advance_frames(ms=interval_ms)

        self.assertGreater(
            self.if1.handler.packet_stats_tx.icmp6__mld_general_query__send,
            before,
            msg="The router must resume emitting a General Query once the other querier goes silent.",
        )


class TestRouterMldQuerierMembership(RouterTestCase):
    """
    The M5d MLDv2 querier group-membership-table tests (RFC 3810 §7.4).
    """

    def _memberships(self) -> dict[Ip6Address, Ip6MulticastFilterMode]:
        """Map the router-learned memberships on if1 to their filter mode."""

        return {m.group: m.filter_mode for m in self.if1.handler.mld_querier_memberships()}

    def test__router__mld_querier__learns_exclude_membership(self) -> None:
        """
        Ensure a MODE_IS_EXCLUDE Report for a group installs an
        EXCLUDE-mode router membership entry for it.

        Reference: RFC 3810 §7.4 (router action on a MODE_IS_EXCLUDE record).
        """

        self._enable_mld_querier(self.if1)

        self._drive_forward(
            ingress=self.if1,
            frame=self._build_mld2_report(
                src_ip=STACK__IP6_HOST.address,
                src_mac=HOST_A__MAC_ADDRESS,
                records=[
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                        multicast_address=_GROUP,
                    )
                ],
            ),
        )

        self.assertEqual(
            self._memberships().get(_GROUP),
            Ip6MulticastFilterMode.EXCLUDE,
            msg="A MODE_IS_EXCLUDE Report must install an EXCLUDE router membership.",
        )
        self.assertEqual(
            self.if1.handler.packet_stats_rx.icmp6__mld2_report__querier_learn,
            1,
            msg="Learning a membership from a Report must bump the querier-learn counter once.",
        )

    def test__router__mld_querier__learns_include_membership_with_source(self) -> None:
        """
        Ensure a MODE_IS_INCLUDE Report with a source list installs an
        INCLUDE-mode router membership carrying those sources.

        Reference: RFC 3810 §7.4 (router action on a MODE_IS_INCLUDE record).
        """

        self._enable_mld_querier(self.if1)

        self._drive_forward(
            ingress=self.if1,
            frame=self._build_mld2_report(
                src_ip=STACK__IP6_HOST.address,
                src_mac=HOST_A__MAC_ADDRESS,
                records=[
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                        multicast_address=_GROUP,
                        source_addresses=[_SOURCE],
                    )
                ],
            ),
        )

        memberships = {m.group: m for m in self.if1.handler.mld_querier_memberships()}
        self.assertIn(_GROUP, memberships, msg="A MODE_IS_INCLUDE Report with sources must install a membership.")
        self.assertEqual(
            memberships[_GROUP].filter_mode,
            Ip6MulticastFilterMode.INCLUDE,
            msg="A MODE_IS_INCLUDE Report must install an INCLUDE router membership.",
        )
        self.assertEqual(
            memberships[_GROUP].sources,
            frozenset({_SOURCE}),
            msg="The INCLUDE router membership must carry the reported source list.",
        )

    def test__router__mld_querier__membership_expires_after_interval(self) -> None:
        """
        Ensure a learned membership is pruned once the Multicast Address
        Listening Interval elapses with no refreshing Report.

        Reference: RFC 3810 §7.2.4 (group timer expiry prunes membership).
        Reference: RFC 3810 §9.4 (Multicast Address Listening Interval).
        """

        self._enable_mld_querier(self.if1)
        self._drive_forward(
            ingress=self.if1,
            frame=self._build_mld2_report(
                src_ip=STACK__IP6_HOST.address,
                src_mac=HOST_A__MAC_ADDRESS,
                records=[
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                        multicast_address=_GROUP,
                    )
                ],
            ),
        )
        self.assertIn(_GROUP, self._memberships(), msg="Precondition: the group must be learned first.")

        interval_ms = (
            mld__constants.MLD__ROBUSTNESS_VARIABLE * mld__constants.MLD__QUERY_INTERVAL__MS
            + mld__constants.MLD__QUERY_RESPONSE_INTERVAL__MS
        )
        self._advance_frames(ms=interval_ms)

        self.assertNotIn(
            _GROUP,
            self._memberships(),
            msg="A membership with no refreshing Report must expire after the listening interval.",
        )
