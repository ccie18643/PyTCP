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
This module contains the M5b IGMPv3 querier integration tests: the
'igmp.mc_forwarding' activation gate, the startup General-Query burst,
the steady-state periodic General Query, and querier teardown.

pytcp/tests/integration/router/test__router__igmp__querier.py

ver 3.0.9
"""

from net_addr import Ip4Address
from pytcp.protocols.igmp import igmp__constants
from pytcp.tests.lib.network_testcase import (
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.router_testcase import RouterTestCase

# A competing querier on LAN-A with an address numerically below the
# router's own LAN-A address (10.0.1.7) — its Query wins the election
# and makes the router step down. A second, higher address loses.
_LOWER_QUERIER__IP4 = Ip4Address("10.0.1.2")
_HIGHER_QUERIER__IP4 = Ip4Address("10.0.1.99")


class TestRouterIgmpQuerier(RouterTestCase):
    """
    The M5b IGMPv3 querier General-Query emission tests.
    """

    def test__router__igmp_querier__disabled_interface_is_silent(self) -> None:
        """
        Ensure an interface whose 'igmp.mc_forwarding' switch is off does
        not take the querier role — refreshing it emits no Query and no
        Query fires over time, matching exact host behaviour.

        Reference: RFC 3376 §6 (only a multicast router is a querier).
        """

        self.if1.handler.refresh_igmp_querier()
        emitted = self._advance_frames(ms=igmp__constants.IGMP__QUERY_INTERVAL__MS * 2)

        self._assert_no_forward(emitted)
        self.assertEqual(
            self.if1.handler.packet_stats_tx.igmp__general_query__send,
            0,
            msg="A host interface (mc_forwarding off) must emit no General Query.",
        )

    def test__router__igmp_querier__startup_emits_first_general_query(self) -> None:
        """
        Ensure bringing up the querier on an interface immediately emits
        the first startup General Query to the all-systems group with the
        interface's own source address.

        Reference: RFC 3376 §6 (querier General Query emission).
        Reference: RFC 3376 §8.7 (Startup Query Count).
        """

        emitted = self._enable_igmp_querier(self.if1)

        frames = emitted[self.if1.ifindex]
        self.assertEqual(
            len(frames),
            1,
            msg=f"Querier bring-up must emit exactly one startup General Query; got {len(frames)}.",
        )
        self._assert_igmp_general_query(frames[0], source=STACK__IP4_HOST.address)
        self.assertEqual(
            emitted[self.if2.ifindex],
            [],
            msg="An interface whose querier was not brought up must stay silent.",
        )

    def test__router__igmp_querier__startup_burst_spacing(self) -> None:
        """
        Ensure a newly-elected querier sends Startup Query Count General
        Queries spaced by the Startup Query Interval before settling into
        the steady-state Query Interval.

        Reference: RFC 3376 §8.6 (Startup Query Interval).
        Reference: RFC 3376 §8.7 (Startup Query Count).
        """

        self._enable_igmp_querier(self.if1)  # startup query 1 of 2.

        # The second startup query fires one Startup Query Interval later.
        second = self._advance_frames(ms=igmp__constants.IGMP__STARTUP_QUERY_INTERVAL__MS)
        self.assertEqual(
            len(second[self.if1.ifindex]),
            1,
            msg="The second startup General Query must fire after one Startup Query Interval.",
        )
        self._assert_igmp_general_query(second[self.if1.ifindex][0], source=STACK__IP4_HOST.address)

        self.assertEqual(
            self.if1.handler.packet_stats_tx.igmp__general_query__send,
            igmp__constants.IGMP__STARTUP_QUERY_COUNT,
            msg="The querier must have emitted exactly Startup Query Count General Queries.",
        )

    def test__router__igmp_querier__steady_state_periodic_query(self) -> None:
        """
        Ensure that after the startup burst drains the querier emits a
        General Query once per Query Interval.

        Reference: RFC 3376 §8.2 (Query Interval).
        """

        self._enable_igmp_querier(self.if1)  # startup query 1.
        self._advance_frames(ms=igmp__constants.IGMP__STARTUP_QUERY_INTERVAL__MS)  # startup query 2.

        # The first steady-state query fires one Query Interval after the
        # last startup query.
        steady = self._advance_frames(ms=igmp__constants.IGMP__QUERY_INTERVAL__MS)
        self.assertEqual(
            len(steady[self.if1.ifindex]),
            1,
            msg="A steady-state General Query must fire after one Query Interval.",
        )

        # A second Query Interval elicits one more.
        steady_2 = self._advance_frames(ms=igmp__constants.IGMP__QUERY_INTERVAL__MS)
        self.assertEqual(
            len(steady_2[self.if1.ifindex]),
            1,
            msg="Steady-state General Queries must recur every Query Interval.",
        )

    def test__router__igmp_querier__general_query_advertises_timers(self) -> None:
        """
        Ensure the emitted General Query advertises the querier's Query
        Response Interval as its Max Resp Code, the Query Interval as its
        QQIC, and the Robustness Variable as its QRV.

        Reference: RFC 3376 §4.1.1 (Max Resp Code — Query Response Interval).
        Reference: RFC 3376 §4.1.7 (QQIC — Query Interval).
        Reference: RFC 3376 §4.1.6 (QRV — Robustness Variable).
        """

        emitted = self._enable_igmp_querier(self.if1)
        query = self._assert_igmp_general_query(emitted[self.if1.ifindex][0], source=STACK__IP4_HOST.address)

        self.assertEqual(
            query.max_response_time,
            igmp__constants.IGMP__QUERY_RESPONSE_INTERVAL__MS // 100,
            msg="Max Resp Code must decode to the Query Response Interval (units of 1/10 s).",
        )
        self.assertEqual(
            query.querier_query_interval,
            igmp__constants.IGMP__QUERY_INTERVAL__MS // 1000,
            msg="QQIC must decode to the Query Interval (seconds).",
        )
        self.assertEqual(
            query.qrv,
            igmp__constants.IGMP__ROBUSTNESS_VARIABLE,
            msg="QRV must carry the Robustness Variable.",
        )

    def test__router__igmp_querier__stop_cancels_queries(self) -> None:
        """
        Ensure relinquishing the querier role cancels the pending
        General-Query ticket so no further Queries fire.

        Reference: RFC 3376 §6 (querier role teardown).
        """

        self._enable_igmp_querier(self.if1)  # one startup query emitted.
        self.if1.handler.stop_igmp_querier()

        emitted = self._advance_frames(ms=igmp__constants.IGMP__QUERY_INTERVAL__MS * 2)
        self._assert_no_forward(emitted)


class TestRouterIgmpQuerierElection(RouterTestCase):
    """
    The M5b IGMPv3 querier-election tests (RFC 3376 §6.6.2).
    """

    def test__router__igmp_querier__lower_ip_query_steps_down(self) -> None:
        """
        Ensure a General Query from a source address lower than the
        router's own makes the router step down to Non-Querier — it stops
        emitting General Queries.

        Reference: RFC 3376 §6.6.2 (querier election — lowest address wins).
        """

        self._enable_igmp_querier(self.if1)  # startup query 1 emitted.
        before = self.if1.handler.packet_stats_tx.igmp__general_query__send

        self._drive_forward(
            ingress=self.if1,
            frame=self._build_igmp_general_query(src_ip=_LOWER_QUERIER__IP4, src_mac=HOST_A__MAC_ADDRESS),
        )

        self.assertEqual(
            self.if1.handler.packet_stats_rx.igmp__querier__election_lost,
            1,
            msg="A lower-address Query must make the router lose the election exactly once.",
        )

        # Having stepped down, the router emits no further General Query.
        emitted = self._advance_frames(ms=igmp__constants.IGMP__QUERY_INTERVAL__MS * 2)
        self._assert_no_forward(emitted)
        self.assertEqual(
            self.if1.handler.packet_stats_tx.igmp__general_query__send,
            before,
            msg="A stepped-down (Non-Querier) router must emit no further General Query.",
        )

    def test__router__igmp_querier__higher_ip_query_ignored(self) -> None:
        """
        Ensure a General Query from a source address higher than the
        router's own does not affect the election — the router stays
        Querier and keeps emitting General Queries.

        Reference: RFC 3376 §6.6.2 (querier election — higher address loses).
        """

        self._enable_igmp_querier(self.if1)  # startup query 1 emitted.

        self._drive_forward(
            ingress=self.if1,
            frame=self._build_igmp_general_query(src_ip=_HIGHER_QUERIER__IP4, src_mac=HOST_A__MAC_ADDRESS),
        )

        self.assertEqual(
            self.if1.handler.packet_stats_rx.igmp__querier__election_lost,
            0,
            msg="A higher-address Query must not cause the router to lose the election.",
        )

        # Still Querier — the second startup query fires on schedule.
        second = self._advance_frames(ms=igmp__constants.IGMP__STARTUP_QUERY_INTERVAL__MS)
        self.assertEqual(
            len(second[self.if1.ifindex]),
            1,
            msg="A router that stays Querier must keep emitting startup General Queries.",
        )

    def test__router__igmp_querier__resumes_after_other_querier_present(self) -> None:
        """
        Ensure a stepped-down router resumes the Querier role once the
        elected querier has been silent for the Other Querier Present
        Interval, emitting a General Query again.

        Reference: RFC 3376 §6.6.2 (resume Querier on Other Querier Present expiry).
        Reference: RFC 3376 §8.5 (Other Querier Present Interval).
        """

        self._enable_igmp_querier(self.if1)
        self._drive_forward(
            ingress=self.if1,
            frame=self._build_igmp_general_query(src_ip=_LOWER_QUERIER__IP4, src_mac=HOST_A__MAC_ADDRESS),
        )

        # Other Querier Present Interval for a Query advertising the
        # default QRV / Query Interval / Query Response Interval:
        # Robustness x Query Interval + Query Response Interval / 2.
        interval_ms = (
            igmp__constants.IGMP__ROBUSTNESS_VARIABLE * igmp__constants.IGMP__QUERY_INTERVAL__MS
            + igmp__constants.IGMP__QUERY_RESPONSE_INTERVAL__MS // 2
        )

        resumed = self._advance_frames(ms=interval_ms)
        self.assertEqual(
            len(resumed[self.if1.ifindex]),
            1,
            msg="The router must resume emitting a General Query once the other querier goes silent.",
        )
        self._assert_igmp_general_query(resumed[self.if1.ifindex][0], source=STACK__IP4_HOST.address)
