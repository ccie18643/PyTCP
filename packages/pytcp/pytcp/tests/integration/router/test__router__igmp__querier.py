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

from pytcp.protocols.igmp import igmp__constants
from pytcp.tests.lib.network_testcase import STACK__IP4_HOST
from pytcp.tests.lib.router_testcase import RouterTestCase


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
