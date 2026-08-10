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
This module contains the M5f IPv4 multicast forwarding integration
tests: replication of a transit multicast datagram to downstream
listeners, the RPF check, the no-listener drop, and link-local
multicast scope enforcement.

pytcp/tests/integration/router/test__router__ip4__mforward.py

ver 3.0.10
"""

from net_addr import Ip4Address
from net_proto import IgmpV3GroupRecord, IgmpV3RecordType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from pytcp.tests.lib.network_testcase import (
    HOST_A__MAC_ADDRESS,
    AddedInterface,
)
from pytcp.tests.lib.router_testcase import (
    INTERNET__IP4,
    UPSTREAM_GW__MAC,
    RouterTestCase,
)

# A global-scope multicast group (not the 224.0.0.0/24 link-local
# control block) a downstream host listens to.
_GROUP = Ip4Address("239.1.1.1")


class TestRouterIp4MulticastForward(RouterTestCase):
    """
    The M5f IPv4 multicast forwarding (replication) tests.
    """

    def _learn_group_on(self, *ifaces: AddedInterface, group: Ip4Address) -> None:
        """Drive a MODE_IS_EXCLUDE Report for 'group' into each interface's querier."""

        for iface in ifaces:
            self._drive_forward(
                ingress=iface,
                frame=self._build_igmp_v3_report(
                    src_ip=Ip4Address("10.0.1.50"),
                    src_mac=HOST_A__MAC_ADDRESS,
                    records=[IgmpV3GroupRecord(type=IgmpV3RecordType.MODE_IS_EXCLUDE, multicast_address=group)],
                ),
            )

    def test__router__ip4__mforward__replicates_to_listeners(self) -> None:
        """
        Ensure a transit multicast datagram is replicated out every
        interface with a downstream listener for the group, with the TTL
        decremented, and not back out the ingress interface.

        Reference: RFC 1812 §5.2.4 (multicast forwarding — last hop).
        """

        self._enable_igmp_querier(self.if1, self.if2, self.if3)
        self._learn_group_on(self.if1, self.if2, group=_GROUP)

        emitted = self._drive_forward(
            ingress=self.if3,
            frame=self._build_transit_multicast_ip4(
                src_mac=UPSTREAM_GW__MAC,
                src_ip=INTERNET__IP4,
                group=_GROUP,
                ttl=10,
            ),
        )

        self.assertEqual(
            len(emitted[self.if1.ifindex]),
            1,
            msg="A downstream-listener interface (if1) must receive one replica.",
        )
        self.assertEqual(
            len(emitted[self.if2.ifindex]),
            1,
            msg="A downstream-listener interface (if2) must receive one replica.",
        )
        self.assertEqual(
            emitted[self.if3.ifindex],
            [],
            msg="The ingress interface must not receive a replica (no loopback).",
        )

        # The replica preserves the group destination with the TTL
        # decremented by one.
        replica = PacketRx(emitted[self.if1.ifindex][0])
        EthernetParser(replica)
        Ip4Parser(replica)
        self.assertEqual(
            replica.ethernet.dst,
            _GROUP.multicast_mac,
            msg="The replica's Ethernet destination must be the group's multicast MAC.",
        )
        self.assertEqual(replica.ip4.dst, _GROUP, msg="The replica must keep the group destination.")
        self.assertEqual(replica.ip4.ttl, 9, msg="The replica's TTL must be decremented by one.")

        self._assert_iface_packet_stats_rx(
            self.if3,
            ethernet__pre_parse=1,
            ip4__pre_parse=1,
            ip4__mforward=2,
        )

    def test__router__ip4__mforward__no_listeners_dropped(self) -> None:
        """
        Ensure a transit multicast datagram with no downstream listener
        for its group is dropped rather than replicated.

        Reference: RFC 1812 §5.2.4 (forward only to interested interfaces).
        """

        self._enable_igmp_querier(self.if1, self.if2, self.if3)

        emitted = self._drive_forward(
            ingress=self.if3,
            frame=self._build_transit_multicast_ip4(
                src_mac=UPSTREAM_GW__MAC,
                src_ip=INTERNET__IP4,
                group=_GROUP,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_iface_packet_stats_rx(
            self.if3,
            ethernet__pre_parse=1,
            ip4__pre_parse=1,
            ip4__mforward_no_listeners__drop=1,
        )

    def test__router__ip4__mforward__rpf_failure_dropped(self) -> None:
        """
        Ensure a transit multicast datagram that arrives on an interface
        other than the one the unicast FIB would use to reach its source
        is dropped by the Reverse Path Forwarding check.

        Reference: RFC 1812 §5.2.4 (RPF check — multicast loop prevention).
        """

        self._enable_igmp_querier(self.if1, self.if2, self.if3)

        # The source is reachable via if3 (default route), but the
        # datagram arrives on if1 — RPF fails before any listener lookup.
        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_multicast_ip4(
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=INTERNET__IP4,
                group=_GROUP,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_iface_packet_stats_rx(
            self.if1,
            ethernet__pre_parse=1,
            ip4__pre_parse=1,
            ip4__mforward_rpf__drop=1,
        )

    def test__router__ip4__mforward__link_local_group_not_forwarded(self) -> None:
        """
        Ensure a datagram addressed to the 224.0.0.0/24 link-local
        multicast control block is never forwarded, regardless of
        listeners.

        Reference: RFC 5771 (224.0.0.0/24 link-local control block).
        Reference: RFC 1112 §6.1 (TTL-scoped local multicast).
        """

        self._enable_igmp_querier(self.if1, self.if2, self.if3)

        emitted = self._drive_forward(
            ingress=self.if3,
            frame=self._build_transit_multicast_ip4(
                src_mac=UPSTREAM_GW__MAC,
                src_ip=INTERNET__IP4,
                group=Ip4Address("224.0.0.5"),
                ttl=10,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_iface_packet_stats_rx(
            self.if3,
            ethernet__pre_parse=1,
            ip4__pre_parse=1,
            ip4__mforward_scope__drop=1,
        )
