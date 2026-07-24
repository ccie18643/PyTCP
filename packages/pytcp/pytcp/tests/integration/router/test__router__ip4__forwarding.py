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
This module contains the M1 IPv4 unicast transit-forwarding
integration tests — the RFC 1812 §5.2 forward path exercised on
the three-interface 'RouterTestCase' topology: the happy-path
forward out a connected LAN and via the default gateway, the TTL
Time-Exceeded and no-route Destination-Unreachable ICMP errors,
and the martian / oversize / unresolved-next-hop drop paths.

pytcp/tests/integration/router/test__router__ip4__forwarding.py

ver 3.0.9
"""

from net_addr import Ip4Address, Ip4Network
from pytcp import stack
from pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, HOST_A__MAC_ADDRESS
from pytcp.tests.lib.router_testcase import (
    HOST_D__IP4,
    HOST_D__MAC,
    HOST_E__IP4,
    INTERNET__IP4,
    UPSTREAM_GW__MAC,
    RouterTestCase,
)


class TestRouterIp4Forwarding(RouterTestCase):
    """
    The M1 IPv4 unicast transit-forwarding path.
    """

    def test__router__ip4__forward__connected_lan_happy_path(self) -> None:
        """
        Ensure an inbound IPv4 transit datagram destined to a host on a
        connected LAN is forwarded out that LAN's interface toward the
        host's own MAC, with the TTL decremented by one and the payload
        preserved byte-for-byte.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        Reference: RFC 1812 §5.3.1 (TTL decrement on forward).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=HOST_D__IP4,
                ttl=64,
            ),
        )

        self._assert_forwarded_ip4(
            emitted,
            egress=self.if2,
            src_ip=HOST_A__IP4_ADDRESS,
            dst_ip=HOST_D__IP4,
            ttl_out=63,
            next_hop_mac=HOST_D__MAC,
            payload=b"router-forward-test",
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward=1,
        )

    def test__router__ip4__forward__via_default_gateway(self) -> None:
        """
        Ensure an inbound IPv4 transit datagram destined off-net is
        forwarded out the upstream interface toward the default
        gateway's MAC — the next hop being the gateway, not the final
        destination — with the TTL decremented.

        Reference: RFC 1812 §5.2.4 (next-hop determination).
        Reference: RFC 1812 §5.3.1 (TTL decrement on forward).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=INTERNET__IP4,
                ttl=64,
            ),
        )

        self._assert_forwarded_ip4(
            emitted,
            egress=self.if3,
            src_ip=HOST_A__IP4_ADDRESS,
            dst_ip=INTERNET__IP4,
            ttl_out=63,
            next_hop_mac=UPSTREAM_GW__MAC,
            payload=b"router-forward-test",
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward=1,
        )

    def test__router__ip4__forward__ttl_expired_time_exceeded(self) -> None:
        """
        Ensure an inbound IPv4 transit datagram arriving with TTL 1 is
        not forwarded but instead elicits an ICMPv4 Time Exceeded (Type
        11, Code 0) back to the datagram's source.

        Reference: RFC 1812 §5.3.1 (TTL exhausted, discard).
        Reference: RFC 1812 §4.3.3.5 (Time Exceeded on TTL expiry).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=HOST_D__IP4,
                ttl=1,
            ),
        )

        self._assert_icmp4_error(
            emitted,
            ingress=self.if1,
            icmp_type=11,
            icmp_code=0,
            to_ip=HOST_A__IP4_ADDRESS,
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward_ttl_exceeded__drop=1,
        )

    def test__router__ip4__forward__no_route_dest_unreachable(self) -> None:
        """
        Ensure an inbound IPv4 transit datagram with no covering route
        is not forwarded but instead elicits an ICMPv4 Destination
        Unreachable (Type 3, Code 0 — network unreachable) back to the
        source.

        Reference: RFC 1812 §5.2.4 (next-hop determination fails).
        Reference: RFC 1812 §4.3.3.1 (Destination Unreachable, no route).
        """

        self._enable_forwarding()

        # Remove the default route so the off-net destination is
        # covered by no route at all.
        stack.ip4_fib.remove(destination=Ip4Network("0.0.0.0/0"))

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=INTERNET__IP4,
                ttl=64,
            ),
        )

        self._assert_icmp4_error(
            emitted,
            ingress=self.if1,
            icmp_type=3,
            icmp_code=0,
            to_ip=HOST_A__IP4_ADDRESS,
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward_no_route__drop=1,
        )

    def test__router__ip4__forward__martian_destination_drop(self) -> None:
        """
        Ensure an inbound IPv4 transit datagram destined to a
        link-local (martian) address is dropped with no frame emitted
        and no ICMP error.

        Reference: RFC 1812 §5.3.7 (martian-address filtering).
        Reference: RFC 3927 §2.7 (link-local scope not forwarded).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=Ip4Address("169.254.1.1"),
                ttl=64,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward_martian_dst__drop=1,
        )

    def test__router__ip4__forward__next_hop_unresolved_queued(self) -> None:
        """
        Ensure an inbound IPv4 transit datagram whose next hop cannot be
        resolved from the egress ARP cache is queued pending resolution
        (no frame emitted this pass) and counted as a no-neighbor drop.

        Reference: RFC 1812 §5.2.4 (next-hop determination).
        Reference: RFC 1122 §2.3.2.2 (queue pending address resolution).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=HOST_E__IP4,
                ttl=64,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward_no_neighbor__drop=1,
        )

    def test__router__ip4__forward__oversize_df_set_frag_needed(self) -> None:
        """
        Ensure an inbound IPv4 transit datagram larger than the egress
        MTU with the Don't-Fragment flag set is not forwarded but
        instead elicits an ICMPv4 Fragmentation Needed (Type 3, Code 4)
        carrying the egress MTU as the next-hop MTU.

        Reference: RFC 1812 §4.3.3.3 (Fragmentation Needed on DF=1 oversize).
        Reference: RFC 1191 §3 (next-hop MTU in the ICMP error).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=HOST_D__IP4,
                ttl=64,
                df=True,
                payload=b"X" * 1600,
            ),
        )

        self._assert_icmp4_error(
            emitted,
            ingress=self.if1,
            icmp_type=3,
            icmp_code=4,
            to_ip=HOST_A__IP4_ADDRESS,
            mtu=1500,
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward_too_big__drop=1,
        )

    def test__router__ip4__forward__oversize_df_clear_fragments(self) -> None:
        """
        Ensure an inbound IPv4 transit datagram larger than the egress
        MTU with the Don't-Fragment flag clear is fragmented to the
        egress MTU and forwarded out the egress interface as multiple
        fragments, each preserving the source / destination /
        Identification and carrying the decremented TTL.

        Reference: RFC 791 §3.2 (router fragments a DF=0 oversize datagram).
        Reference: RFC 1812 §5.2.6 (fragmentation on forward).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=HOST_D__IP4,
                ttl=64,
                df=False,
                payload=b"X" * 1600,
            ),
        )

        self._assert_forwarded_fragments_ip4(
            emitted,
            egress=self.if2,
            src_ip=HOST_A__IP4_ADDRESS,
            dst_ip=HOST_D__IP4,
            ttl_out=63,
            next_hop_mac=HOST_D__MAC,
            payload=b"X" * 1600,
            mtu=1500,
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward_fragmented=1,
        )

    def test__router__ip4__forward__disabled_drops_as_host(self) -> None:
        """
        Ensure that with forwarding disabled (the default) an inbound
        IPv4 transit datagram is dropped exactly as a host would —
        counted in 'ip4__dst_unknown__drop' with no forward counter
        touched and no frame emitted.

        Reference: RFC 1812 §5.2.1 (host does not forward).
        """

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip4(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=HOST_D__IP4,
                ttl=64,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unknown__drop=1,
        )
