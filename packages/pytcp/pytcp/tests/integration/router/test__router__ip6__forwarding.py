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
This module contains the M1 IPv6 unicast transit-forwarding
integration tests — the RFC 1812 §5.2 forward path exercised on
the three-interface 'RouterTestCase' topology: the happy-path
forward out a connected LAN and via the default gateway, the
Hop-Limit Time-Exceeded and no-route Destination-Unreachable
ICMPv6 errors, and the scope / oversize / unresolved-next-hop
drop paths.

pytcp/tests/integration/router/test__router__ip6__forwarding.py

ver 3.0.10
"""

from net_addr import Ip6Address, Ip6Network
from pytcp import stack
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.tests.lib.network_testcase import HOST_A__IP6_ADDRESS, HOST_A__MAC_ADDRESS
from pytcp.tests.lib.router_testcase import (
    HOST_D__IP6,
    HOST_D__MAC,
    HOST_E__IP6,
    INTERNET__IP6,
    LAN_B_GW__IP6,
    LAN_B_GW__MAC,
    UPSTREAM_GW__MAC,
    RouterTestCase,
)


class TestRouterIp6Forwarding(RouterTestCase):
    """
    The M1 IPv6 unicast transit-forwarding path.
    """

    def test__router__ip6__forward__connected_lan_happy_path(self) -> None:
        """
        Ensure an inbound IPv6 transit datagram destined to a host on a
        connected LAN is forwarded out that LAN's interface toward the
        host's own MAC, with the Hop-Limit decremented by one and the
        payload preserved byte-for-byte.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        Reference: RFC 8200 §3 (Hop-Limit decrement on forward).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP6_ADDRESS,
                dst_ip=HOST_D__IP6,
                hop=64,
            ),
        )

        self._assert_forwarded_ip6(
            emitted,
            egress=self.if2,
            src_ip=HOST_A__IP6_ADDRESS,
            dst_ip=HOST_D__IP6,
            hop_out=63,
            next_hop_mac=HOST_D__MAC,
            payload=b"router-forward-test",
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__forward=1,
        )

    def test__router__ip6__forward__via_default_gateway(self) -> None:
        """
        Ensure an inbound IPv6 transit datagram destined off-net is
        forwarded out the upstream interface toward the default
        gateway's MAC, with the Hop-Limit decremented.

        Reference: RFC 1812 §5.2.4 (next-hop determination).
        Reference: RFC 8200 §3 (Hop-Limit decrement on forward).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP6_ADDRESS,
                dst_ip=INTERNET__IP6,
                hop=64,
            ),
        )

        self._assert_forwarded_ip6(
            emitted,
            egress=self.if3,
            src_ip=HOST_A__IP6_ADDRESS,
            dst_ip=INTERNET__IP6,
            hop_out=63,
            next_hop_mac=UPSTREAM_GW__MAC,
            payload=b"router-forward-test",
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__forward=1,
        )

    def test__router__ip6__forward__hop_expired_time_exceeded(self) -> None:
        """
        Ensure an inbound IPv6 transit datagram arriving with Hop-Limit
        1 is not forwarded but instead elicits an ICMPv6 Time Exceeded
        (Type 3, Code 0) back to the datagram's source.

        Reference: RFC 8200 §3 (Hop-Limit exhausted, discard).
        Reference: RFC 4443 §3.3 (Time Exceeded on Hop-Limit expiry).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP6_ADDRESS,
                dst_ip=HOST_D__IP6,
                hop=1,
            ),
        )

        self._assert_icmp6_error(
            emitted,
            ingress=self.if1,
            icmp_type=3,
            icmp_code=0,
            to_ip=HOST_A__IP6_ADDRESS,
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__forward_hop_exceeded__drop=1,
        )

    def test__router__ip6__forward__no_route_dest_unreachable(self) -> None:
        """
        Ensure an inbound IPv6 transit datagram with no covering route
        is not forwarded but instead elicits an ICMPv6 Destination
        Unreachable (Type 1, Code 0 — no route) back to the source.

        Reference: RFC 1812 §5.2.4 (next-hop determination fails).
        Reference: RFC 4443 §3.1 (Destination Unreachable, no route).
        """

        self._enable_forwarding()

        # Remove the default route so the off-net destination is
        # covered by no route at all.
        stack.ip6_fib.remove(destination=Ip6Network("::/0"))

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP6_ADDRESS,
                dst_ip=INTERNET__IP6,
                hop=64,
            ),
        )

        self._assert_icmp6_error(
            emitted,
            ingress=self.if1,
            icmp_type=1,
            icmp_code=0,
            to_ip=HOST_A__IP6_ADDRESS,
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__forward_no_route__drop=1,
        )

    def test__router__ip6__forward__link_local_scope_drop(self) -> None:
        """
        Ensure an inbound IPv6 transit datagram destined to a
        link-local address is dropped (never forwarded off-link) with
        no frame emitted and no ICMP error.

        Reference: RFC 4007 §9 (link-local scope not forwarded).
        Reference: RFC 1812 §5.3.7 (scope-based filtering).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP6_ADDRESS,
                dst_ip=Ip6Address("fe80::99"),
                hop=64,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__forward_scope__drop=1,
        )

    def test__router__ip6__forward__link_local_source_scope_drop(self) -> None:
        """
        Ensure an inbound IPv6 transit datagram whose SOURCE is a
        link-local address is dropped (a link-local source must never be
        forwarded across interfaces) with no frame emitted.

        Reference: RFC 4007 §9 (link-local scope not forwarded off-link).
        Reference: RFC 1812 §5.3.7 (scope-based source filtering).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=Ip6Address("fe80::91"),
                dst_ip=INTERNET__IP6,
                hop=64,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__forward_scope__drop=1,
        )

    def test__router__ip6__forward__next_hop_unresolved_queued(self) -> None:
        """
        Ensure an inbound IPv6 transit datagram whose next hop cannot be
        resolved from the egress ND cache is queued pending resolution
        (no frame emitted this pass) and counted as a no-neighbor drop.

        Reference: RFC 1812 §5.2.4 (next-hop determination).
        Reference: RFC 1122 §2.3.2.2 (queue pending address resolution).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP6_ADDRESS,
                dst_ip=HOST_E__IP6,
                hop=64,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__forward_no_neighbor__drop=1,
        )

    def test__router__ip6__forward__oversize_packet_too_big(self) -> None:
        """
        Ensure an inbound IPv6 transit datagram larger than the egress
        MTU is not forwarded (routers never fragment IPv6) but instead
        elicits an ICMPv6 Packet Too Big (Type 2) carrying the egress
        MTU as the next-hop MTU, back to the source.

        Reference: RFC 8200 §5 (routers never fragment IPv6).
        Reference: RFC 4443 §3.2 (Packet Too Big).
        Reference: RFC 8201 §3 (next-hop MTU in the ICMP error).
        """

        self._enable_forwarding()

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP6_ADDRESS,
                dst_ip=HOST_D__IP6,
                hop=64,
                payload=b"X" * 1600,
            ),
        )

        self._assert_icmp6_packet_too_big(
            emitted,
            ingress=self.if1,
            mtu=1500,
            to_ip=HOST_A__IP6_ADDRESS,
        )
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__forward_too_big__drop=1,
        )

    def test__router__ip6__forward__hairpin_emits_redirect(self) -> None:
        """
        Ensure a datagram forwarded back out the interface it arrived on
        (next hop on-link to the source) elicits an ICMPv6 ND Redirect,
        sourced from the interface link-local address, advertising the
        better first hop, while the triggering datagram is still
        forwarded toward that next hop.

        Reference: RFC 4861 §8 (ICMPv6 Redirect on same-interface forward).
        Reference: RFC 4861 §4.5 (Redirect source is link-local).
        """

        self._enable_forwarding()
        # More-specific route sending 2001:db8:0:9::/64 back out LAN-B via
        # a gateway on LAN-B — makes ingress == egress (if2) a hairpin.
        stack.ip6_fib.add(
            route=Route(
                destination=Ip6Network("2001:db8:0:9::/64"),
                gateway=LAN_B_GW__IP6,
                oif=self.if2.ifindex,
                protocol=RouteProtocol.STATIC,
            )
        )

        emitted = self._drive_forward(
            ingress=self.if2,
            frame=self._build_transit_ip6(
                ingress=self.if2,
                src_mac=HOST_D__MAC,
                src_ip=HOST_D__IP6,
                dst_ip=INTERNET__IP6,
                hop=64,
            ),
        )

        self._assert_redirect_and_forward_ip6(
            emitted,
            iface=self.if2,
            src_ip=HOST_D__IP6,
            dst_ip=INTERNET__IP6,
            target=LAN_B_GW__IP6,
            next_hop_mac=LAN_B_GW__MAC,
            hop_out=63,
            payload=b"router-forward-test",
        )
        self._assert_iface_packet_stats_rx(
            self.if2,
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__forward=1,
            ip6__forward_redirect=1,
        )

    def test__router__ip6__forward__disabled_drops_as_host(self) -> None:
        """
        Ensure that with forwarding disabled (the default) an inbound
        IPv6 transit datagram is dropped exactly as a host would —
        counted in 'ip6__dst_unknown__drop' with no forward counter
        touched and no frame emitted.

        Reference: RFC 1812 §5.2.1 (host does not forward).
        """

        emitted = self._drive_forward(
            ingress=self.if1,
            frame=self._build_transit_ip6(
                ingress=self.if1,
                src_mac=HOST_A__MAC_ADDRESS,
                src_ip=HOST_A__IP6_ADDRESS,
                dst_ip=HOST_D__IP6,
                hop=64,
            ),
        )

        self._assert_no_forward(emitted)
        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip6__pre_parse=1,
            ip6__dst_unknown__drop=1,
        )
