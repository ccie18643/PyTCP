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

from net_addr import Buffer, Ip4Address, Ip4Network
from net_proto import (
    Icmp4Assembler,
    Icmp4MessageRedirect,
    Icmp4RedirectCode,
    Ip4Assembler,
    UdpAssembler,
)
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pytcp import stack
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.router_testcase import (
    HOST_D__IP4,
    HOST_D__MAC,
    HOST_E__IP4,
    INTERNET__IP4,
    LAN_B_GW__IP4,
    LAN_B_GW__MAC,
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

    def _install_hairpin_route(self) -> None:
        """
        Install a more-specific route sending 198.51.100.0/24 back out
        LAN-B via a gateway on LAN-B, so a datagram from a LAN-B host to
        that network is forwarded out the interface it arrived on
        (ingress == egress) — the ICMP-Redirect hairpin condition.
        """

        stack.ip4_fib.add(
            route=Route(
                destination=Ip4Network("198.51.100.0/24"),
                gateway=LAN_B_GW__IP4,
                oif=self.if2.ifindex,
                protocol=RouteProtocol.STATIC,
            )
        )

    def test__router__ip4__forward__hairpin_emits_redirect(self) -> None:
        """
        Ensure a datagram forwarded back out the interface it arrived on
        (next hop on-link to the source) elicits an ICMPv4 Redirect
        advising the better first hop, while the triggering datagram is
        still forwarded toward that next hop.

        Reference: RFC 1812 §5.2.7.2 (ICMP Redirect on same-interface forward).
        """

        self._enable_forwarding()
        self._install_hairpin_route()

        emitted = self._drive_forward(
            ingress=self.if2,
            frame=self._build_transit_ip4(
                ingress=self.if2,
                src_mac=HOST_D__MAC,
                src_ip=HOST_D__IP4,
                dst_ip=INTERNET__IP4,
                ttl=64,
            ),
        )

        self._assert_redirect_and_forward_ip4(
            emitted,
            iface=self.if2,
            src_ip=HOST_D__IP4,
            dst_ip=INTERNET__IP4,
            gateway=LAN_B_GW__IP4,
            next_hop_mac=LAN_B_GW__MAC,
            ttl_out=63,
            payload=b"router-forward-test",
        )
        self._assert_iface_packet_stats_rx(
            self.if2,
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward=1,
            ip4__forward_redirect=1,
        )

    def test__router__ip4__forward__cross_interface_no_redirect(self) -> None:
        """
        Ensure a datagram forwarded out a different interface than it
        arrived on does not elicit an ICMP Redirect (the source could not
        reach the next hop directly).

        Reference: RFC 1812 §5.2.7.2 (Redirect only on same-interface forward).
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

    def test__router__ip4__forward__hairpin_send_redirects_disabled_suppresses(self) -> None:
        """
        Ensure that with 'ip4.send_redirects' disabled on the ingress
        interface a hairpin forward still forwards the datagram but emits
        no ICMP Redirect.

        Reference: RFC 1812 §5.2.7.2 (send_redirects gate).
        Reference: Linux net.ipv4.conf.<iface>.send_redirects.
        """

        self._enable_forwarding()
        self._install_hairpin_route()
        # The harness interfaces carry no name, so target the 'default'
        # per-interface template slot to disable send_redirects.
        sysctl_module.set("ip4.default.send_redirects", False)

        emitted = self._drive_forward(
            ingress=self.if2,
            frame=self._build_transit_ip4(
                ingress=self.if2,
                src_mac=HOST_D__MAC,
                src_ip=HOST_D__IP4,
                dst_ip=INTERNET__IP4,
                ttl=64,
            ),
        )

        self._assert_forwarded_ip4(
            emitted,
            egress=self.if2,
            src_ip=HOST_D__IP4,
            dst_ip=INTERNET__IP4,
            ttl_out=63,
            next_hop_mac=LAN_B_GW__MAC,
            payload=b"router-forward-test",
        )
        self._assert_iface_packet_stats_rx(
            self.if2,
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__forward=1,
        )

    def _build_icmp4_redirect_rx(self, *, gateway: Ip4Address, embedded_dst: Ip4Address) -> bytes:
        """
        Build an inbound ICMPv4 Redirect frame from an on-link router
        (HOST_A) to the stack, advising 'gateway' as the better first hop
        for 'embedded_dst'. The embedded datagram is a well-formed IPv4/UDP
        packet the stack originally sent toward 'embedded_dst'.
        """

        embedded = Ip4Assembler(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=embedded_dst,
            ip4__payload=UdpAssembler(udp__sport=40000, udp__dport=40000, udp__payload=b"12345678"),
        )
        redirect = Icmp4Assembler(
            icmp4__message=Icmp4MessageRedirect(
                code=Icmp4RedirectCode.HOST,
                gateway=gateway,
                data=bytes(embedded),
            ),
        )
        ip4 = Ip4Assembler(
            ip4__src=HOST_A__IP4_ADDRESS,
            ip4__dst=STACK__IP4_HOST.address,
            ip4__payload=redirect,
        )
        eth = EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=ip4,
        )
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def test__router__ip4__redirect_rx__accepted_installs_route(self) -> None:
        """
        Ensure an inbound ICMPv4 Redirect advising an on-link gateway
        installs a per-destination host route toward that gateway when
        'ip4.accept_redirects' is enabled.

        Reference: RFC 1122 §3.3.1.2 (host accepts a Redirect).
        """

        self.if1.handler._phrx_ethernet(
            PacketRx(
                self._build_icmp4_redirect_rx(
                    gateway=Ip4Address("10.0.1.50"),
                    embedded_dst=INTERNET__IP4,
                )
            )
        )

        routes = [
            route
            for route in stack.ip4_fib.snapshot()
            if route.protocol is RouteProtocol.REDIRECT and route.destination == Ip4Network("198.51.100.10/32")
        ]
        self.assertEqual(len(routes), 1, msg="An accepted Redirect must install exactly one host route.")
        self.assertEqual(
            routes[0].gateway,
            Ip4Address("10.0.1.50"),
            msg="The installed Redirect route must point at the advised gateway.",
        )
        self._assert_iface_packet_stats_rx(
            self.if1,
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__redirect=1,
            icmp4__redirect__accept=1,
        )

    def test__router__ip4__redirect_rx__ignored_when_disabled(self) -> None:
        """
        Ensure an inbound ICMPv4 Redirect installs no route and is counted
        as ignored when 'ip4.accept_redirects' is disabled.

        Reference: RFC 1122 §3.3.1.2 (accept_redirects gate).
        """

        sysctl_module.set("ip4.default.accept_redirects", False)

        self.if1.handler._phrx_ethernet(
            PacketRx(
                self._build_icmp4_redirect_rx(
                    gateway=Ip4Address("10.0.1.50"),
                    embedded_dst=INTERNET__IP4,
                )
            )
        )

        routes = [route for route in stack.ip4_fib.snapshot() if route.protocol is RouteProtocol.REDIRECT]
        self.assertEqual(routes, [], msg="A Redirect must install no route when accept_redirects is disabled.")
        self._assert_iface_packet_stats_rx(
            self.if1,
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__redirect=1,
            icmp4__redirect__ignore=1,
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
