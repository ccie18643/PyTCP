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
This module contains the real-TAP two-tap router end-to-end tests — the
root-gated suite that boots one real daemon as a router between two taps
and proves the 3.0.9 forwarding plane on a real wire: a transit datagram
in on tap-A is forwarded out tap-B with its TTL / Hop Limit decremented
(resolving the egress neighbor via real ARP / ND), and a TTL-expired
transit datagram is dropped with a real ICMPv4 Time Exceeded returned to
the source. Skipped unless run as root with PYTCP_REAL_TAP=1.

pytcp/tests/integration/real_tap/test__real_tap__router.py

ver 3.0.9
"""

import time
from typing import cast

from net_addr import Ip4Address
from net_proto import Icmp4MessageTimeExceeded, IpProto
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.icmp4.icmp4__parser import Icmp4Parser
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from net_proto.protocols.udp.udp__parser import UdpParser
from pytcp.tests.lib.real_tap_router_testcase import RealTapRouterTestCase

_SPORT = 41001
_DPORT = 41002


class TestRealTapRouter(RealTapRouterTestCase):
    """
    The real-TAP two-tap router forwarding tests.
    """

    def test__real_tap__router__ipv4_unicast_transit_forwarded(self) -> None:
        """
        Ensure an IPv4 unicast datagram from the peer on tap-A to the peer
        on tap-B is forwarded out tap-B with its TTL decremented, the
        router resolving the egress neighbor via a real ARP exchange.

        Reference: RFC 1812 §5.2.1 (forwarding decremented-TTL datagrams between interfaces).
        """

        udp = UdpAssembler(udp__sport=_SPORT, udp__dport=_DPORT, udp__payload=b"transit-a-to-b")
        ip4 = Ip4Assembler(ip4__src=self.PEER_A_IP4, ip4__dst=self.PEER_B_IP4, ip4__ttl=64, ip4__payload=udp)
        self._send(self._peer_a, self._eth(src=self.PEER_A_MAC, dst=self.ROUTER_A_MAC, payload=ip4))

        # The router has no neighbor entry for peer-B -> it ARP-requests
        # it on tap-B; answer so the queued transit datagram flushes.
        self._answer_arp_request(self._peer_b, target_ip4=self.PEER_B_IP4, answer_mac=self.PEER_B_MAC)

        def _is_forwarded(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP4:
                return False
            Ip4Parser(packet_rx)
            if packet_rx.ip4.proto is not IpProto.UDP or packet_rx.ip4.dst != self.PEER_B_IP4:
                return False
            UdpParser(packet_rx)
            return packet_rx.udp.dport == _DPORT

        forwarded = self._expect(self._peer_b, _is_forwarded, timeout=5.0)
        self.assertEqual(
            forwarded.ip4.ttl,
            63,
            msg="The forwarded datagram's IPv4 TTL must be decremented by one in transit.",
        )
        self.assertEqual(
            forwarded.ip4.src,
            self.PEER_A_IP4,
            msg="The forwarded datagram must preserve the original source address.",
        )
        self.assertEqual(
            forwarded.ethernet.dst,
            self.PEER_B_MAC,
            msg="The forwarded datagram must be sent to the resolved egress neighbor's MAC.",
        )
        self.assertEqual(
            bytes(forwarded.udp.payload),
            b"transit-a-to-b",
            msg="The forwarded datagram must carry the original UDP payload unchanged.",
        )

    def test__real_tap__router__ipv6_unicast_transit_forwarded(self) -> None:
        """
        Ensure an IPv6 unicast datagram from the peer on tap-A to the peer
        on tap-B is forwarded out tap-B with its Hop Limit decremented, the
        router resolving the egress neighbor via a real ND exchange.

        Reference: RFC 1812 §5.2.1 (forwarding decremented-hop datagrams between interfaces).
        """

        udp = UdpAssembler(udp__sport=_SPORT, udp__dport=_DPORT, udp__payload=b"transit6-a-to-b")
        ip6 = Ip6Assembler(ip6__src=self.PEER_A_IP6, ip6__dst=self.PEER_B_IP6, ip6__hop=64, ip6__payload=udp)
        self._send(self._peer_a, self._eth(src=self.PEER_A_MAC, dst=self.ROUTER_A_MAC, payload=ip6))

        # The router has no neighbor entry for peer-B -> it Neighbor-
        # Solicits it on tap-B; answer so the queued transit datagram
        # flushes.
        self._answer_nd_solicitation(
            self._peer_b,
            target_ip6=self.PEER_B_IP6,
            answer_mac=self.PEER_B_MAC,
            router_mac=self.ROUTER_B_MAC,
        )

        def _is_forwarded(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP6:
                return False
            Ip6Parser(packet_rx)
            if packet_rx.ip6.next is not IpProto.UDP or packet_rx.ip6.dst != self.PEER_B_IP6:
                return False
            UdpParser(packet_rx)
            return packet_rx.udp.dport == _DPORT

        forwarded = self._expect(self._peer_b, _is_forwarded, timeout=5.0)
        self.assertEqual(
            forwarded.ip6.hop,
            63,
            msg="The forwarded datagram's IPv6 Hop Limit must be decremented by one in transit.",
        )
        self.assertEqual(
            forwarded.ip6.src,
            self.PEER_A_IP6,
            msg="The forwarded datagram must preserve the original source address.",
        )
        self.assertEqual(
            forwarded.ethernet.dst,
            self.PEER_B_MAC,
            msg="The forwarded datagram must be sent to the resolved egress neighbor's MAC.",
        )
        self.assertEqual(
            bytes(forwarded.udp.payload),
            b"transit6-a-to-b",
            msg="The forwarded datagram must carry the original UDP payload unchanged.",
        )

    def test__real_tap__router__ipv4_ttl_expired_emits_time_exceeded(self) -> None:
        """
        Ensure a transit IPv4 datagram arriving with TTL=1 is dropped
        rather than forwarded, and the router returns a real ICMPv4 Time
        Exceeded to the datagram's source out tap-A.

        Reference: RFC 1812 §5.3.1 (TTL reaching zero in transit yields ICMP Time Exceeded).
        """

        udp = UdpAssembler(udp__sport=_SPORT, udp__dport=_DPORT, udp__payload=b"ttl-expired")
        ip4 = Ip4Assembler(ip4__src=self.PEER_A_IP4, ip4__dst=self.PEER_B_IP4, ip4__ttl=1, ip4__payload=udp)
        self._send(self._peer_a, self._eth(src=self.PEER_A_MAC, dst=self.ROUTER_A_MAC, payload=ip4))

        # The Time Exceeded goes back to peer-A, which the router has not
        # resolved -> it ARP-requests peer-A on tap-A; answer so the
        # queued ICMP error flushes.
        self._answer_arp_request(self._peer_a, target_ip4=self.PEER_A_IP4, answer_mac=self.PEER_A_MAC)

        def _is_time_exceeded(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP4:
                return False
            Ip4Parser(packet_rx)
            if packet_rx.ip4.proto is not IpProto.ICMP4 or packet_rx.ip4.dst != self.PEER_A_IP4:
                return False
            Icmp4Parser(packet_rx)
            return isinstance(packet_rx.icmp4.message, Icmp4MessageTimeExceeded)

        error = self._expect(self._peer_a, _is_time_exceeded, timeout=5.0)
        self.assertEqual(
            error.ip4.src,
            self.ROUTER_A_IP4.address,
            msg="The ICMP Time Exceeded must be sourced from the router's ingress-interface address.",
        )
        self.assertEqual(
            cast(Icmp4MessageTimeExceeded, error.icmp4.message).code.value,
            0,
            msg="The Time Exceeded must carry code 0 (TTL exceeded in transit).",
        )

    def test__real_tap__router__ipv4_multicast_replicated_to_listener(self) -> None:
        """
        Ensure a transit IPv4 multicast datagram is replicated out the
        interface with a learned downstream listener (peer-B's IGMPv3
        join) with its TTL decremented, proving the multicast-router
        forwarding plane end to end on a real wire.

        Reference: RFC 1812 §5.2.4 (multicast forwarding to interested interfaces).
        """

        group = Ip4Address("239.1.1.1")

        # Peer-B joins the group on tap-B so the router's querier learns a
        # downstream listener; let the RX pipeline process the report
        # before the transit datagram arrives (real-wire timing is
        # legitimate in this suite).
        self._send(
            self._peer_b,
            self._igmp_v3_join_frame(group=group, src_ip4=self.PEER_B_IP4, src_mac=self.PEER_B_MAC),
        )
        time.sleep(0.5)

        udp = UdpAssembler(udp__sport=_SPORT, udp__dport=_DPORT, udp__payload=b"multicast-a-to-b")
        ip4 = Ip4Assembler(ip4__src=self.PEER_A_IP4, ip4__dst=group, ip4__ttl=10, ip4__payload=udp)
        self._send(self._peer_a, self._eth(src=self.PEER_A_MAC, dst=group.multicast_mac, payload=ip4))

        def _is_replica(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP4:
                return False
            Ip4Parser(packet_rx)
            if packet_rx.ip4.proto is not IpProto.UDP or packet_rx.ip4.dst != group:
                return False
            UdpParser(packet_rx)
            return packet_rx.udp.dport == _DPORT

        replica = self._expect(self._peer_b, _is_replica, timeout=5.0)
        self.assertEqual(
            replica.ip4.ttl,
            9,
            msg="The multicast replica's IPv4 TTL must be decremented by one in transit.",
        )
        self.assertEqual(
            replica.ethernet.dst,
            group.multicast_mac,
            msg="The multicast replica's Ethernet destination must be the group's multicast MAC.",
        )
        self.assertEqual(
            bytes(replica.udp.payload),
            b"multicast-a-to-b",
            msg="The multicast replica must carry the original UDP payload unchanged.",
        )
